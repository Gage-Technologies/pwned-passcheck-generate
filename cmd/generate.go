package cmd

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/klauspost/compress/gzip"
	"github.com/sourcegraph/conc"
	"math"
	"os"
	"sync/atomic"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(genCmd)

	// default error rate is ~1/100M
	genCmd.Flags().Float64P("error", "e", 0.00000001, "maximum error rate accepted by the bloom filter")
	// default max size is -1 to indicate no limit
	genCmd.Flags().IntP("max", "m", -1, "maximum count of entities that will be inserted into the bloom filter (-1 is unlimited)")
	// default shard count is 128
	genCmd.Flags().IntP("shards", "s", 128, "number of shards to use for the bloom filter")
}

// genCmd
//
//	Command to generate a bloom filter from a Pwned Password Database archive
var genCmd = &cobra.Command{
	Use:   "gen <input path> <output path>",
	Short: "Generate a bloom filter from the passed Pwned Password Database archive",
	// we require the input and output path
	Args: cobra.ExactArgs(2),
	Run:  runGenCmd,
}

func runGenCmd(cmd *cobra.Command, args []string) {
	// open the password file
	pass, err := os.Open(args[0])
	if err != nil {
		pterm.Fatal.Printf("failed to open password archive: %v\n", err)
		return
	}
	defer pass.Close()

	// create output file to save the bloom filter
	fl, err := os.Create(args[1])
	if err != nil {
		pterm.Fatal.Printf("failed to create output file: %v\n", err)
		return
	}
	defer fl.Close()

	// create deafult progress bar
	pbBuilder := pterm.DefaultProgressbar.
		WithTitle("Generating Filter").
		WithBarStyle(pterm.NewStyle(pterm.FgCyan)).
		WithTitleStyle(pterm.NewStyle(pterm.FgCyan)).
		WithRemoveWhenDone(true)

	// retrieve the max size of the filter
	maxSize, err := cmd.Flags().GetInt("max")
	if err != nil {
		pterm.Fatal.Printf("failed to retrieve max size: %v\n", err)
		return
	}

	// only add a total to the progress bar if we have a max configured
	if maxSize > 0 {
		pbBuilder = pbBuilder.WithTotal(maxSize)
	} else {
		info, err := os.Stat(args[0])
		if err == nil {
			// estimate the size since the average line size is ~44 bytes
			maxSize = int(info.Size() / 44)
			pbBuilder = pbBuilder.WithTotal(maxSize)
		}
	}

	// retrieve the error probability for the bloom filter
	errProb, err := cmd.Flags().GetFloat64("error")
	if err != nil {
		pterm.Fatal.Printf("failed to retrieve error rate flag: %v\n", err)
		return
	}

	// add a buffer size if 20% to the bloom filter max size
	bfSize := int(float32(maxSize)*.20) + maxSize

	// update filter config for the shard count
	shardCount, err := cmd.Flags().GetInt("shards")
	if err != nil {
		pterm.Fatal.Printf("failed to retrieve shard count flag: %v\n", err)
		return
	}
	shardSize := int(math.Ceil(float64(bfSize) / float64(shardCount)))
	errProb *= float64(shardCount)

	// print the shard info
	pterm.Info.Printfln(
		"\n##############################\nFilter Configuration\nShard Count: %v\nShard Size: %v\nError Probability: %v",
		shardCount, shardSize, errProb,
	)

	// create slice to hold the shards of the filter
	filters := make([]*bloom.BloomFilter, shardCount)
	queues := make([]chan string, shardCount)
	for i := range filters {
		filters[i] = bloom.NewWithEstimates(uint(shardSize), errProb)
		queues[i] = make(chan string)
	}

	// start the progress bar
	pb, err := pbBuilder.Start()
	if err != nil {
		pterm.Fatal.Printf("failed to create progress bar: %v\n", err)
		return
	}

	// create a wait group for  the shard workers
	wg := conc.NewWaitGroup()

	// create a context for the workers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// launch the filter workers
	for i := range filters {
		q := queues[i]
		wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case b := <-q:
					// write to the filter
					filters[i].AddString(b)
					// increment the progress bar
					pb.Increment()
				}
			}
		})
	}

	// create a new scanner to preprocess each line from the
	// password archive - this is used to trim the prevalence
	// count from each line in the archive
	scanner := bufio.NewScanner(pass)

	// create index to track which queue we're writing to
	qIdx := 0

	// create atomic integer to track the count of entities written
	count := &atomic.Int64{}

	// iterate the lines in the password archive adding them to the filter
	for scanner.Scan() {
		// skip corrupted data
		if len(scanner.Text()) < 40 {
			pterm.Warning.Printfln("skipping corrupted entry: %v", scanner.Text())
			continue
		}

		// first 40 chars is sha1 sum
		queues[qIdx] <- scanner.Text()[:40]

		// increment the counter
		count.Add(1)

		// exit if the count is equal to the max entities
		if maxSize > 0 && int64(maxSize) == count.Load() {
			cancel()
			break
		}

		// increment the queue index
		qIdx = qIdx + 1
		if qIdx == len(queues) {
			qIdx = 0
		}
	}

	// handle any errors that occurred in the scanning
	if err := scanner.Err(); err != nil {
		_, _ = pb.Stop()
		pterm.Fatal.Printf("failed to read password archive: %v\n", err)
		return
	}

	// wait for the queues to clear then cancel the context
	for {
		cleared := true
		for i := range queues {
			if len(queues[i]) > 0 {
				cleared = false
				break
			}
		}
		if cleared {
			cancel()
			break
		}
	}

	// wait for the workers to finish
	wg.Wait()

	// create a tar archive with high compression

	// create output file
	outFile, err := os.Create(args[1])
	if err != nil {
		pterm.Fatal.Printf("failed to create output file: %v\n", err)
		return
	}
	defer outFile.Close()

	// create gzip writer
	gzipWriter := gzip.NewWriter(outFile)
	defer gzipWriter.Close()

	// create tar writer
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// write header for the index file
	headerBuf := []byte(fmt.Sprintf("%d", shardCount))
	err = tarWriter.WriteHeader(&tar.Header{
		Name: "index",
		Size: int64(len(headerBuf)),
		Mode: 0666,
	})
	if err != nil {
		pterm.Fatal.Printf("failed to write index header: %v\n", err)
		return
	}

	// write index file
	_, err = tarWriter.Write(headerBuf)
	if err != nil {
		pterm.Fatal.Printf("failed to write index header: %v\n", err)
		return
	}

	// iterate through the shards
	for i := 0; i < shardCount; i++ {
		// write the shard to a buffer so that we know the file size
		buf := new(bytes.Buffer)
		_, err = filters[i].WriteTo(buf)
		if err != nil {
			pterm.Fatal.Printf("failed to write filter: %v\n", err)
			return
		}

		// extract bytes from buffer
		bufBytes := buf.Bytes()

		// write header for the file
		err = tarWriter.WriteHeader(&tar.Header{
			Name: fmt.Sprintf("%d", i),
			Size: int64(len(bufBytes)),
			Mode: 0666,
		})
		if err != nil {
			pterm.Fatal.Printf("failed to write header: %v\n", err)
			return
		}

		// write buffer
		_, err = tarWriter.Write(bufBytes)
		if err != nil {
			pterm.Fatal.Printf("failed to write buffer: %v\n", err)
			return
		}
	}

	// close the tar archive
	_ = tarWriter.Close()
	_ = gzipWriter.Close()
	_ = outFile.Close()

	// stop the progress bar
	_, _ = pb.Stop()

	// print the response
	pterm.Info.Printfln("\n##############################\nDownload Complete\nOutput File: %s", args[1])
}
