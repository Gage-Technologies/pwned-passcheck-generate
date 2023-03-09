package cmd

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/pterm/pterm"
	"github.com/sourcegraph/conc/pool"
	"github.com/spf13/cobra"
)

const (
	pwndRangeMax = 1024 * 1024
)

func init() {
	rootCmd.AddCommand(dlCmd)
}

// dlCmd
//
//	Command to download the password hash file from the Pwned Password Database archives
var dlCmd = &cobra.Command{
	Use:   "dl <output path>",
	Short: "Downloads the password hashes",
	// we require the output path
	Args: cobra.ExactArgs(1),
	Run:  runDlCmd,
}

func runDlCmd(cmd *cobra.Command, args []string) {
	// create new output file
	f, err := os.Create(args[0])
	if err != nil {
		pterm.Fatal.Printf("failed to create output file: %v\n", err)
		return
	}

	// create new hasher to generate a sha1 hash of the file
	hasher := sha1.New()

	// create deafult progress bar
	pbBuilder := pterm.DefaultProgressbar.
		WithTitle("Downloading Password List").
		WithBarStyle(pterm.NewStyle(pterm.FgCyan)).
		WithTitleStyle(pterm.NewStyle(pterm.FgCyan)).
		WithRemoveWhenDone(true).
		// set total to the max amount of ranges
		WithTotal(pwndRangeMax)

	// start progress bar
	pb, err := pbBuilder.Start()
	if err != nil {
		pterm.Fatal.Printf("failed to create progressbar: %v\n", err)
		return
	}

	// create channel with up to 128 chunks buffered
	q := make(chan []byte, 128)

	// create worker pool to launch multiple goroutines
	wg := pool.New().WithMaxGoroutines(129)

	// create integer to track the size of the output file
	size := 0

	// launch goroutine to async write to file wo we can buffer the file download
	go func() {
		for {
			// wait for the next chunk
			buf, ok := <-q
			if !ok {
				return
			}

			// update the checksum hashes
			_, err = hasher.Write(buf)
			if err != nil {
				pterm.Fatal.Printf("failed to append to checksum buffer: %v\n", err)
				return
			}

			// update the output file
			_, err = f.Write(buf)
			if err != nil {
				pterm.Fatal.Printf("failed to append to output file: %v\n", err)
				return
			}

			// calculate new size
			size += len(buf)

			// update the progress bar
			pb.Add(1)
		}
	}()

	// launch workers to query the api
	for i := 0; i < pwndRangeMax; i++ {
		wg.Go(func() {
			// query the api for this range
			buf, err := getHashRange(i)
			if err != nil {
				pterm.Fatal.Printf("failed to get hash range: %v\n", err)
				return
			}

			// send the buffer to the write queue
			q <- buf
		})
	}

	// wait for the queue to fill so we know that the next
	// empty wait loop is waiting to finish and not exiting before start
	wg.Wait()

	// wait for the queue to empty then close
	for {
		if len(q) > 0 {
			time.Sleep(time.Millisecond * 10)
			continue
		}
		close(q)
		break
	}

	// stop progress bar
	_, _ = pb.Stop()

	// close the temp file
	_ = f.Close()

	// print the response
	pterm.Info.Printfln("##############################\nDownload Complete\nOutput File: %s\nSHA1 Checksum: %s", args[0], hex.EncodeToString(hasher.Sum(nil)))
}

// getHashRange
//
//	Retrieves a hash range from the Pwned Password Archive API
func getHashRange(r int) ([]byte, error) {
	// format int to hex encoded big endian
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(r))
	// trim the first 3 characters - I don't know why the did this but it's required
	encodedRange := hex.EncodeToString(buf)[3:]

	// query api for the hash range
	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", encodedRange)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to query api: %v", err)
	}

	defer resp.Body.Close()

	// read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// prepend the range head to each of the hashes
	out := [][]byte{}
	for _, hash := range bytes.Split(body, []byte("\n")) {
        out = append(out, append([]byte(encodedRange), hash...))
    }

	// return the hash range
	return bytes.Join(out, []byte("\n")), nil
}
