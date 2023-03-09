package cmd

import (
	"bufio"
	"os"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(genCmd)

	// default error rate is ~1/100M
	genCmd.Flags().Float64P("error", "e", 0.00000001, "maximum error rate accepted by the bloom filter")
	// default size is ~500M
	genCmd.Flags().UintP("size", "s", 500000000, "estimated count of entities that will be inserted into the bloom filter")
	// default max size is -1 to indicate no limit
	genCmd.Flags().IntP("max", "m", -1, "maximum count of entities that will be inserted into the bloom filter (-1 is unlimited)")
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
	// create the bloom filter
	es, err := cmd.Flags().GetUint("size")
	if err != nil {
		pterm.Fatal.Printf("failed to retrieve size flag: %v\n", err)
		return
	}
	errProb, err := cmd.Flags().GetFloat64("error")
	if err != nil {
		pterm.Fatal.Printf("failed to retrieve error rate flag: %v\n", err)
		return
	}
	filter := bloom.NewWithEstimates(es, errProb)

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
			// esitmate the size since the average line size is ~44 bytes
			pbBuilder = pbBuilder.WithTotal(int(info.Size() / 44))
		}
	}

	// start the progress bar
	pb, err := pbBuilder.Start()
	if err != nil {
		pterm.Fatal.Printf("failed to create progress bar: %v\n", err)
		return
	}

	// create a new scanner to preprocess each line from the
	// password archive - this is used to trim the prevelance
	// count from each line in the archive
	scanner := bufio.NewScanner(pass)

	// create integer to track the count of entities written
	count := 0

	// iterate the lines in the password archive adding them to the filter
	for scanner.Scan() {
		// skip corrupted data
		if len(scanner.Text()) < 40 {
			continue
		}

		// first 40 chars is sha1 sum
		filter.AddString(scanner.Text()[:40])
		// increment the progress bar
		pb.Increment()
		// increment the counter
		count++

		// exit if the count is equal to the max entities
		if maxSize > 0 && maxSize == count {
			break
		}
	}

	// handle any errors that occurred in the scanning
	if err := scanner.Err(); err != nil {
		_, _ = pb.Stop()
		pterm.Fatal.Printf("failed to read password archive: %v\n", err)
		return
	}

	// save the filter to the output file
	_, err = filter.WriteTo(fl)
	if err != nil {
		_, _ = pb.Stop()
		pterm.Fatal.Printf("failed to write bloom filter: %v\n", err)
		return
	}

	// stop the progress bar
	_, _ = pb.Stop()

	// print the response
	pterm.Info.Printfln("\n##############################\nDownload Complete\nOutput File: %s", args[0])
}
