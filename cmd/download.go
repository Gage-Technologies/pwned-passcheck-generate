package cmd

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
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
	// open get request to the target server
	req, err := http.NewRequest(
		"GET",
		"https://downloads.pwnedpasswords.com/passwords/pwned-passwords-sha1-ordered-by-count-v8.7z",
		nil,
	)
	if err != nil {
		pterm.Fatal.Printf("failed to create request: %v\n", err)
		return
	}

	// open output file
	f, err := os.Create(args[0])
	if err != nil {
		pterm.Fatal.Printf("failed to create output file: %v\n", err)
		return
	}
	defer f.Close()

	// create hasher to check the sum of the password file
	hasher := sha1.New()

	// send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		pterm.Fatal.Printf("failed to send request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// validate the status code
	if resp.StatusCode != 200 {
		pterm.Fatal.Printf("failed to download password hashes: %v\n", resp.StatusCode)
		return
	}

	// create deafult progress bar
	pbBuilder := pterm.DefaultProgressbar.
		WithTitle("Downloading Password List").
		WithBarStyle(pterm.NewStyle(pterm.FgCyan)).
		WithTitleStyle(pterm.NewStyle(pterm.FgCyan)).
		WithRemoveWhenDone(true)

	// attempt to load the file size from the header
	// and update the progress bar for the total bytes
	if resp.Header.Get("Content-Length") != "" {
		totalBytes, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
		if err == nil {
			pbBuilder = pbBuilder.WithTotal(int(totalBytes))
		}
	}

	// start progress bar
	pb, err := pbBuilder.Start()
	if err != nil {
		pterm.Fatal.Printf("failed to create progressbar: %v\n", err)
		return
	}

	// launch read loop
	for {
		// read a 1KiB chunk from the remote server
		buf := make([]byte, 1024)
		n, err := resp.Body.Read(buf)
		if err != nil {
			// exit quietly if we arex finished
			if errors.Is(err, io.EOF) {
				break
			}
			pterm.Fatal.Printf("failed to read block from remote server: %v\n", err)
			return
		}

		// trim the buffer
		buf = buf[:n]

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

		// update the progress bar
		pb.Add(n)
	}

	// stop progress bar
	_, _ = pb.Stop()

	// check the checksum hash of the file
	cksm := hex.EncodeToString(hasher.Sum(nil))
	if cksm != "9c0a584e6799c09c648ded04d1e373172d54a77e" {
		pterm.Fatal.Printf("failed to verify checksum of downloaded file: %v\n", cksm)
		return
	}

	// print the response
	pterm.Info.Printfln("\n##############################\nDownload Complete\nOutput File: %s", args[0])
}
