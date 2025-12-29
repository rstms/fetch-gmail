/*
Copyright © 2025 Matt Krueger <mkrueger@rstms.net>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

 3. Neither the name of the copyright holder nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
package cmd

import (
	"fmt"
	"github.com/rstms/fetch-gmail/client"
	"github.com/spf13/cobra"
	"io"
	"log"
	"os"
)

const ERROR_CONFIG = 1
const ERROR_OSFAIL = 71
const ERROR_TEMPFAIL = 75

var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "read an email from stdin and send it via gmail",
	Long: `
MDA suitable for calling from smtpd.  Performs a tokend lookup to retrieve an
access_token for the gmail SMTP authentication.
Rewrites the sender address as the Gmail address from the tokend response.
see smtpd.conf manpage for description of env vars and exit codes
`,
	Run: func(cmd *cobra.Command, args []string) {
		exitCode, err := SendGmail(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "relay failed: %v", err)
			os.Exit(exitCode)
		}
		os.Exit(exitCode)
	},
}

func SendGmail(reader io.Reader) (int, error) {
	mailFrom, err := Getvar("SENDER")
	if err != nil {
		return ERROR_CONFIG, err
	}
	rcptTo, err := Getvar("RECIPIENT")
	if err != nil {
		return ERROR_CONFIG, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return ERROR_OSFAIL, err
	}
	relay, err := client.NewRelay(hostname, mailFrom, []string{rcptTo})
	if err != nil {
		return ERROR_CONFIG, err
	}
	_, _, err = relay.Send(reader)
	if err != nil {
		return ERROR_TEMPFAIL, err
	}
	return 0, nil
}

func init() {
	rootCmd.AddCommand(sendCmd)
}

func Getvar(name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", Fatalf("null %s", name)
	}
	if ViperGetBool("debug") {
		log.Printf("%s=%s\n", name, value)
	}
	return value, nil
}
