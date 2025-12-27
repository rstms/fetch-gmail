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
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"log"
	"net/smtp"
	"os"
	"regexp"
	"strings"
)

const ERROR_CONFIG = 1
const ERROR_OSFAIL = 71
const ERROR_TEMPFAIL = 75

var FROM_PATTERN = regexp.MustCompile(`^From:[[:space:]]+(.*)[[:space:]]+<([^>]+)>.*$`)

var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "read an email from stdin and send it via gmail",
	Long: `
MTA suitable for calling from smtpd.  Performs a tokend lookup to retrieve an
access_token for the gmail SMTP authentication.
Rewrites the sender address as the Gmail address from the tokend response.
see smtpd.conf manpage for description of env vars and exit codes
`,
	Run: func(cmd *cobra.Command, args []string) {
		code, err := SendGmail(os.Stdin)
		if err != nil {
			log.Printf("exiting %d, %v\n", code, err)
		}
		os.Exit(code)
	},
}

func init() {
	rootCmd.AddCommand(sendCmd)
}

type GmailAuth struct {
	Address string
	Token   string
}

func NewGmailAuth(address, token string) *GmailAuth {
	return &GmailAuth{Address: address, Token: token}
}

func (a *GmailAuth) Start(info *smtp.ServerInfo) (string, []byte, error) {
	if ViperGetBool("debug") {
		log.Printf("Start: info: %+v\n", info)
	}
	authString := FormatToken(a.Address, a.Token)
	return "XOAUTH2", []byte(authString), nil
}

func (a *GmailAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return nil, Fatalf("unexpected challenge: %v", string(fromServer))
	}
	return nil, nil
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

func SendGmail(reader io.Reader) (int, error) {
	_, err := Getvar("LOGNAME")
	if err != nil {
		return ERROR_OSFAIL, Fatal(err)
	}
	recipient, err := Getvar("RECIPIENT")
	if err != nil {
		return ERROR_OSFAIL, Fatal(err)
	}
	sender, err := Getvar("SENDER")
	if err != nil {
		return ERROR_OSFAIL, Fatal(err)
	}
	token, err := RequestToken(sender)
	if err != nil {
		return ERROR_OSFAIL, Fatal(err)
	}
	debug := ViperGetBool("debug")
	if debug {
		log.Printf("TOKEN: %s\n", FormatJSON(token))
	}
	lines := []string{}
	inHeader := true
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimRight(line, "\r\n")
		if debug {
			log.Printf("%s\n", HexDump([]byte(line)))
		}
		if inHeader && strings.TrimSpace(line) == "" {
			inHeader = false
		}
		if inHeader && strings.HasPrefix(line, "From: ") {
			fields := FROM_PATTERN.FindStringSubmatch(line)
			if len(fields) == 3 {
				line = fmt.Sprintf("From: %s <%s>", fields[1], token.Gmail)
			} else {
				line = fmt.Sprintf("From: %s", token.Gmail)
			}
		}
		lines = append(lines, line)
	}
	err = scanner.Err()
	if err != nil {
		return ERROR_OSFAIL, Fatal(err)
	}
	smtpClient, err := smtp.Dial("smtp.gmail.com:587")
	if err != nil {
		return ERROR_TEMPFAIL, Fatal(err)
	}
	defer smtpClient.Close()
	tlsConfig := tls.Config{
		ServerName: "smtp.gmail.com",
	}
	err = smtpClient.StartTLS(&tlsConfig)
	if err != nil {
		return ERROR_TEMPFAIL, Fatal(err)
	}
	auth := NewGmailAuth(token.Gmail, token.Token)
	err = smtpClient.Auth(auth)
	if err != nil {
		return ERROR_TEMPFAIL, Fatal(err)
	}
	err = smtpClient.Mail(sender)
	if err != nil {
		return ERROR_TEMPFAIL, Fatal(err)
	}
	err = smtpClient.Rcpt(recipient)
	if err != nil {
		return ERROR_TEMPFAIL, Fatal(err)
	}
	wc, err := smtpClient.Data()
	if err != nil {
		return ERROR_TEMPFAIL, Fatal(err)
	}
	defer wc.Close()
	msg := []byte(strings.Join(lines, "\r\n"))
	_, err = wc.Write(msg)
	if err != nil {
		return ERROR_TEMPFAIL, Fatal(err)
	}
	return 0, nil
}

/*
   When an action delivery method is mda, smtpd(8) runs the associated
     command for the delivery with the mail content provided via standard
     input.  The command is expected to read all the mail content.
     The exit code of the command reports the outcome of the delivery: status
     0 (EX_OK) is a successful delivery; status 71 (EX_OSERR) and 75
     (EX_TEMPFAIL) are temporary failures; and all other exit status are
     considered permanent failures.
     The following environment variables are set:
     DOMAIN              The recipient domain.
     EXTENSION           The sub address of the recipient (may be unset).
     HOME                The delivery user's login directory.
     LOCAL               The local part of the recipient user address.
     LOGNAME             The login name of the user.
     ORIGINAL_RECIPIENT  The address of the original recipient.
     PATH                Set to _PATH_DEFPATH.  Traditionally /usr/bin:/bin,
                         but expanded to include /usr/sbin, /sbin,
                         /usr/X11R6/bin, /usr/local/bin, and /usr/local/sbin
                         in OpenBSD.
     RECIPIENT           The address of the final recipient.
     SENDER              The address of the sender (might be empty).
     SHELL               Set to /bin/sh.
     USER                Synonym of LOGNAME for backwards compatibility.
*/
