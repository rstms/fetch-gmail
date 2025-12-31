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

package client

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/smtp"
	"regexp"
	"strings"
)

const Version = "0.1.12"

var FROM_PATTERN = regexp.MustCompile(`^From:[[:space:]]+(.*)[[:space:]]+<([^>]+)>.*$`)
var HEADER_PATTERN = regexp.MustCompile(`^([^[:space:]]+):[[:space:]]+[^[:space:]]+.*`)

type Auth struct {
	Address string
	Token   string
	debug   bool
}

func (a *Auth) Start(info *smtp.ServerInfo) (string, []byte, error) {
	if a.debug {
		log.Printf("Start: info: %+v\n", info)
	}
	authString := FormatToken(a.Address, a.Token)
	return "XOAUTH2", []byte(authString), nil
}

func (a *Auth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return nil, Fatalf("unexpected challenge: %v", string(fromServer))
	}
	return nil, nil
}

type Relay struct {
	Hostname   string
	Sender     string
	Recipients []string
	debug      bool
	auth       *Auth
}

func NewRelay(hostname, sender string, recipients []string) (*Relay, error) {
	if !strings.HasPrefix(sender, "gmail.") {
		return nil, Fatalf("invalid sender address: %s", sender)
	}
	token, err := RequestToken(sender)
	if err != nil {
		return nil, Fatal(err)
	}
	debug := ViperGetBool("debug")
	if debug {
		log.Printf("TOKEN: %s\n", FormatJSON(token))
	}
	r := Relay{
		Hostname:   hostname,
		Sender:     token.Gmail,
		Recipients: recipients,
		debug:      debug,
		auth:       &Auth{Address: token.Gmail, Token: token.Token, debug: debug},
	}
	return &r, nil
}

func (r *Relay) Send(conn io.Reader) (int, string, error) {

	smtpClient, err := smtp.Dial("smtp.gmail.com:587")
	if err != nil {
		return 554, "relay connection failed", Fatal(err)
	}
	defer func() {
		if r.debug {
			log.Println("closing relay client")
		}
		err := smtpClient.Close()
		if err != nil {
			log.Printf("relay client close failed: %v\n", err)
		}
	}()
	tlsConfig := tls.Config{
		ServerName: "smtp.gmail.com",
	}
	err = smtpClient.StartTLS(&tlsConfig)
	if err != nil {
		return 554, "relay STARTTLS failed", Fatal(err)
	}
	err = smtpClient.Auth(r.auth)
	if err != nil {
		return 554, "relay AUTH failed", Fatal(err)
	}
	err = smtpClient.Mail(r.Sender)
	if err != nil {
		return 554, "relay MAIL FROM failed", Fatal(err)
	}
	for _, recipient := range r.Recipients {
		err = smtpClient.Rcpt(recipient)
		if err != nil {
			return 554, "relay RCPT TO failed", Fatal(err)
		}
	}
	wc, err := smtpClient.Data()
	if err != nil {
		return 554, "relay DATA failed", Fatal(err)
	}

	count, err := r.RelayData(conn, wc)
	if err != nil {
		return 554, "failed copying message data", Fatal(err)
	}
	if r.debug {
		log.Printf("Wrote message body (%d bytes)\n", count)
	}
	return 250, "2.0.0 Message accepted for delivery", nil
}

func (r *Relay) RelayData(conn io.Reader, wc io.WriteCloser) (uint64, error) {
	defer func() {
		if r.debug {
			log.Printf("closing body writer")
		}
		err := wc.Close()
		if err != nil {
			log.Printf("failed closing body writer: %v\n", err)
		}
	}()
	scanner := bufio.NewScanner(conn)
	var dataCount uint64

	inHeader := true
	var inDKIM bool
	for scanner.Scan() {
		text := scanner.Text()
		text = strings.TrimRight(text, "\r\n")
		if inHeader {
			if text == "" {
				inHeader = false
				inDKIM = false
			}
		}
		if inHeader {
			match := HEADER_PATTERN.FindStringSubmatch(text)
			if len(match) > 1 {
				headerKey := match[1]
				inDKIM = false
				switch headerKey {
				case "DKIM-Signature":
					inDKIM = true
				case "From":
					text = fmt.Sprintf("From: %s", r.Sender)
				}
			}
		}
		if inDKIM {
			if r.debug {
				log.Printf("skip: %s\n", text)
			}
		} else {
			if text == "." {
				break
			}
			if r.debug {
				log.Printf("relay: %s\n", text)
			}
			lineCount, err := io.WriteString(wc, text+"\r\n")
			if err != nil {
				return 0, Fatal(err)
			}
			dataCount += uint64(lineCount)
		}
	}
	err := scanner.Err()
	if err != nil {
		return 0, Fatal(err)
	}
	return dataCount, nil
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
