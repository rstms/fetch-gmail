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
	"encoding/base64"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"log"
	"os"
	"strings"
	"sync"
)

var Debug bool

var pluginCmd = &cobra.Command{
	Use:   "plugin [HOST] [PORT]",
	Short: "fetchmail OAUTH2 plugin",
	Long: `
TLS IMAP server proxy replacing 'LOGIN ...' with 'AUTHENTICATE XAUTH2 ...'
HOST defaults to 'imap.gmail.com'
PORT defaults to 'imaps'
`,
	Args: cobra.RangeArgs(0, 2),
	Run: func(cmd *cobra.Command, args []string) {
		Debug = ViperGetBool("debug")
		host := "imap.gmail.com"
		if len(args) > 0 {
			host = args[0]
		}
		port := "imaps"
		if len(args) > 1 {
			port = args[1]
		}
		err := Relay(fmt.Sprintf("%s:%s", host, port), os.Stdin, os.Stdout)
		if err != nil {
			cobra.CheckErr(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(pluginCmd)
}
func Relay(host string, ifp io.Reader, ofp io.Writer) error {
	if Debug {
		log.Printf("connecting to %s\n", host)
	}
	conn, err := tls.Dial("tcp", host, &tls.Config{})
	if err != nil {
		return Fatal(err)
	}
	defer conn.Close()
	var authPending bool
	toClient := make(chan string, 1)
	toServer := make(chan string, 1)
	var wg sync.WaitGroup
	errors := []error{}
	wg.Add(1)
	go func() {
		if Debug {
			defer log.Println("readFromClient: returning")
		}
		defer wg.Done()
		defer close(toServer)
		scanner := bufio.NewScanner(ifp)
		for scanner.Scan() {
			line := scanner.Text()
			if Debug {
				log.Printf("fromClient: '%s'\n%s\n", line, HexDump([]byte(line)))
			}
			toServer <- line
		}
		err := scanner.Err()
		if err != nil {
			if Debug {
				log.Printf("read from client failed: %v", err)
			}
			errors = append(errors, err)
			return
		}
		if Debug {
			log.Println("EOF from client")
		}
	}()
	wg.Add(1)
	go func() {
		if Debug {
			defer log.Println("readFromServer: returning")
		}
		defer wg.Done()
		defer close(toClient)
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			line := scanner.Text()
			if Debug {
				log.Printf("fromServer: '%s'\n%s\n", line, HexDump([]byte(line)))
			}
			if authPending {
				failed, err := isAuthFailed(line)
				if err != nil {
					log.Printf("isAuthFailed: %v", err)
					errors = append(errors, err)
					return
				}
				if failed {
					fmt.Fprintf(conn, "\r\n")
				}
				authPending = false
			}
			toClient <- scanner.Text()
		}
		err := scanner.Err()
		if err != nil {
			log.Printf("readFromServer failed: %v", err)
			errors = append(errors, err)
			return
		}
		if Debug {
			log.Println("readFromServer: EOF")
		}
	}()
	wg.Add(1)
	go func() {
		if Debug {
			defer log.Println("writeToServer: returning")
		}
		defer wg.Done()
		for {
			select {
			case line, ok := <-toServer:
				if !ok {
					if Debug {
						log.Println("toServer channel closed")
					}
					return
				}
				if Debug {
					log.Printf("toServer: '%s'\n%s\n", line, HexDump([]byte(line)))
				}
				authPending = false
				line, changed, err := filterLine(line)
				if err != nil {
					if Debug {
						log.Printf("writeToServer: filterLine failed: %v\n", err)
					}
					errors = append(errors, err)
					return
				}
				if changed {
					authPending = true
					if Debug {
						log.Printf("toServer[modified]: '%s'\n%s\n", line, HexDump([]byte(line)))
					}
				}
				_, err = fmt.Fprintf(conn, "%s\r\n", line)
				if err != nil {
					if Debug {
						log.Printf("writeToServer failed: %v", err)
					}
					errors = append(errors, err)
					return
				}
			}
		}
	}()
	wg.Add(1)
	go func() {
		if Debug {
			defer log.Println("writeToClient: returning")
		}
		defer wg.Done()
		for {
			select {
			case line, ok := <-toClient:
				if !ok {
					if Debug {
						log.Println("toClient channel closed")
					}
					return
				}
				if Debug {
					log.Printf("toClient: '%s'\n%s\n", line, HexDump([]byte(line)))
				}
				_, err := fmt.Fprintf(ofp, "%s\r\n", line)
				if err != nil {
					if Debug {
						log.Printf("writeToClient failed: %v", err)
					}
					errors = append(errors, err)
					return
				}
			}
		}
	}()
	if Debug {
		log.Printf("waiting...")
	}
	wg.Wait()
	if Debug {
		log.Printf("wait complete")
	}
	if len(errors) > 1 {
		return errors[0]
	}
	return nil
}
func isAuthFailed(line string) (bool, error) {
	fields := strings.Fields(line)
	if len(fields) == 2 && fields[0] == "+" {
		message, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil {
			return false, Fatal(err)
		}
		log.Printf("Authenticate failed: %s\n", string(message))
		return true, nil
	}
	return false, nil
}
func filterLine(line string) (string, bool, error) {
	fields := strings.Fields(line)
	if len(fields) > 2 {
		switch fields[1] {
		case "LOGIN":
			nonce := fields[0]
			user := strings.Trim(fields[2], "'\"")
			response, err := RequestToken(user)
			if err != nil {
				return "", false, Fatal(err)
			}
			formatted := fmt.Sprintf("user=%s\x01auth=Bearer %s\x01\x01", response.Gmail, response.Token)
			encoded := base64.StdEncoding.EncodeToString([]byte(formatted))
			return fmt.Sprintf("%s AUTHENTICATE XOAUTH2 %s", nonce, encoded), true, nil
		}
	}
	return line, false, nil
}
