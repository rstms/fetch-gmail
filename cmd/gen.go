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
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var genCmd = &cobra.Command{
	Use:   "gen USERNAME",
	Short: "generate fetchmail RC file",
	Long: `
generate .fetchmailrc for polling GMAIL for USERNAME GMAIL
`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := GenerateRC(args[0])
		cobra.CheckErr(err)
	},
}

func init() {
	rootCmd.AddCommand(genCmd)
}

type TokenResponse struct {
	Gmail string
	Local string
	Token string
}

func RequestToken(username string) (*TokenResponse, error) {
	url := fmt.Sprintf("https://%s", ViperGetString("tokend_host"))
	header := map[string]string{"X-Api-Key": ViperGetString("api_key")}
	client, err := NewAPIClient(
		"",
		url,
		ViperGetString("cert"),
		ViperGetString("key"),
		ViperGetString("ca"),
		&header,
	)
	if err != nil {
		return nil, Fatal(err)
	}
	var response TokenResponse
	_, err = client.Get(fmt.Sprintf("/oauth/token/%s/", username), &response)
	if err != nil {
		return nil, Fatal(err)
	}
	return &response, nil
}

var RC_TEMPLATE = `
poll imap.gmail.com with proto IMAP
    plugin '${PLUGIN_PATH} plugin imap.gmail.com imaps'
    user '${GMAIL_ADDRESS}' is '${LOCAL_ADDRESS}' here
	sslproto ''
	password AUTH_TOKEN
	keep
`

func binPath() (string, error) {
	bin, err := os.Executable()
	if err != nil {
		return "", Fatal(err)
	}
	fullPath, err := filepath.Abs(bin)
	if err != nil {
		return "", Fatal(err)
	}
	return fullPath, nil
}

func GenerateRC(username string) error {
	token, err := RequestToken(username)
	if err != nil {
		return Fatal(err)
	}

	pluginPath, err := binPath()
	if err != nil {
		return Fatal(err)
	}

	data := strings.ReplaceAll(RC_TEMPLATE, "${GMAIL_ADDRESS}", token.Gmail)
	data = strings.ReplaceAll(data, "${LOCAL_ADDRESS}", token.Local)
	data = strings.ReplaceAll(data, "${PLUGIN_PATH}", pluginPath)

	fmt.Println(data)
	return nil
}

/*
#!/usr/bin/env bash
USERNAME=$1

	usage() {
	    echo >&2 "Usage: $(basename $0) USERNAME"
	    exit 1
	}

if [ -z "$USERNAME" ]; then

	USERNAME=gmail.mailcapsule
	#usage

fi
CFGDIR=~/.config/fetch-gmail
CERT=$CFGDIR/token.pem
KEY=$CFGDIR/token.key
API_KEY=$(cat $CFGDIR/api_key)
RESULT="$(curl -s --cert $CERT --key $KEY -H "X-Api-Key: $API_KEY" $URL/$USERNAME/)"
TOKEN="$(jq <<<$RESULT -r .Token)"
GMAIL_ADDRESS="$(jq <<<$RESULT -r .Gmail)"
LOCAL_ADDRESS="$(jq <<<$RESULT -r .Local)"
ENCODED_TOKEN=$(encode_token)
cat ->~/.fetchmailrc<<EOF
poll imap.gmail.com with proto IMAP

	    plugin 'fetchmail-oauth2-plugin %h'
	    user '$GMAIL_ADDRESS' is '$LOCAL_ADDRESS' here
		sslproto ''
		password AUTH_TOKEN
		keep

EOF
chmod 0700 ~/.fetchmailrc
fetchmail -vvv
*/
