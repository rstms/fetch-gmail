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

	"github.com/rstms/fetch-gmail/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var genCmd = &cobra.Command{
	Use:   "gen",
	Short: "generate fetchmail RC file",
	Long: `
generate .fetchmailrc for polling gmail with access_token
`,
	Run: func(cmd *cobra.Command, args []string) {
		username := ViperGetString("user")
		rc, err := GenerateRC(username)
		cobra.CheckErr(err)
		ViperSetDefault("gen.output", filepath.Join("/home", username, ".fetchmailrc"))
		filename := ViperGetString("gen.output")
		switch {
		case rc == "":
			os.Exit(1)
		case filename == "-":
			fmt.Println(rc)
		default:
			err := os.WriteFile(filename, []byte(rc), 0600)
			cobra.CheckErr(err)
		}
		os.Exit(0)
	},
}

func init() {
	CobraAddCommand(rootCmd, rootCmd, genCmd)
	OptionString(genCmd, "output", "o", "", "output filename")
}

var DEFAULT_RC_TEMPLATE = `
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

func GenerateRC(username string) (string, error) {
	token, err := client.RequestToken(username)
	if err != nil {
		return "", err
	}
	if token == nil {
		return "", nil
	}
	pluginPath, err := binPath()
	if err != nil {
		return "", Fatal(err)
	}
	var templateString string
	configDir, _ := filepath.Split(viper.ConfigFileUsed())
	templateFile := filepath.Join(configDir, "rc.template")
	if !IsFile(templateFile) {
		err := os.WriteFile(templateFile, []byte(DEFAULT_RC_TEMPLATE), 0600)
		if err != nil {
			return "", Fatal(err)
		}
	}
	data, err := os.ReadFile(templateFile)
	if err != nil {
		return "", Fatal(err)
	}
	templateString = string(data)
	macros := map[string]string{
		"${GMAIL_ADDRESS}": token.Gmail,
		"${LOCAL_ADDRESS}": token.Local,
		"${PLUGIN_PATH}":   pluginPath,
	}
	for macro, value := range macros {
		templateString = strings.ReplaceAll(templateString, macro, value)
	}
	return templateString, nil
}
