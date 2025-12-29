package client

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
)

type TokenResponse struct {
	Success bool
	Request string
	Message string
	User    string
	Gmail   string
	Local   string
	Token   string
}

func RequestToken(username string) (*TokenResponse, error) {
	header := map[string]string{"X-Api-Key": ViperGetString("tokend_client.api_key")}
	baseUrl := fmt.Sprintf("https://%s", ViperGetString("tokend_client.tokend_host"))
	client, err := NewAPIClient(
		"",
		baseUrl,
		ViperGetString("tokend_client.cert"),
		ViperGetString("tokend_client.key"),
		ViperGetString("tokend_client.ca"),
		&header,
	)
	if err != nil {
		return nil, Fatal(err)
	}
	var response TokenResponse
	err = client.SetFlag("require_success", false)
	err = client.SetFlag("require_json", false)
	if err != nil {
		return nil, Fatal(err)
	}
	url := fmt.Sprintf("/oauth/token/%s/", username)
	_, err = client.Get(url, &response)
	if err != nil {
		return nil, Fatal(err)
	}
	status, ok := client.StatusCode()
	switch {
	case ok:
		return &response, nil
	case status == http.StatusNotFound:
		return nil, errors.New(response.Message)
	}
	return nil, Fatalf("request failed with status: %d", status)
}

func FormatToken(gmailAddress, token string) string {
	return fmt.Sprintf("user=%s\x01auth=Bearer %s\x01\x01", gmailAddress, token)
}

func EncodeToken(gmailAddress, token string) string {
	formatted := FormatToken(gmailAddress, token)
	return base64.StdEncoding.EncodeToString([]byte(formatted))
}
