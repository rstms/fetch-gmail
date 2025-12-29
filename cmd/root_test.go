package cmd

import (
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func initTestConfig(t *testing.T) {
	Init("fetch_gmail", rootCmd.Version, filepath.Join("..", "testdata", "config.yaml"))
}

func TestRoot(t *testing.T) {
	initTestConfig(t)
	apiKey := ViperGetString("tokend_client.api_key")
	require.NotEmpty(t, apiKey)
}
