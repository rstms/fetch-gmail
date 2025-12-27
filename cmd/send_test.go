package cmd

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestSend(t *testing.T) {
	initTestConfig(t)
	err := os.Setenv("LOGNAME", os.Getenv("TEST_LOGNAME"))
	require.Nil(t, err)
	err = os.Setenv("RECIPIENT", os.Getenv("TEST_RECIPIENT"))
	require.Nil(t, err)
	err = os.Setenv("SENDER", os.Getenv("TEST_SENDER"))
	require.Nil(t, err)
	messageFile := filepath.Join("testdata", "message")
	ifp, err := os.OpenFile(messageFile, os.O_RDONLY, 0)
	require.Nil(t, err)
	defer ifp.Close()
	code, err := SendGmail(ifp)
	require.Nil(t, err)
	require.Zero(t, code)
}
