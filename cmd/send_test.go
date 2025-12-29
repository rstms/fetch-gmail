package cmd

import (
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func TestSend(t *testing.T) {
	initTestConfig(t)
	err := os.Setenv("RECIPIENT", ViperGetString("test.rcpt_to"))
	require.Nil(t, err)
	err = os.Setenv("SENDER", ViperGetString("test.mail_from"))
	require.Nil(t, err)
	messageFile := filepath.Join("..", "testdata", "message")
	ifp, err := os.OpenFile(messageFile, os.O_RDONLY, 0)
	require.Nil(t, err)
	defer ifp.Close()
	code, err := SendGmail(ifp)
	require.Nil(t, err)
	log.Printf("exitCode=%d\n", code)
	require.Zero(t, code)
}
