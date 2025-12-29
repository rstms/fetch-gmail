package client

import (
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func initTestConfig(t *testing.T) {
	Init("fetch_gmail", Version, filepath.Join("..", "testdata", "config.yaml"))
}

func TestRelaySend(t *testing.T) {
	initTestConfig(t)
	hostname := ViperGetString("test.hostname")
	mailFrom := ViperGetString("test.mail_from")
	rcptTo := ViperGetString("test.rcpt_to")
	messageFile := filepath.Join("..", "testdata", "message")
	ifp, err := os.OpenFile(messageFile, os.O_RDONLY, 0)
	require.Nil(t, err)
	defer ifp.Close()

	relay, err := NewRelay(hostname, mailFrom, []string{rcptTo})
	require.Nil(t, err)
	code, msg, err := relay.Send(ifp)
	log.Printf("code=%d msg=%s err=%v\n", code, msg, err)
	require.Nil(t, err)
	require.Equal(t, code, 250)
}
