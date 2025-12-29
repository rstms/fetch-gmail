package relay

import (
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func initTestConfig(t *testing.T) {
	Init("fetch_gmail", Version, filepath.Join("..", "testdata", "config.yaml"))
}

/*
// TestServer is interactive, requiring an SSH pipe and relay connection from smtpd
func TestServer(t *testing.T) {
	initTestConfig(t)
	relayCmd := ViperGetString("test.relay_command")
	parts := strings.Fields(relayCmd)
	relay := exec.Command(parts[0], parts[1:]...)
	err := relay.Start()
	require.Nil(t, err)
	log.Println("relay started")
	defer func() {
		log.Println("stopping relay")
		err := relay.Process.Kill()
		require.Nil(t, err)
		err = relay.Wait()
		require.Nil(t, err)
		log.Println("relay stopped")
	}()
	server, err := NewServer(ViperGetString("test.listen_host"))
	require.Nil(t, err)
	err = server.Start()
	require.Nil(t, err)
	log.Printf("server started, send a message")
	err = server.Wait()
	require.Nil(t, err)
}
*/

func TestValidatePassword(t *testing.T) {
	initTestConfig(t)
	server, err := NewServer(ViperGetString("test.listen_host"))
	require.Nil(t, err)
	user := ViperGetString("test.user")
	pass := ViperGetString("test.pass")
	valid, err := server.validatePassword(user, pass)
	require.Nil(t, err)
	require.True(t, valid)
}
