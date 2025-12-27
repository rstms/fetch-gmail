package cmd

import (
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func initTestConfig(t *testing.T) {
	viper.SetConfigFile(filepath.Join("testdata", "config", "config.yaml"))
	err := viper.ReadInConfig()
	require.Nil(t, err)
}

func TestRoot(t *testing.T) {
	initTestConfig(t)
}
