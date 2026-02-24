package main

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// CLIConfig is the persistent CLI configuration.
type CLIConfig struct {
	Address   string `yaml:"address"`
	Token     string `yaml:"token"`
	TLSCACert string `yaml:"tls_ca_cert"`
}

var cfg CLIConfig

// configPath returns the path to the CLI config file.
func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secretvault", "config.yaml")
}

// loadConfig loads the CLI config from disk.
func loadConfig() {
	cfg = CLIConfig{
		Address: "http://127.0.0.1:8200",
	}
	data, err := os.ReadFile(configPath())
	if err != nil {
		return // Use defaults
	}
	yaml.Unmarshal(data, &cfg) //nolint:errcheck
}

// saveConfig persists the CLI config to disk.
func saveConfig() error {
	path := configPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
