package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/polargoose18/mayak/internal/targets"
)

// Config holds command-line configuration for the control node.
type Config struct {
	Addr     string
	TLSAddr  string
	TLSCert  string
	TLSKey   string
	Targets  string
	StateDir string
}

// loadConfig parses command-line flags.
func loadConfig() (*Config, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("find state directory: %w", err)
	}
	cfg := &Config{
		Addr:     ":8443",
		TLSAddr:  ":443",
		StateDir: filepath.Join(configDir, "mayak-ctrl"),
	}
	args := os.Args[1:]
	value := func(i *int, name string) (string, error) {
		*i++
		if *i >= len(args) {
			return "", fmt.Errorf("%s needs a value", name)
		}
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		var err error
		switch args[i] {
		case "--addr":
			cfg.Addr, err = value(&i, "--addr")
		case "--tls-addr":
			cfg.TLSAddr, err = value(&i, "--tls-addr")
		case "--tls-cert":
			cfg.TLSCert, err = value(&i, "--tls-cert")
		case "--tls-key":
			cfg.TLSKey, err = value(&i, "--tls-key")
		case "--state-dir":
			cfg.StateDir, err = value(&i, "--state-dir")
		case "--targets":
			cfg.Targets, err = value(&i, "--targets")
		default:
			return nil, fmt.Errorf("unknown flag: %s", args[i])
		}
		if err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// newCtrlServer creates a ctrlServer from a Config, loading the signed
// targets list from the file named by --targets. Without --targets the node
// rejects every host.
func newCtrlServer(cfg *Config) (*ctrlServer, error) {
	var tlist *targets.Targets
	if cfg.Targets != "" {
		var err error
		tlist, err = loadCtrlTargets(cfg.Targets, cfg.StateDir, time.Now())
		if err != nil {
			return nil, err
		}
	}
	return newCtrlServerWithTargets(cfg, tlist), nil
}

// loadCtrlTargets loads the node's trusted list at the supplied clock time.
func loadCtrlTargets(path, stateDir string, now time.Time) (*targets.Targets, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read targets %s: %w", path, err)
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("create control state directory: %w", err)
	}
	list, err := targets.Accept(targets.PublicKeys(), data, now, targets.FileRevStore(filepath.Join(stateDir, "targets.rev")))
	if err != nil {
		return nil, fmt.Errorf("accept targets %s: %w", path, err)
	}
	return list, nil
}
