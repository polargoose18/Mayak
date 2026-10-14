package main

import (
	"bytes"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute version: %v", err)
	}
	if got, want := out.String(), version+"\n"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
	if version != "dev" {
		t.Errorf("version = %q, want %q", version, "dev")
	}
}
