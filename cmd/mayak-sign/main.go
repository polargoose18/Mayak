// Command mayak-sign is the owner's tool for the signed targets list:
// key generation, signing and verification. See docs/KEYS.md.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/polargoose18/mayak/internal/targets"
)

// keyFileName is the private key file created by keygen. The private key is
// stored as the base64 of the 32-byte ed25519 seed.
const keyFileName = "targets-signing.key"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "mayak-sign",
		Short:         "Keys and signatures for the Mayak targets list (owner tool)",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newKeygenCmd(), newSignCmd(), newVerifyCmd())
	return root
}

func newKeygenCmd() *cobra.Command {
	var outDir string
	cmd := &cobra.Command{
		Use:   "keygen --out <dir>",
		Short: "Create an ed25519 key pair; print the public key as base64",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runKeygen(cmd, outDir)
		},
	}
	cmd.Flags().StringVar(&outDir, "out", "", "directory for the private key file (created if missing)")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func runKeygen(cmd *cobra.Command, outDir string) error {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", outDir, err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	path := filepath.Join(outDir, keyFileName)
	// O_EXCL makes the refusal to overwrite atomic.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s already exists, refusing to overwrite", path)
	}
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	_, err = f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write %s: %w", path, err)
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "private key written to %s; keep it out of the repository\n", path)
	fmt.Fprintln(cmd.OutOrStdout(), base64.StdEncoding.EncodeToString(pub))
	return nil
}

func newSignCmd() *cobra.Command {
	var keyPath, inPath, outPath string
	cmd := &cobra.Command{
		Use:   "sign --key <file> --in <targets.json> --out <targets.signed.json>",
		Short: "Validate an unsigned targets list and sign it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			priv, err := readPrivateKey(keyPath)
			if err != nil {
				return err
			}
			in, err := os.ReadFile(inPath)
			if err != nil {
				return fmt.Errorf("read %s: %w", inPath, err)
			}
			list, err := targets.ParseUnsigned(in)
			if err != nil {
				return fmt.Errorf("%s: %w", inPath, err)
			}
			signed, err := targets.Sign(priv, *list)
			if err != nil {
				return err
			}
			if err := os.WriteFile(outPath, append(signed, '\n'), 0o644); err != nil {
				return fmt.Errorf("write %s: %w", outPath, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "signed rev %s, %d targets -> %s\n", list.Rev, len(list.Items), outPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "private key file made by keygen")
	cmd.Flags().StringVar(&inPath, "in", "", "unsigned targets list")
	cmd.Flags().StringVar(&outPath, "out", "", "signed output file")
	for _, name := range []string{"key", "in", "out"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func newVerifyCmd() *cobra.Command {
	var pubB64, inPath string
	cmd := &cobra.Command{
		Use:   "verify --pub <base64> --in <file>",
		Short: "Verify a signed targets file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
			if err != nil || len(raw) != ed25519.PublicKeySize {
				return errors.New("--pub must be a base64 ed25519 public key (32 bytes)")
			}
			data, err := os.ReadFile(inPath)
			if err != nil {
				return fmt.Errorf("read %s: %w", inPath, err)
			}
			list, err := targets.Verify(ed25519.PublicKey(raw), data)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "OK: rev %s, %d targets\n", list.Rev, len(list.Items))
			return nil
		},
	}
	cmd.Flags().StringVar(&pubB64, "pub", "", "public key, base64")
	cmd.Flags().StringVar(&inPath, "in", "", "signed targets file")
	_ = cmd.MarkFlagRequired("pub")
	_ = cmd.MarkFlagRequired("in")
	return cmd
}

// readPrivateKey loads a key file made by keygen. Errors never include the
// file contents.
func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("key %s: not a key file made by keygen", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
