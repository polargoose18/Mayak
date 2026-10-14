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
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/polargoose18/mayak/internal/targets"
)

// keyFileName is the private key file created by keygen. The private key is
// stored as the base64 of the 32-byte ed25519 seed.
const keyFileName = "targets-signing.key"

func newRootCmd() *cobra.Command { return newRootCmdAt(time.Now) }

// newRootCmdAt builds the command with a clock, so that tests can fix the
// time against which expires is checked.
func newRootCmdAt(now func() time.Time) *cobra.Command {
	root := &cobra.Command{
		Use:           "mayak-sign",
		Short:         "Keys and signatures for the Mayak targets list (owner tool)",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newKeygenCmd(), newPubkeyCmd(), newSignCmd(now), newVerifyCmd(now))
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

func newPubkeyCmd() *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "pubkey --key <file>",
		Short: "Print the public key of a key file as base64",
		Long: `Print the public key that belongs to a private key file made by keygen: one
line of base64, the same as keygen printed, and nothing else. It is the form
that verify --pub takes and that goes into internal/targets/pubkeys.go.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			priv, err := readPrivateKey(keyPath)
			if err != nil {
				return err
			}
			warnKeyMode(cmd, keyPath)
			pub := priv.Public().(ed25519.PublicKey)
			fmt.Fprintln(cmd.OutOrStdout(), base64.StdEncoding.EncodeToString(pub))
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "private key file made by keygen")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func newSignCmd(now func() time.Time) *cobra.Command {
	var keyPath, inPath, outPath string
	cmd := &cobra.Command{
		Use:   "sign --key <file> --in <targets.json> --out <targets.signed.json>",
		Short: "Validate an unsigned targets list and sign it",
		Long: `Validate an unsigned targets list and sign its exact bytes.

The list carries its own rev and expires. Signing is refused if expires is in
the past or more than 30 days ahead, and if --out already holds a signed list
whose rev is not older than the new one: revs only grow.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			priv, err := readPrivateKey(keyPath)
			if err != nil {
				return err
			}
			warnKeyMode(cmd, keyPath)

			in, err := os.ReadFile(inPath)
			if err != nil {
				return fmt.Errorf("read %s: %w", inPath, err)
			}
			list, err := targets.ParseUnsigned(in)
			if err != nil {
				return fmt.Errorf("%s: %w", inPath, err)
			}
			if err := checkExisting(outPath, list.Rev); err != nil {
				return err
			}

			signed, err := targets.Sign(priv, in, now())
			if err != nil {
				return err
			}
			if err := os.WriteFile(outPath, append(signed, '\n'), 0o644); err != nil {
				return fmt.Errorf("write %s: %w", outPath, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "signed rev %s, %d targets, expires %s -> %s\n",
				list.Rev, len(list.Items), list.Expires.UTC().Format(time.RFC3339), outPath)
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

// checkExisting makes sure that signing into out does not roll back a signed
// list that is already there. The old list is read without checking its
// signature: it is the owner's own file, and after a key change it is signed
// by the old key.
func checkExisting(out, newRev string) error {
	old, err := os.ReadFile(out)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", out, err)
	}
	stored, err := targets.StoredRev(old)
	if err != nil {
		return fmt.Errorf("%s exists and is not a signed targets list, refusing to overwrite it", out)
	}
	if err := targets.CheckRev(stored, newRev); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	if c, _ := targets.CompareRev(newRev, stored); c == 0 {
		return fmt.Errorf("%s already holds rev %s: raise the rev of the new list", out, stored)
	}
	return nil
}

// warnKeyMode warns if other users can read the key file.
func warnKeyMode(cmd *cobra.Command, path string) {
	info, err := os.Stat(path)
	if err != nil || runtime.GOOS == "windows" {
		return
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s is accessible by other users (mode %04o); run chmod 600 on it\n", path, mode)
	}
}

func newVerifyCmd(now func() time.Time) *cobra.Command {
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
			list, err := targets.Verify([]ed25519.PublicKey{raw}, data, now())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "OK: rev %s, %d targets, expires %s\n",
				list.Rev, len(list.Items), list.Expires.UTC().Format(time.RFC3339))
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
