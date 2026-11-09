package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/polargoose18/mayak/internal/runner"
)

// exitError carries a process exit code from a command to main. err may be
// nil when the command has already printed its own message.
type exitError struct {
	Code int
	Err  error
}

func (e *exitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit status %d", e.Code)
	}
	return e.Err.Error()
}

func (e *exitError) Unwrap() error { return e.Err }

// errInterrupted marks a run stopped by the user (SIGINT); main maps it to
// exit code 130.
var errInterrupted = errors.New("interrupted")

func main() {
	env := productionEnv()
	if err := newRootCmd(env).Execute(); err != nil {
		var ee *exitError
		switch {
		case errors.As(err, &ee):
			if ee.Err != nil && !errors.Is(ee.Err, errInterrupted) {
				fmt.Fprintln(os.Stderr, "error:", ee.Err)
			}
			os.Exit(ee.Code)
		default:
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}
}

// version is the agent's version; it is the one place it is named.
const version = "dev"

// newRootCmd builds the command tree; env is the world the check command
// runs against.
func newRootCmd(env runner.Env) *cobra.Command {
	root := &cobra.Command{
		Use:           "mayak",
		Short:         "Mayak network reachability agent",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetContext(context.Background())
	root.AddCommand(newVersionCmd())
	root.AddCommand(newCheckCmd(env))
	return root
}

// newVersionCmd prints the version.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the agent version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version)
			return err
		},
	}
}
