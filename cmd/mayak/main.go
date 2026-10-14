// Command mayak is the Mayak agent CLI.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const version = "dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "mayak",
		Short:         "Mayak network reachability agent",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCmd())
	return root
}

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

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
