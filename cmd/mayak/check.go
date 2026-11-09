package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/polargoose18/mayak/internal/report"
	"github.com/polargoose18/mayak/internal/runner"
	"github.com/polargoose18/mayak/internal/targets"
)

// guardNoControl is printed when the build has no control node: without one
// nothing can be measured, and nothing was touched.
const guardNoControl = "mayak check: no control node is configured in this build, so nothing can be measured. Nothing was sent."

// inconclusiveSentence is printed when every target of the run came out
// inconclusive: the measurement itself cannot be trusted (ADR-006, Q5).
const inconclusiveSentence = "The control node was unreachable, so no result of this run can be trusted."

// verdictSentence maps every verdict to one plain-English sentence.
var verdictSentence = map[report.Verdict]string{
	report.VerdictOK:             "The site opened normally.",
	report.VerdictDNSTamper:      "The DNS answer looks forged: the address is not a real one for this site.",
	report.VerdictIPBlock:        "The site's address refuses connections, which looks like an IP block.",
	report.VerdictSNIBlock:       "The connection is cut when the site's name is shown, which looks like SNI filtering.",
	report.VerdictTLSIntercept:   "The TLS certificate does not match the site, which looks like interception.",
	report.VerdictHTTPStub:       "The site answers with a known block page instead of its real content.",
	report.VerdictQUICBlock:      "The site cannot be reached over QUIC while other paths work.",
	report.VerdictVendorGeoblock: "The site itself reports that it is unavailable from this region.",
	report.VerdictTimeoutUnknown: "The site never answered, so the reason could not be determined.",
	report.VerdictInconclusive:   "The control node could not be reached, so no trustworthy measurement was possible.",
	report.VerdictVendorDown:     "The site seems to be down for everyone right now.",
	report.VerdictAllowlistMode:  "The network only allows a list of approved sites, and this one is not on it.",
	report.VerdictFreezeAfterN:   "The connection starts but stalls after some data, which looks like throttling by volume.",
	report.VerdictThrottled:      "The site is reachable but much slower than it should be, which looks like throttling.",
}

func newCheckCmd(env runner.Env) *cobra.Command {
	var (
		limit       int
		targetsKind string
		targetsFile string
		asJSON      bool
	)
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Measure how the targets of the signed list open from this network",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCheck(cmd, env, checkFlags{
				Limit: limit, Targets: targetsKind, TargetsFile: targetsFile, JSON: asJSON,
			})
		},
	}
	cmd.Flags().IntVar(&limit, "limit", runner.DefaultLimit,
		fmt.Sprintf("how many targets to check (%d..%d)", runner.MinLimit, runner.MaxLimit))
	cmd.Flags().StringVar(&targetsKind, "targets", "", `which set of targets to check (only "core")`)
	cmd.Flags().StringVar(&targetsFile, "targets-file", "", "path to a signed targets list (default: the list built into mayak)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON instead of text")
	return cmd
}

type checkFlags struct {
	Limit       int
	Targets     string
	TargetsFile string
	JSON        bool
}

func runCheck(cmd *cobra.Command, env runner.Env, f checkFlags) error {
	ctx := cmd.Context()

	// Ctrl-C stops the run; main maps this to exit code 130.
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	if f.Limit < runner.MinLimit || f.Limit > runner.MaxLimit {
		return &exitError{Code: 1, Err: fmt.Errorf(
			"--limit must be between %d and %d, got %d", runner.MinLimit, runner.MaxLimit, f.Limit)}
	}
	switch f.Targets {
	case "", "core":
	default:
		return &exitError{Code: 1, Err: fmt.Errorf("--targets must be \"core\" or empty, got %q", f.Targets)}
	}

	dir, err := userDir()
	if err != nil {
		return &exitError{Code: 1, Err: fmt.Errorf("find the mayak directory: %w", err)}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return &exitError{Code: 1, Err: fmt.Errorf("create the mayak directory %s: %w", dir, err)}
	}

	// Stage state so cancellation never changes the accepted rev or rotation.
	staged, err := os.MkdirTemp(dir, ".check-")
	if err != nil {
		return &exitError{Code: 1, Err: fmt.Errorf("prepare the mayak state: %w", err)}
	}
	defer os.RemoveAll(staged)
	for _, name := range []string{runner.RevFile, runner.RotationFile} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return &exitError{Code: 1, Err: fmt.Errorf("read the mayak state: %w", err)}
		}
		if err := os.WriteFile(filepath.Join(staged, name), data, 0o600); err != nil {
			return &exitError{Code: 1, Err: fmt.Errorf("prepare the mayak state: %w", err)}
		}
	}
	src := runner.Source{File: f.TargetsFile, Dir: staged}
	list, err := src.Load(env)
	if err != nil {
		return &exitError{Code: 1, Err: err}
	}
	picked, err := src.Pick(list, f.Limit)
	if err != nil {
		return &exitError{Code: 1, Err: err}
	}

	// The guard runs before any network use: without a control node there is
	// nothing to measure and nothing was touched.
	if env.Control.BaseURL == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), guardNoControl)
		return &exitError{Code: 2}
	}

	opts := runner.DefaultOptions()
	opts.Limit = f.Limit
	results, err := runner.Run(ctx, env, opts, picked, func(ctx context.Context, t targets.Target) runner.Result {
		return runner.Check(ctx, env, t)
	})
	interrupted := err != nil && ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled)
	if err != nil && !interrupted {
		return &exitError{Code: 1, Err: fmt.Errorf("run the checks: %w", err)}
	}
	if interrupted {
		return interruptedOutput(cmd, env, list, results)
	}
	for _, name := range []string{runner.RevFile, runner.RotationFile} {
		if err := os.Rename(filepath.Join(staged, name), filepath.Join(dir, name)); err != nil {
			return &exitError{Code: 1, Err: fmt.Errorf("record the mayak state: %w", err)}
		}
	}

	// Every verdict inconclusive means the measurement itself cannot be
	// trusted (ADR-006, Q5): say so and exit 2.
	trusted := false
	for _, r := range results {
		if r.Verdict != report.VerdictInconclusive {
			trusted = true
			break
		}
	}
	if !trusted {
		if f.JSON {
			if err := printJSON(cmd, env, list, results); err != nil {
				return err
			}
			return &exitError{Code: 2}
		}
		printText(cmd, results)
		fmt.Fprintln(cmd.OutOrStdout(), inconclusiveSentence)
		return &exitError{Code: 2}
	}

	if f.JSON {
		return printJSON(cmd, env, list, results)
	}
	printText(cmd, results)
	return nil
}

// interruptedOutput prints what an interrupted run produced and reports
// exit 130. Text: the measured results, the summary, the interrupt sentence.
// JSON: one array of only the measured results, or nothing on stdout when
// none was measured. Results with Err set never reach the report.
func interruptedOutput(cmd *cobra.Command, env runner.Env, list *targets.Targets, results []runner.Result) error {
	var measured []runner.Result
	for _, r := range results {
		if r.Err == nil {
			measured = append(measured, r)
		}
	}
	if f := flagJSON(cmd); f {
		if err := printJSON(cmd, env, list, measured); err != nil {
			return err
		}
		return &exitError{Code: 130, Err: errInterrupted}
	}
	printText(cmd, measured)
	fmt.Fprintln(cmd.OutOrStdout(), interruptSentence)
	return &exitError{Code: 130, Err: errInterrupted}
}

// interruptSentence is printed after an interrupted run's results.
const interruptSentence = "The run was interrupted; it stopped before finishing, and nothing was sent."

// flagJSON reports whether the check command runs with --json; the flag set
// is looked up on the command that is executing.
func flagJSON(cmd *cobra.Command) bool {
	v, err := cmd.Flags().GetBool("json")
	return err == nil && v
}

// userDir is the agent's directory for its files (os.UserConfigDir()/mayak).
func userDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "mayak"), nil
}

// printText writes one line per result, a summary and the sending notice.
func printText(cmd *cobra.Command, results []runner.Result) {
	out := cmd.OutOrStdout()
	counts := map[report.Verdict]int{}
	for _, r := range results {
		counts[r.Verdict]++
		sentence, ok := verdictSentence[r.Verdict]
		if !ok {
			sentence = "The result could not be interpreted."
		}
		fmt.Fprintf(out, "%s  %s  %s\n", r.Target.ID, r.Verdict, sentence)
	}
	fmt.Fprintf(out, "Summary: %d checked", len(results))
	for _, v := range report.Verdicts() {
		if counts[v] == 0 {
			continue
		}
		fmt.Fprintf(out, ", %s %d", v, counts[v])
	}
	fmt.Fprintln(out)

	if len(results) > 0 && counts[report.VerdictInconclusive] == len(results) {
		fmt.Fprintln(out, "The control node was unreachable, so nothing could be measured.")
	}
	fmt.Fprintln(out, "Nothing was sent.")
}

// printJSON writes exactly one JSON array of report documents to stdout.
func printJSON(cmd *cobra.Command, env runner.Env, list *targets.Targets, results []runner.Result) error {
	if len(results) == 0 {
		return nil
	}
	meta := runner.ReportMeta{
		Ver:      version,
		OS:       runner.OSName(runtime.GOOS),
		Rev:      list.Rev,
		Now:      env.Clock.Now(),
		IPVer:    runner.IPVersion(results),
		Resolver: report.ResolverUnknown,
	}
	doc, err := runner.BuildReport(meta, results)
	if err != nil {
		return &exitError{Code: 1, Err: fmt.Errorf("build the report: %w", err)}
	}
	if err := json.NewEncoder(cmd.OutOrStdout()).Encode([]report.Report{doc}); err != nil {
		return &exitError{Code: 1, Err: fmt.Errorf("print the report: %w", err)}
	}
	return nil
}
