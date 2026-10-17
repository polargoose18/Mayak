package runner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/polargoose18/mayak/internal/targets"
)

// CheckFunc checks one target. It must return once ctx is done: the pool
// relies on it to end a test at its timeout and a run at its cancel.
type CheckFunc func(ctx context.Context, t targets.Target) Result

// SystemClock is the real Clock.
type SystemClock struct{}

// Now returns the current time.
func (SystemClock) Now() time.Time { return time.Now() }

// After waits for d on the real clock.
func (SystemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// DefaultOptions returns the ceilings of SPEC section 5 and the default
// number of targets (ADR-006, Q3).
func DefaultOptions() Options {
	return Options{
		Limit:       DefaultLimit,
		Concurrency: MaxConcurrency,
		PauseMin:    PauseMin,
		PauseMax:    PauseMax,
		Timeout:     TestTimeout,
	}
}

// checkPool refuses options looser than the ceilings. Limit is not checked
// here: Run gets the targets already picked.
func (o Options) checkPool() error {
	switch {
	case o.Concurrency < 1 || o.Concurrency > MaxConcurrency:
		return fmt.Errorf("concurrency %d is outside 1..%d", o.Concurrency, MaxConcurrency)
	case o.PauseMin < PauseMin || o.PauseMax > PauseMax || o.PauseMin > o.PauseMax:
		return fmt.Errorf("pause %v..%v is outside %v..%v", o.PauseMin, o.PauseMax, PauseMin, PauseMax)
	case o.Timeout <= 0 || o.Timeout > TestTimeout:
		return fmt.Errorf("test timeout %v is outside (0, %v]", o.Timeout, TestTimeout)
	}
	return nil
}

// Run checks the targets within the ceilings of SPEC section 5: at most
// opts.Concurrency checks at the same time, a pause of opts.PauseMin to
// opts.PauseMax (picked with env.Rand, waited on env.Clock) before every start
// but the first, and a context with opts.Timeout for each check. The results
// are in the order of list; Run sets their Target, Started and Duration.
//
// If ctx is cancelled, no new check starts, the running ones see the cancel
// through their context, and Run returns once they have ended, with ctx's
// error. A target that did not start gets a Result with only Target and Err.
func Run(ctx context.Context, env Env, opts Options, list []targets.Target, check CheckFunc) ([]Result, error) {
	if err := opts.checkPool(); err != nil {
		return nil, fmt.Errorf("run checks: %w", err)
	}
	if env.Clock == nil || env.Rand == nil {
		return nil, errors.New("run checks: no clock or no randomness")
	}
	if check == nil {
		return nil, errors.New("run checks: no check")
	}

	results := make([]Result, len(list))
	slots := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	next := 0
	for ; next < len(list); next++ {
		// Пауза до занятия слота: между двумя стартами проходит не меньше
		// паузы, даже если слот освобождается сразу.
		if next > 0 && !wait(ctx, env.Clock, pause(env.Rand, opts)) {
			break
		}
		if !acquire(ctx, slots) {
			break
		}
		wg.Add(1)
		go func(i int, started time.Time) {
			defer wg.Done()
			defer func() { <-slots }()
			results[i] = runOne(ctx, env.Clock, started, opts.Timeout, list[i], check)
		}(next, env.Clock.Now())
	}
	wg.Wait()

	for i := next; i < len(list); i++ {
		results[i] = Result{Target: list[i], Err: ctx.Err()}
	}
	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, nil
}

func runOne(ctx context.Context, clock Clock, started time.Time, timeout time.Duration, t targets.Target, check CheckFunc) Result {
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	r := check(tctx, t)
	r.Target = t
	r.Started = started
	r.Duration = clock.Now().Sub(started)
	return r
}

// pause picks a pause in [opts.PauseMin, opts.PauseMax].
func pause(r Rand, opts Options) time.Duration {
	return opts.PauseMin + time.Duration(r.Int64N(int64(opts.PauseMax-opts.PauseMin)+1))
}

// acquire takes a slot and reports false if ctx ended first. A slot taken at
// the same moment as the cancel is given back: the target does not start.
func acquire(ctx context.Context, slots chan struct{}) bool {
	select {
	case slots <- struct{}{}:
		if ctx.Err() != nil {
			<-slots
			return false
		}
		return true
	case <-ctx.Done():
		return false
	}
}

// wait waits for d on clock and reports false if ctx ended first.
func wait(ctx context.Context, clock Clock, d time.Duration) bool {
	select {
	case <-clock.After(d):
		return ctx.Err() == nil
	case <-ctx.Done():
		return false
	}
}
