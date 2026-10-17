package runner

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/polargoose18/mayak/internal/targets"
)

// fixedRand always returns the same offset, clamped into [0, n).
type fixedRand struct{ v int64 }

func (r fixedRand) Int64N(n int64) int64 { return min(max(r.v, 0), n-1) }

func targetsOf(n int) []targets.Target {
	l := listOf("2026-10-20.1", testNow.Add(24*time.Hour), n)
	return l.Items
}

func poolEnv(r Rand) (Env, *fakeClock) {
	c := &fakeClock{now: testNow}
	return Env{Clock: c, Rand: r}, c
}

// TestOptionsMatchSpec compares with the numbers of SPEC section 5 written
// out, so that a changed constant breaks the test.
func TestOptionsMatchSpec(t *testing.T) {
	o := DefaultOptions()
	if o.Limit != 10 || o.Concurrency != 4 || o.PauseMin != 200*time.Millisecond ||
		o.PauseMax != 800*time.Millisecond || o.Timeout != 8*time.Second {
		t.Errorf("DefaultOptions() = %+v, want SPEC section 5", o)
	}
}

func TestRunRejectsLooserOptions(t *testing.T) {
	env, _ := poolEnv(fixedRand{})
	ok := func(context.Context, targets.Target) Result { return Result{} }
	tests := []struct {
		name string
		edit func(*Options)
	}{
		{"five at once", func(o *Options) { o.Concurrency = 5 }},
		{"none at once", func(o *Options) { o.Concurrency = 0 }},
		{"pause below 200 ms", func(o *Options) { o.PauseMin = 199 * time.Millisecond }},
		{"pause above 800 ms", func(o *Options) { o.PauseMax = 801 * time.Millisecond }},
		{"pause range upside down", func(o *Options) { o.PauseMin, o.PauseMax = 700*time.Millisecond, 300*time.Millisecond }},
		{"timeout above 8 s", func(o *Options) { o.Timeout = 8*time.Second + 1 }},
		{"no timeout", func(o *Options) { o.Timeout = 0 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := DefaultOptions()
			tc.edit(&o)
			if _, err := Run(context.Background(), env, o, targetsOf(3), ok); err == nil {
				t.Errorf("options %+v: want error", o)
			}
		})
	}
	if _, err := Run(context.Background(), Env{Rand: fixedRand{}}, DefaultOptions(), targetsOf(3), ok); err == nil {
		t.Error("no clock: want error")
	}
	if _, err := Run(context.Background(), Env{Clock: &fakeClock{}}, DefaultOptions(), targetsOf(3), ok); err == nil {
		t.Error("no rand: want error")
	}
	if _, err := Run(context.Background(), env, DefaultOptions(), targetsOf(3), nil); err == nil {
		t.Error("no check: want error")
	}
}

// TestRunPeakConcurrency holds every check until the pool has had the chance
// to start more than it may, then measures the peak.
func TestRunPeakConcurrency(t *testing.T) {
	for _, conc := range []int{4, 2, 1} {
		t.Run(fmt.Sprint(conc), func(t *testing.T) {
			env, _ := poolEnv(fixedRand{})
			o := DefaultOptions()
			o.Concurrency = conc

			var running, peak atomic.Int64
			release := make(chan struct{})
			check := func(ctx context.Context, tg targets.Target) Result {
				n := running.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				<-release
				running.Add(-1)
				return Result{Verdict: "ok"}
			}

			done := make(chan []Result)
			go func() {
				res, err := Run(context.Background(), env, o, targetsOf(12), check)
				if err != nil {
					t.Error(err)
				}
				done <- res
			}()
			// The fake clock does not wait, so a pool without a ceiling
			// would start all twelve at once. Wait for the ceiling, then a
			// little more for a check that should not come.
			deadline := time.Now().Add(5 * time.Second)
			for peak.Load() < int64(conc) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			time.Sleep(50 * time.Millisecond)
			close(release)
			res := <-done

			if got := peak.Load(); got != int64(conc) {
				t.Errorf("peak = %d checks at once, want exactly %d", got, conc)
			}
			if len(res) != 12 {
				t.Fatalf("got %d results, want 12", len(res))
			}
		})
	}
	// The default is the SPEC ceiling, written out.
	if DefaultOptions().Concurrency != 4 {
		t.Errorf("default concurrency = %d, want 4", DefaultOptions().Concurrency)
	}
}

func TestRunPauses(t *testing.T) {
	tests := []struct {
		name string
		rand Rand
		want time.Duration // 0: any value in the range
	}{
		{"shortest", fixedRand{0}, 200 * time.Millisecond},
		{"longest", fixedRand{1 << 62}, 800 * time.Millisecond},
		{"random", rand.New(rand.NewPCG(1, 2)), 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, clock := poolEnv(tc.rand)
			ok := func(context.Context, targets.Target) Result { return Result{} }
			if _, err := Run(context.Background(), env, DefaultOptions(), targetsOf(10), ok); err != nil {
				t.Fatal(err)
			}
			got := clock.pauses()
			if len(got) != 9 {
				t.Fatalf("%d pauses for 10 starts, want 9 (one before every start but the first)", len(got))
			}
			for i, d := range got {
				if d < 200*time.Millisecond || d > 800*time.Millisecond {
					t.Errorf("pause %d = %v, want 200..800 ms", i, d)
				}
				if tc.want != 0 && d != tc.want {
					t.Errorf("pause %d = %v, want %v", i, d, tc.want)
				}
			}
		})
	}
}

// TestRunPauseBeforeEachStart checks that the pause comes between two
// starts, not after them: a check starts only once the clock has moved on.
func TestRunPauseBeforeEachStart(t *testing.T) {
	env, _ := poolEnv(fixedRand{0})
	var mu sync.Mutex
	var starts []time.Time
	check := func(ctx context.Context, tg targets.Target) Result {
		mu.Lock()
		starts = append(starts, env.Clock.Now())
		mu.Unlock()
		return Result{}
	}
	res, err := Run(context.Background(), env, DefaultOptions(), targetsOf(5), check)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range res {
		if want := testNow.Add(time.Duration(i) * 200 * time.Millisecond); !r.Started.Equal(want) {
			t.Errorf("target %d started at %v, want %v", i, r.Started, want)
		}
	}
	if len(starts) != 5 {
		t.Errorf("%d checks ran, want 5", len(starts))
	}
}

func TestRunKeepsListOrder(t *testing.T) {
	env, _ := poolEnv(rand.New(rand.NewPCG(3, 4)))
	items := targetsOf(9)
	// Later targets finish first.
	check := func(ctx context.Context, tg targets.Target) Result {
		var i int
		fmt.Sscanf(tg.ID, "t%d", &i)
		time.Sleep(time.Duration(9-i) * time.Millisecond)
		return Result{Verdict: "ok", Target: targets.Target{ID: "overwritten"}}
	}
	res, err := Run(context.Background(), env, DefaultOptions(), items, check)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range res {
		if r.Target.ID != items[i].ID {
			t.Errorf("result %d is for %s, want %s", i, r.Target.ID, items[i].ID)
		}
		if r.Verdict != "ok" || r.Err != nil {
			t.Errorf("result %d = %v, %v; want the check's own result", i, r.Verdict, r.Err)
		}
	}
}

// TestRunTestTimeout: the check gets a context with the test timeout, and a
// check that waits on it ends with a result rather than hanging the run.
func TestRunTestTimeout(t *testing.T) {
	env, _ := poolEnv(fixedRand{})

	t.Run("8 s by default", func(t *testing.T) {
		var left []time.Duration
		var mu sync.Mutex
		check := func(ctx context.Context, tg targets.Target) Result {
			d, ok := ctx.Deadline()
			if !ok {
				t.Error("check context has no deadline")
			}
			mu.Lock()
			left = append(left, time.Until(d))
			mu.Unlock()
			return Result{}
		}
		if _, err := Run(context.Background(), env, DefaultOptions(), targetsOf(3), check); err != nil {
			t.Fatal(err)
		}
		for _, l := range left {
			if l > 8*time.Second || l < 7*time.Second {
				t.Errorf("deadline %v ahead, want 8 s", l)
			}
		}
	})

	t.Run("fires", func(t *testing.T) {
		o := DefaultOptions()
		o.Timeout = 30 * time.Millisecond
		check := func(ctx context.Context, tg targets.Target) Result {
			<-ctx.Done() // a probe that never gets an answer
			return Result{Verdict: "timeout_seen", Err: ctx.Err()}
		}
		done := make(chan []Result)
		go func() {
			res, err := Run(context.Background(), env, o, targetsOf(6), check)
			if err != nil {
				t.Error(err)
			}
			done <- res
		}()
		select {
		case res := <-done:
			for i, r := range res {
				if r.Verdict != "timeout_seen" || !errors.Is(r.Err, context.DeadlineExceeded) {
					t.Errorf("result %d = %v, %v; want the check's result after its timeout", i, r.Verdict, r.Err)
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the run hangs on checks that time out")
		}
	})
}

// blockingClock is a Clock whose After never fires, so that a run can be
// cancelled during a pause.
type blockingClock struct{ fakeClock }

func (c *blockingClock) After(time.Duration) <-chan time.Time { return make(chan time.Time) }

func TestRunCancel(t *testing.T) {
	tests := []struct {
		name  string
		clock Clock
	}{
		{"during checks", &fakeClock{now: testNow}},
		{"during a pause", &blockingClock{fakeClock{now: testNow}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := runtime.NumGoroutine()
			ctx, cancel := context.WithCancel(context.Background())
			var started atomic.Int64
			check := func(cctx context.Context, tg targets.Target) Result {
				if started.Add(1) == 1 {
					cancel()
				}
				<-cctx.Done()
				return Result{Err: cctx.Err()}
			}
			done := make(chan struct{})
			var res []Result
			var err error
			go func() {
				res, err = Run(ctx, Env{Clock: tc.clock, Rand: fixedRand{}}, DefaultOptions(), targetsOf(10), check)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("the run does not end after cancel")
			}
			if !errors.Is(err, context.Canceled) {
				t.Errorf("err = %v, want context.Canceled", err)
			}
			if len(res) != 10 {
				t.Fatalf("got %d results, want one per target", len(res))
			}
			items := targetsOf(10)
			for i, r := range res {
				if r.Target.ID != items[i].ID || !errors.Is(r.Err, context.Canceled) {
					t.Errorf("result %d = %s, %v; want %s cancelled", i, r.Target.ID, r.Err, items[i].ID)
				}
			}
			if n := started.Load(); n == 10 {
				t.Error("every target started despite the cancel")
			}

			deadline := time.Now().Add(2 * time.Second)
			for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if n := runtime.NumGoroutine(); n > before {
				t.Errorf("%d goroutines after the run, %d before: a goroutine leaked", n, before)
			}
		})
	}
}

func TestRunEmptyList(t *testing.T) {
	env, clock := poolEnv(fixedRand{})
	res, err := Run(context.Background(), env, DefaultOptions(), nil, func(context.Context, targets.Target) Result {
		t.Error("check called for an empty list")
		return Result{}
	})
	if err != nil || len(res) != 0 || len(clock.pauses()) != 0 {
		t.Errorf("got %v, %v, %d pauses; want nothing", res, err, len(clock.pauses()))
	}
}

func TestSystemClock(t *testing.T) {
	var c Clock = SystemClock{}
	if d := time.Since(c.Now()); d < 0 || d > time.Second {
		t.Errorf("Now is %v off", d)
	}
	select {
	case <-c.After(time.Millisecond):
	case <-time.After(5 * time.Second):
		t.Error("After does not fire")
	}
}
