package probe

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// start returns a function that reports the milliseconds since this call.
func start() func() int64 {
	t0 := time.Now()
	return func() int64 { return time.Since(t0).Milliseconds() }
}

// cancelled returns an error if the caller cancelled ctx. An expired deadline
// is not an error here: it makes the individual attempts time out, which is a
// result.
func cancelled(test string, ctx context.Context) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return fmt.Errorf("%s: %w", test, ctx.Err())
	}
	return nil
}
