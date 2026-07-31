// Package scheduler runs a periodic background refresh — the automatic side of "cache feed can
// be updated by the user on their requirement basis or automatically update in 1 month
// duration": a simple time.Ticker is all a 30-day default cadence needs, no cron-expression
// parser required. Manual refresh is just calling feeds.SyncAll directly (e.g. via the CLI's
// `sync feeds` or the HTTP API's `POST /v1/intel/feeds/sync`) — this package only owns the
// unattended, scheduled path.
package scheduler

import (
	"context"
	"log"
	"time"
)

// DefaultInterval is the "automatic update in 1 month duration" the user asked for.
const DefaultInterval = 30 * 24 * time.Hour

// StartPeriodic runs fn once per interval until ctx is canceled, logging (but not panicking
// on) any error fn returns so one bad cycle doesn't take down the scheduler. It does not run
// fn immediately on start — the cache is expected to already be populated by an initial manual
// sync (e.g. at first-run setup); pass runImmediately=true to change that.
func StartPeriodic(ctx context.Context, interval time.Duration, runImmediately bool, fn func(ctx context.Context) error) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	go func() {
		if runImmediately {
			if err := fn(ctx); err != nil {
				log.Printf("[scheduler] initial run failed: %v", err)
			}
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := fn(ctx); err != nil {
					log.Printf("[scheduler] periodic run failed: %v", err)
				}
			}
		}
	}()
}
