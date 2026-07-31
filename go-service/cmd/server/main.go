// Command server runs the Go OSINT/IOC-cache/analyzer service as a long-running HTTP daemon —
// meant to sit behind Node (see cmd/analyzer-cli for the standalone offline CLI, which shares
// the same internal packages). Not intended to be exposed publicly; Node proxies to it.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"time"

	"k3siem/goservice/internal/api"
	"k3siem/goservice/internal/cache"
	"k3siem/goservice/internal/config"
	"k3siem/goservice/internal/feeds"
	"k3siem/goservice/internal/httpx"
	"k3siem/goservice/internal/scheduler"
)

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	// Convenience for this repo's local dev: the OSINT/feed API keys already live in
	// backend/.env. A dedicated go-service/.env (if present) takes priority; real
	// environment variables always win over either file.
	config.LoadDotEnv(".env")
	config.LoadDotEnv("../backend/.env")

	addr := getEnv("GO_SERVICE_ADDR", ":8090")
	cachePath := getEnv("GO_SERVICE_CACHE_PATH", "./data/cache.db")

	intervalDays := 30
	if v := os.Getenv("FEED_SYNC_INTERVAL_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			intervalDays = n
		}
	}

	if dir := filepath.Dir(cachePath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("create cache directory: %v", err)
		}
	}
	store, err := cache.Open(cachePath)
	if err != nil {
		log.Fatalf("open cache: %v", err)
	}
	defer store.Close()

	client := httpx.New()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Automatic side of "update on request or automatically every month" — manual refresh is
	// just POST /v1/intel/feeds/sync, handled independently of this ticker.
	interval := time.Duration(intervalDays) * 24 * time.Hour
	scheduler.StartPeriodic(ctx, interval, false, func(ctx context.Context) error {
		log.Printf("[scheduler] running scheduled feed sync (every %d days)", intervalDays)
		summary, err := feeds.SyncAll(ctx, store, client, false)
		if err != nil {
			return err
		}
		log.Printf("[scheduler] feed sync done: %d active, %d errors, %d added", summary.Totals.Active, summary.Totals.Errors, summary.Totals.Added)
		return nil
	})

	srv := &http.Server{Addr: addr, Handler: api.New(store, client).Handler()}

	go func() {
		log.Printf("[server] listening on %s (cache=%s, feed sync every %d days)", addr, cachePath, intervalDays)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("[server] shutting down…")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[server] shutdown error: %v", err)
	}
}
