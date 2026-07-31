// Command analyzer-cli is the standalone entrypoint for the offline log analyzer: sync threat
// intel feeds into a local cache, then analyze a log file fully offline against that cache —
// no live backend, no live internet access at analysis time once the cache is populated.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"k3siem/goservice/internal/analyzer"
	"k3siem/goservice/internal/cache"
	"k3siem/goservice/internal/feeds"
	"k3siem/goservice/internal/httpx"
	"k3siem/goservice/internal/osint"
	"k3siem/goservice/internal/report"
)

var cachePath string

func main() {
	root := &cobra.Command{
		Use:   "analyzer-cli",
		Short: "K3 SIEM offline log analyzer: threat-intel feed cache + IOC-matching log analysis",
	}
	root.PersistentFlags().StringVar(&cachePath, "cache", "./data/cache.db", "path to the local IOC/feed cache file")

	root.AddCommand(newSyncCmd(), newAnalyzeCmd(), newCacheCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func openStore() (*cache.Store, error) {
	if dir := filepath.Dir(cachePath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create cache directory: %w", err)
		}
	}
	return cache.Open(cachePath)
}

// rootContext is canceled on SIGINT/SIGTERM so a long feed sync or analysis run can shut down
// cleanly instead of leaving the cache file mid-write.
func rootContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

func newSyncCmd() *cobra.Command {
	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "Refresh cached data from live sources",
	}

	var force bool
	feedsCmd := &cobra.Command{
		Use:   "feeds",
		Short: "Sync all 13 threat-intel IOC feeds into the local cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := rootContext()
			defer cancel()

			store, err := openStore()
			if err != nil {
				return err
			}
			defer store.Close()

			client := httpx.New()
			summary, err := feeds.SyncAll(ctx, store, client, force)
			if err != nil {
				return err
			}

			fmt.Printf("Synced %d feeds: %d active, %d errors, %d waiting on config, %d new IOCs added\n\n",
				summary.Totals.Feeds, summary.Totals.Active, summary.Totals.Errors, summary.Totals.WaitingOnConfig, summary.Totals.Added)
			for _, r := range summary.Feeds {
				line := fmt.Sprintf("  [%-16s] %-30s total=%d added=%d", r.Status, r.Name, r.Total, r.Added)
				if r.Error != "" {
					line += " — " + r.Error
				}
				fmt.Println(line)
			}
			return nil
		},
	}
	feedsCmd.Flags().BoolVar(&force, "force", false, "bypass any persisted rate-limit cooldown and retry now")
	syncCmd.AddCommand(feedsCmd)

	var targetType, target string
	var refresh bool
	osintCmd := &cobra.Command{
		Use:   "osint",
		Short: "Look up an IP/domain/hash/email against live OSINT sources and cache the result",
		RunE: func(cmd *cobra.Command, args []string) error {
			if target == "" {
				return fmt.Errorf("--target is required")
			}
			ctx, cancel := rootContext()
			defer cancel()

			store, err := openStore()
			if err != nil {
				return err
			}
			defer store.Close()

			client := httpx.New()
			ttl := osint.DefaultTTL
			if refresh {
				ttl = 0 // force a live re-fetch regardless of cached freshness
			}

			var result osint.Result
			switch targetType {
			case "ip":
				result = osint.LookupIP(ctx, client, store, target, ttl)
			case "domain":
				result = osint.LookupDomain(ctx, client, store, target, ttl)
			case "hash":
				result = osint.LookupHash(ctx, client, store, target, ttl)
			case "email":
				result = osint.LookupEmail(ctx, client, store, target, ttl)
			default:
				return fmt.Errorf("--type must be one of ip, domain, hash, email (got %q)", targetType)
			}

			fmt.Printf("OSINT lookup for %s (%s), cached at %s:\n", result.Target, result.Type, result.FetchedAt.Format(time.RFC3339))
			names := make([]string, 0, len(result.Sources))
			for name := range result.Sources {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				src := result.Sources[name]
				status := "no data"
				if !src.Configured {
					status = "not configured"
				} else if src.Data != nil {
					status = "cached"
				}
				fmt.Printf("  %-12s %s\n", name, status)
			}
			return nil
		},
	}
	osintCmd.Flags().StringVar(&targetType, "type", "", "target type: ip, domain, hash, or email (required)")
	osintCmd.Flags().StringVar(&target, "target", "", "the IP/domain/hash/email to look up (required)")
	osintCmd.Flags().BoolVar(&refresh, "refresh", false, "bypass the cached TTL and force a live re-fetch")
	syncCmd.AddCommand(osintCmd)

	return syncCmd
}

func newAnalyzeCmd() *cobra.Command {
	var input, outJSON, outHTML string
	var offline bool

	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze a log file against the cached IOC set",
		RunE: func(cmd *cobra.Command, args []string) error {
			if input == "" {
				return fmt.Errorf("--input is required")
			}
			ctx, cancel := rootContext()
			defer cancel()

			store, err := openStore()
			if err != nil {
				return err
			}
			defer store.Close()

			if offline {
				stats, err := store.Stats()
				if err != nil {
					return err
				}
				if stats.Total == 0 {
					return fmt.Errorf("--offline requires a populated cache, but %s has 0 cached IOCs — run `analyzer-cli sync feeds` at least once first", cachePath)
				}
			}

			result, err := analyzer.Analyze(ctx, store, input)
			if err != nil {
				return err
			}

			fmt.Printf("Scanned %d lines in %s, found %d indicator hits (%s)\n",
				result.LinesScanned, result.Input, len(result.Hits), result.FinishedAt.Sub(result.StartedAt).Round(time.Millisecond))
			for sev, count := range result.HitsBySeverity {
				fmt.Printf("  %-10s %d\n", sev, count)
			}

			if outJSON != "" {
				if err := report.WriteJSON(result, outJSON); err != nil {
					return fmt.Errorf("write JSON report: %w", err)
				}
				fmt.Println("JSON report:", outJSON)
			}
			if outHTML != "" {
				if err := report.WriteHTML(result, outHTML); err != nil {
					return fmt.Errorf("write HTML report: %w", err)
				}
				fmt.Println("HTML report:", outHTML)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&input, "input", "", "path to the log file to analyze (required)")
	cmd.Flags().StringVar(&outJSON, "out", "", "write a JSON report to this path")
	cmd.Flags().StringVar(&outHTML, "html", "", "write a self-contained HTML report to this path")
	cmd.Flags().BoolVar(&offline, "offline", false, "refuse to run unless the cache is already populated (compliance/air-gap assertion)")
	return cmd
}

func newCacheCmd() *cobra.Command {
	cacheCmd := &cobra.Command{
		Use:   "cache",
		Short: "Inspect the local IOC/feed cache",
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show cached IOC counts and per-feed sync status",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openStore()
			if err != nil {
				return err
			}
			defer store.Close()

			stats, err := store.Stats()
			if err != nil {
				return err
			}
			fmt.Printf("Cache file: %s\n", store.Path())
			fmt.Printf("Total IOCs: %d\n\n", stats.Total)

			fmt.Println("By type:")
			for t, count := range stats.ByType {
				fmt.Printf("  %-8s %d\n", t, count)
			}

			feedMeta, err := store.ListFeedMeta()
			if err != nil {
				return err
			}
			sort.Slice(feedMeta, func(i, j int) bool { return feedMeta[i].Name < feedMeta[j].Name })

			fmt.Println("\nFeeds:")
			for _, m := range feedMeta {
				lastSync := "never"
				if !m.LastSync.IsZero() {
					lastSync = m.LastSync.Format("2006-01-02 15:04:05 MST")
				}
				fmt.Printf("  [%-16s] %-30s ioc_count=%-6d last_sync=%s\n", m.Status, m.Name, m.IOCCount, lastSync)
				if m.LastError != "" {
					fmt.Printf("      last_error: %s\n", m.LastError)
				}
			}
			return nil
		},
	}
	cacheCmd.AddCommand(statusCmd)
	return cacheCmd
}
