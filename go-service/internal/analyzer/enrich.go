package analyzer

import (
	"context"
	"runtime"
	"sync"

	"k3siem/goservice/internal/cache"
	"k3siem/goservice/internal/httpx"
	"k3siem/goservice/internal/osint"
)

// EnrichLive performs live OSINT lookups (requires network) for every distinct IP/domain hit
// in result that doesn't already have cached OSINT data, then updates those hits in place.
// This geolocates and enriches exactly the malicious infrastructure this specific piece of
// evidence actually touched — not the entire IOC cache, which could be hundreds of thousands
// of entries and would blow through free API rate limits for no forensic benefit. Call this
// only when live network access is acceptable; Analyze() itself never does this.
func EnrichLive(ctx context.Context, client *httpx.Client, store *cache.Store, result *Result) {
	type target struct {
		kind  string // "ip" | "domain"
		value string
	}
	seen := map[target]bool{}
	var targets []target
	for _, hit := range result.Hits {
		if hit.OSINT != nil {
			continue // already had cached data at match time
		}
		kind, ok := osintKind(hit.Indicator.Type)
		if !ok {
			continue
		}
		t := target{kind: kind, value: hit.Indicator.Value}
		if seen[t] {
			continue
		}
		seen[t] = true
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		return
	}

	fetched := make(map[target]osint.Result, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup
	limit := runtime.NumCPU()
	if limit < 4 {
		limit = 4
	}
	sem := make(chan struct{}, limit)
	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t target) {
			defer wg.Done()
			defer func() { <-sem }()
			var res osint.Result
			switch t.kind {
			case "ip":
				res = osint.LookupIP(ctx, client, store, t.value, osint.DefaultTTL)
			case "domain":
				res = osint.LookupDomain(ctx, client, store, t.value, osint.DefaultTTL)
			}
			mu.Lock()
			fetched[t] = res
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	for i := range result.Hits {
		kind, ok := osintKind(result.Hits[i].Indicator.Type)
		if !ok || result.Hits[i].OSINT != nil {
			continue
		}
		if res, ok := fetched[target{kind: kind, value: result.Hits[i].Indicator.Value}]; ok {
			r := res
			result.Hits[i].OSINT = &r
		}
	}
}
