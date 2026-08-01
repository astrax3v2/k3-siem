package analyzer

import (
	"context"
	"path/filepath"
	"testing"

	"k3siem/goservice/internal/cache"
	"k3siem/goservice/internal/httpx"
	"k3siem/goservice/internal/ioc"
)

func TestEnrichLiveSkipsAlreadyCachedHits(t *testing.T) {
	store, err := cache.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	defer store.Close()

	result := Result{
		Hits: []Hit{
			{Indicator: ioc.Indicator{Type: ioc.TypeIP, Value: "203.0.113.9"}}, // no OSINT yet
			{Indicator: ioc.Indicator{Type: ioc.TypeHash, Value: "deadbeef"}},  // unsupported kind, must be left alone
		},
	}

	// A hash-type hit has no osintKind mapping, so EnrichLive must leave it untouched and not
	// attempt any network call for it.
	EnrichLive(context.Background(), httpx.New(), store, &result)

	if result.Hits[1].OSINT != nil {
		t.Errorf("expected hash-type hit to be left alone, got OSINT: %#v", result.Hits[1].OSINT)
	}
}

func TestEnrichLiveNoTargetsIsNoop(t *testing.T) {
	store, err := cache.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	defer store.Close()

	result := Result{}
	EnrichLive(context.Background(), httpx.New(), store, &result) // must not panic on empty hits
}
