package osint

import (
	"context"
	"testing"

	"k3siem/goservice/internal/httpx"
)

func TestSafeBrowsingUnconfiguredReturnsNilWithoutNetworkCall(t *testing.T) {
	t.Setenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
	if safeBrowsingConfigured() {
		t.Fatal("expected safeBrowsingConfigured()=false with no key set")
	}
	// With no key set, safeBrowsingLookup must return nil immediately rather than attempting a
	// request — verified by using a context that's already canceled, so any real network
	// attempt would surface as an error/timeout instead of silently succeeding.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := safeBrowsingLookup(ctx, httpx.New(), "http://example.com/malware"); got != nil {
		t.Errorf("expected nil data when unconfigured, got %#v", got)
	}
}

func TestSafeBrowsingConfiguredGate(t *testing.T) {
	t.Setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key-not-real")
	if !safeBrowsingConfigured() {
		t.Fatal("expected safeBrowsingConfigured()=true once the env var is set")
	}
}
