package osint

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"k3siem/goservice/internal/cache"
	"k3siem/goservice/internal/httpx"
)

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.5", true},
		{"192.168.1.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"", true},
	}
	for _, c := range cases {
		if got := isPrivateIP(c.ip); got != c.want {
			t.Errorf("isPrivateIP(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestLookupHashUnconfiguredReturnsNilData(t *testing.T) {
	t.Setenv("VIRUSTOTAL_API_KEY", "")
	store, err := cache.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	defer store.Close()

	result := LookupHash(context.Background(), httpx.New(), store, "deadbeef", DefaultTTL)
	src, ok := result.Sources["virustotal"]
	if !ok {
		t.Fatal("expected a virustotal source entry")
	}
	if src.Configured {
		t.Error("expected configured=false with no API key set")
	}
	if src.Data != nil {
		t.Errorf("expected nil data when unconfigured, got %#v", src.Data)
	}
}

func TestOsintCacheRoundTrip(t *testing.T) {
	store, err := cache.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	defer store.Close()

	t.Setenv("VIRUSTOTAL_API_KEY", "")
	first := LookupHash(context.Background(), httpx.New(), store, "abc123", DefaultTTL)

	cached, ok := GetCachedOnly(store, "hash", "abc123")
	if !ok {
		t.Fatal("expected the lookup to be persisted to the cache")
	}
	if cached.Target != first.Target {
		t.Errorf("cached target = %q, want %q", cached.Target, first.Target)
	}

	// A second lookup within the TTL window should be served from cache without needing to
	// re-run the (network) sources — verified indirectly here since Configured stays stable.
	second := LookupHash(context.Background(), httpx.New(), store, "abc123", DefaultTTL)
	if second.FetchedAt != first.FetchedAt {
		t.Error("expected the second lookup within TTL to be served from cache (same FetchedAt)")
	}
}

func TestOsintCacheExpiresAfterTTL(t *testing.T) {
	store, err := cache.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	defer store.Close()
	t.Setenv("VIRUSTOTAL_API_KEY", "")

	first := LookupHash(context.Background(), httpx.New(), store, "cafef00d", time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	second := LookupHash(context.Background(), httpx.New(), store, "cafef00d", time.Millisecond)
	if second.FetchedAt == first.FetchedAt {
		t.Error("expected a fresh lookup after the TTL expired, got the same cached FetchedAt")
	}
}
