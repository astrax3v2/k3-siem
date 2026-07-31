package cache

import (
	"path/filepath"
	"testing"

	"k3siem/goservice/internal/ioc"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cache.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestUpsertBatchDedup(t *testing.T) {
	store := openTestStore(t)

	indicators := []ioc.Indicator{
		{Type: ioc.TypeIP, Value: "1.2.3.4", Confidence: 80, Severity: "High", Source: "TestFeed"},
	}
	added, err := store.UpsertBatch(indicators)
	if err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}
	if added != 1 {
		t.Fatalf("expected 1 added, got %d", added)
	}

	// Re-inserting the same (type, value) must be a no-op, mirroring the Node upsertIOC
	// skip-if-exists rule.
	added, err = store.UpsertBatch(indicators)
	if err != nil {
		t.Fatalf("UpsertBatch (second): %v", err)
	}
	if added != 0 {
		t.Fatalf("expected 0 added on duplicate insert, got %d", added)
	}

	stats, err := store.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Total != 1 {
		t.Fatalf("expected 1 total IOC, got %d", stats.Total)
	}
}

func TestMatchByTypeValues(t *testing.T) {
	store := openTestStore(t)
	_, err := store.UpsertBatch([]ioc.Indicator{
		{Type: ioc.TypeDomain, Value: "EVIL.example.com", Confidence: 90, Severity: "Critical", Source: "TestFeed"},
	})
	if err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	found, err := store.MatchByTypeValues(ioc.TypeDomain, []string{"evil.example.com", "benign.example.com"})
	if err != nil {
		t.Fatalf("MatchByTypeValues: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 match (case-insensitive), got %d", len(found))
	}
	if found[0].Source != "TestFeed" {
		t.Errorf("unexpected match: %#v", found[0])
	}
}

func TestMatchCIDR(t *testing.T) {
	store := openTestStore(t)
	_, err := store.UpsertBatch([]ioc.Indicator{
		{Type: ioc.TypeIP, Value: "10.0.0.0/8", Confidence: 95, Severity: "Critical", Source: "TestFeed"},
	})
	if err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	found, err := store.MatchCIDR([]string{"192.168.1.1", "10.1.2.3"})
	if err != nil {
		t.Fatalf("MatchCIDR: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 CIDR match, got %d", len(found))
	}
}

func TestIncrementHit(t *testing.T) {
	store := openTestStore(t)
	_, err := store.UpsertBatch([]ioc.Indicator{
		{Type: ioc.TypeHash, Value: "ABCDEF0123456789", Confidence: 80, Severity: "High", Source: "TestFeed"},
	})
	if err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	if err := store.IncrementHit(ioc.TypeHash, "abcdef0123456789"); err != nil {
		t.Fatalf("IncrementHit: %v", err)
	}
	ind, found, err := store.GetIOC(ioc.TypeHash, "abcdef0123456789")
	if err != nil || !found {
		t.Fatalf("GetIOC: found=%v err=%v", found, err)
	}
	if ind.Hits != 1 {
		t.Errorf("expected Hits=1, got %d", ind.Hits)
	}
	if ind.LastSeen.IsZero() {
		t.Error("expected LastSeen to be set")
	}
}

func TestFeedMetaRoundTrip(t *testing.T) {
	store := openTestStore(t)
	meta := FeedMeta{Name: "Test Feed", URL: "https://example.com", Type: "TXT", Status: "active", IOCCount: 5}
	if err := store.SetFeedMeta(meta); err != nil {
		t.Fatalf("SetFeedMeta: %v", err)
	}
	got, found, err := store.GetFeedMeta("Test Feed")
	if err != nil || !found {
		t.Fatalf("GetFeedMeta: found=%v err=%v", found, err)
	}
	if got.IOCCount != 5 || got.Status != "active" {
		t.Errorf("unexpected meta: %#v", got)
	}

	list, err := store.ListFeedMeta()
	if err != nil {
		t.Fatalf("ListFeedMeta: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 feed in list, got %d", len(list))
	}
}
