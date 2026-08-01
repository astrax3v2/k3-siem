package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"k3siem/goservice/internal/cache"
	"k3siem/goservice/internal/ioc"
	"k3siem/goservice/internal/ocsf"
)

func TestExtractCandidates(t *testing.T) {
	line := `login from 1.2.3.4 hash=abcd1234abcd1234abcd1234abcd1234 url=https://evil.example.com/x user=bob@example.com domain=example.com again 1.2.3.4`
	c := extractCandidates(ocsf.Record{}, line)

	if len(c.IP) != 1 || c.IP[0] != "1.2.3.4" {
		t.Errorf("expected deduped single IP, got %#v", c.IP)
	}
	if len(c.Hash) != 1 {
		t.Errorf("expected 1 hash candidate, got %#v", c.Hash)
	}
	if len(c.URL) != 1 {
		t.Errorf("expected 1 URL candidate, got %#v", c.URL)
	}
	if len(c.Email) != 1 || c.Email[0] != "bob@example.com" {
		t.Errorf("expected 1 email candidate, got %#v", c.Email)
	}
	// example.com appears both as a bare domain token and as the email's domain part; the
	// email match should suppress the domain match for that same value, matching the Node
	// `if (!out.Email.has(m)) out.Domain.add(m)` rule.
	for _, d := range c.Domain {
		if d == "bob@example.com" {
			t.Errorf("email value leaked into domain candidates: %#v", c.Domain)
		}
	}
}

func TestAnalyzeEndToEnd(t *testing.T) {
	store, err := cache.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	defer store.Close()

	if _, err := store.UpsertBatch([]ioc.Indicator{
		{Type: ioc.TypeIP, Value: "203.0.113.9", Confidence: 90, Severity: "Critical", Source: "TestFeed"},
		{Type: ioc.TypeIP, Value: "198.51.100.0/24", Confidence: 95, Severity: "Critical", Source: "TestFeed"},
	}); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	logPath := filepath.Join(t.TempDir(), "sample.log")
	content := "2026-01-01 clean line, nothing to see\n" +
		"2026-01-01 connection from 203.0.113.9 refused\n" +
		"2026-01-01 connection from 198.51.100.42 refused\n" +
		"2026-01-01 another clean line\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := Analyze(context.Background(), store, logPath)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if result.LinesScanned != 4 {
		t.Errorf("expected 4 lines scanned, got %d", result.LinesScanned)
	}
	if len(result.Hits) != 2 {
		t.Fatalf("expected 2 hits (1 exact + 1 CIDR), got %d: %#v", len(result.Hits), result.Hits)
	}
	if result.Hits[0].LineNumber != 2 || result.Hits[0].MatchType != "exact" {
		t.Errorf("unexpected first hit: %#v", result.Hits[0])
	}
	if result.Hits[1].LineNumber != 3 || result.Hits[1].MatchType != "cidr" {
		t.Errorf("unexpected second hit: %#v", result.Hits[1])
	}
	if result.HitsBySeverity["Critical"] != 2 {
		t.Errorf("expected 2 Critical hits, got %d", result.HitsBySeverity["Critical"])
	}

	// Matching should have bumped each indicator's hit counter in the cache.
	ind, found, err := store.GetIOC(ioc.TypeIP, "203.0.113.9")
	if err != nil || !found {
		t.Fatalf("GetIOC: found=%v err=%v", found, err)
	}
	if ind.Hits != 1 {
		t.Errorf("expected Hits=1 after analysis, got %d", ind.Hits)
	}
}

func TestAnalyzeSingleImage(t *testing.T) {
	store, err := cache.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	defer store.Close()

	// Not a real JPEG — verifies Analyze() routes by extension to the image path (rather than
	// erroring as "not a log file") and that a corrupt image degrades to a Warning instead of
	// failing the whole run, matching imagemeta.Extract's own panic-recovery contract.
	imgPath := filepath.Join(t.TempDir(), "photo.jpg")
	if err := os.WriteFile(imgPath, []byte("not a real jpeg"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := Analyze(context.Background(), store, imgPath)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(result.Images) != 1 {
		t.Fatalf("expected 1 image result, got %d", len(result.Images))
	}
	if result.Images[0].Path != imgPath {
		t.Errorf("expected image path %q, got %q", imgPath, result.Images[0].Path)
	}
	if len(result.Hits) != 0 || result.LinesScanned != 0 {
		t.Errorf("expected no log-side fields populated for a bare image input, got hits=%d lines=%d", len(result.Hits), result.LinesScanned)
	}
}

func TestAnalyzeDirectoryMixedEvidence(t *testing.T) {
	store, err := cache.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	defer store.Close()

	if _, err := store.UpsertBatch([]ioc.Indicator{
		{Type: ioc.TypeIP, Value: "203.0.113.9", Confidence: 90, Severity: "Critical", Source: "TestFeed"},
	}); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	dir := t.TempDir()
	logA := filepath.Join(dir, "a.log")
	logB := filepath.Join(dir, "b.log")
	imgPath := filepath.Join(dir, "evidence.png")

	if err := os.WriteFile(logA, []byte("connection from 203.0.113.9 refused\nclean line\n"), 0o644); err != nil {
		t.Fatalf("WriteFile a.log: %v", err)
	}
	if err := os.WriteFile(logB, []byte("another clean line\nyet another\n"), 0o644); err != nil {
		t.Fatalf("WriteFile b.log: %v", err)
	}
	if err := os.WriteFile(imgPath, []byte("not a real png"), 0o644); err != nil {
		t.Fatalf("WriteFile evidence.png: %v", err)
	}

	result, err := Analyze(context.Background(), store, dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if result.FilesScanned != 2 {
		t.Errorf("expected 2 log files scanned, got %d", result.FilesScanned)
	}
	if result.LinesScanned != 4 {
		t.Errorf("expected 4 total lines across both logs, got %d", result.LinesScanned)
	}
	if len(result.Images) != 1 {
		t.Fatalf("expected 1 image found in the directory, got %d", len(result.Images))
	}
	if len(result.Hits) != 1 {
		t.Fatalf("expected 1 hit from a.log, got %d: %#v", len(result.Hits), result.Hits)
	}
	if result.Hits[0].SourceFile != logA {
		t.Errorf("expected hit's SourceFile to be %q, got %q", logA, result.Hits[0].SourceFile)
	}
}

func TestAnalyzeDirectorySkipsBinaryNonImageFiles(t *testing.T) {
	store, err := cache.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	defer store.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "a.log")
	binPath := filepath.Join(dir, "evidence.bin")

	if err := os.WriteFile(logPath, []byte("clean line\n"), 0o644); err != nil {
		t.Fatalf("WriteFile a.log: %v", err)
	}
	// A NUL byte marks this as binary content (e.g. a database file or executable that happens
	// to sit in an evidence directory alongside real logs) — it must be skipped rather than
	// scanned as text, matching how git and other tools distinguish binary from text content.
	if err := os.WriteFile(binPath, []byte{0x00, 0x01, 0x02, 'x', 'x', 'x'}, 0o644); err != nil {
		t.Fatalf("WriteFile evidence.bin: %v", err)
	}

	result, err := Analyze(context.Background(), store, dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if result.FilesScanned != 1 {
		t.Errorf("expected only the text log to be counted as scanned, got %d", result.FilesScanned)
	}
	if result.LinesScanned != 1 {
		t.Errorf("expected 1 line scanned (binary file skipped), got %d", result.LinesScanned)
	}
}
