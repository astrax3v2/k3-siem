package feeds

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"k3siem/goservice/internal/cache"
	"k3siem/goservice/internal/httpx"
	"k3siem/goservice/internal/ioc"
)

const cooldownDuration = 20 * time.Minute

var (
	ja3Re    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	sha256Re = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

func syncAbuseIPDB(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	var data struct {
		Data []struct {
			IPAddress            string `json:"ipAddress"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	err := client.FetchJSON(ctx, f.URL, httpx.FetchOptions{
		Headers: map[string]string{"Key": os.Getenv("ABUSEIPDB_API_KEY"), "Accept": "application/json"},
	}, &data)
	if err != nil {
		return nil, err
	}
	out := make([]ioc.Indicator, 0, len(data.Data))
	for _, entry := range data.Data {
		severity := "High"
		if entry.AbuseConfidenceScore >= 90 {
			severity = "Critical"
		}
		out = append(out, ioc.Indicator{
			Type: ioc.TypeIP, Value: entry.IPAddress, Confidence: entry.AbuseConfidenceScore,
			Severity: severity, Source: f.Source,
			Description: fmt.Sprintf("Abuse confidence %d%%", entry.AbuseConfidenceScore),
		})
	}
	return out, nil
}

func syncOTX(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	var data struct {
		Results []struct {
			Name       string `json:"name"`
			Indicators []struct {
				Type      string `json:"type"`
				Indicator string `json:"indicator"`
			} `json:"indicators"`
		} `json:"results"`
	}
	// Large accounts can still take a while to serve even a single pulse since each embeds
	// its full indicator list — matches the Node comment (observed up to ~36s for 10MB).
	err := client.FetchJSON(ctx, f.URL, httpx.FetchOptions{
		Headers:   map[string]string{"X-OTX-API-KEY": os.Getenv("OTX_API_KEY")},
		TimeoutMs: 120000,
	}, &data)
	if err != nil {
		return nil, err
	}
	var out []ioc.Indicator
	for _, pulse := range data.Results {
		for _, indicator := range pulse.Indicators {
			t, ok := otxTypeMap[indicator.Type]
			if !ok {
				continue
			}
			out = append(out, ioc.Indicator{
				Type: ioc.Type(t), Value: indicator.Indicator, Confidence: 70,
				Severity: "High", Source: f.Source, Description: pulse.Name,
			})
		}
	}
	return out, nil
}

func syncOpenPhish(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	var out []ioc.Indicator
	for _, token := range strings.Fields(text) {
		lower := strings.ToLower(token)
		if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
			continue
		}
		out = append(out, ioc.Indicator{
			Type: ioc.TypeURL, Value: token, Confidence: 88, Severity: "High",
			Source: f.Source, Description: "OpenPhish community phishing URL",
		})
	}
	return out, nil
}

func syncPhishTank(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	appKey := os.Getenv("PHISHTANK_APP_KEY")
	var urls []string
	if appKey != "" {
		urls = []string{
			fmt.Sprintf("https://data.phishtank.com/data/%s/online-valid.json", appKey),
			fmt.Sprintf("http://data.phishtank.com/data/%s/online-valid.json", appKey),
		}
	} else {
		urls = []string{"https://data.phishtank.com/data/online-valid.json", f.URL}
	}

	var entries []struct {
		URL    string `json:"url"`
		Target string `json:"target"`
	}
	var lastErr error
	fetched := false
	for _, u := range urls {
		err := client.FetchJSON(ctx, u, httpx.FetchOptions{
			TimeoutMs: 60000,
			Headers:   map[string]string{"User-Agent": "k3-siem-analyzer-go/1.0"},
		}, &entries)
		if err == nil {
			fetched = true
			break
		}
		lastErr = err
	}
	if !fetched {
		if lastErr == nil {
			lastErr = fmt.Errorf("unable to fetch PhishTank feed")
		}
		return nil, lastErr
	}

	out := make([]ioc.Indicator, 0, len(entries))
	for _, entry := range entries {
		if entry.URL == "" {
			continue
		}
		detail := "Verified online phishing URL"
		if entry.Target != "" {
			detail = fmt.Sprintf("Verified phishing URL targeting %s", entry.Target)
		}
		out = append(out, ioc.Indicator{
			Type: ioc.TypeURL, Value: entry.URL, Confidence: 90, Severity: "High",
			Source: f.Source, Description: detail,
		})
	}
	return out, nil
}

func syncSpamhausDrop(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	rows := parseSpamhausLines(text)
	out := make([]ioc.Indicator, 0, len(rows))
	for _, row := range rows {
		description := "Spamhaus DROP netblock"
		if row.SBLID != "" {
			description = fmt.Sprintf("Spamhaus DROP %s", row.SBLID)
		}
		out = append(out, ioc.Indicator{
			Type: ioc.TypeIP, Value: row.CIDR, Confidence: 95, Severity: "Critical",
			Source: f.Source, Description: description,
		})
	}
	return out, nil
}

func syncFeodoTracker(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	var out []ioc.Indicator
	for _, token := range strings.Fields(text) {
		if !isIPv4(token) {
			continue
		}
		out = append(out, ioc.Indicator{
			Type: ioc.TypeIP, Value: token, Confidence: 92, Severity: "Critical",
			Source: f.Source, Description: "Feodo Tracker active/recent botnet C2",
		})
	}
	return out, nil
}

func syncSslblJa3(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	var out []ioc.Indicator
	for _, line := range splitLines(text) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		cols := parseCSVLine(line)
		fingerprint := ""
		for _, c := range cols {
			if ja3Re.MatchString(c) {
				fingerprint = c
				break
			}
		}
		if fingerprint == "" {
			continue
		}
		reason := "Malicious JA3 fingerprint"
		if len(cols) > 0 && cols[len(cols)-1] != "" {
			reason = cols[len(cols)-1]
		}
		out = append(out, ioc.Indicator{
			Type: ioc.TypeHash, Value: fingerprint, Confidence: 86, Severity: "High",
			Source: f.Source, Description: fmt.Sprintf("SSLBL JA3 %s", reason),
		})
	}
	return out, nil
}

func syncUrlhaus(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	var out []ioc.Indicator
	for _, line := range splitLines(text) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		cols := parseCSVLine(line)
		if len(cols) < 3 || cols[2] == "" {
			continue
		}
		threat := "malware_download"
		if len(cols) > 5 && cols[5] != "" {
			threat = cols[5]
		}
		out = append(out, ioc.Indicator{
			Type: ioc.TypeURL, Value: cols[2], Confidence: 85, Severity: "High",
			Source: f.Source, Description: fmt.Sprintf("URLhaus %s", threat),
		})
	}
	return out, nil
}

func syncThreatFox(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	var out []ioc.Indicator
	for _, line := range splitLines(text) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		cols := parseCSVLine(line)
		if len(cols) < 4 {
			continue
		}
		iocType := strings.ToLower(cols[3])
		rawValue := cols[2]
		if rawValue == "" {
			continue
		}
		var t ioc.Type
		value := rawValue
		switch {
		case strings.HasPrefix(iocType, "ip"):
			t = ioc.TypeIP
			value = strings.SplitN(rawValue, ":", 2)[0]
		case iocType == "domain":
			t = ioc.TypeDomain
		case iocType == "url":
			t = ioc.TypeURL
		case strings.Contains(iocType, "hash"):
			t = ioc.TypeHash
		default:
			continue
		}
		confidence := 75
		if len(cols) > 8 {
			confidence = parseIntDefault(cols[8], 75)
		}
		severity := "High"
		if confidence >= 80 {
			severity = "Critical"
		}
		threatType := "threat"
		if len(cols) > 4 && cols[4] != "" {
			threatType = cols[4]
		}
		malware := ""
		if len(cols) > 7 && cols[7] != "" {
			malware = cols[7]
		} else if len(cols) > 6 && cols[6] != "" {
			malware = cols[6]
		}
		description := fmt.Sprintf("ThreatFox %s", threatType)
		if malware != "" {
			description += " — " + malware
		}
		out = append(out, ioc.Indicator{
			Type: t, Value: value, Confidence: confidence, Severity: severity,
			Source: f.Source, Description: description,
		})
	}
	return out, nil
}

func syncMalwareBazaar(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	var out []ioc.Indicator
	for _, rawLine := range splitLines(text) {
		if strings.HasPrefix(rawLine, "#") {
			continue
		}
		hash := strings.TrimSpace(strings.Trim(rawLine, `"`))
		if !sha256Re.MatchString(hash) {
			continue
		}
		out = append(out, ioc.Indicator{
			Type: ioc.TypeHash, Value: hash, Confidence: 85, Severity: "High",
			Source: f.Source, Description: "MalwareBazaar recent malware sample (SHA256)",
		})
	}
	return out, nil
}

func syncBlocklistDe(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	var out []ioc.Indicator
	for _, line := range splitLines(text) {
		if strings.HasPrefix(line, "#") || !isIPv4(line) {
			continue
		}
		out = append(out, ioc.Indicator{
			Type: ioc.TypeIP, Value: line, Confidence: 75, Severity: "Medium",
			Source: f.Source, Description: "Blocklist.de reported attack source",
		})
	}
	return out, nil
}

func syncCinsArmy(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	var out []ioc.Indicator
	for _, line := range splitLines(text) {
		if strings.HasPrefix(line, "#") || !isIPv4(line) {
			continue
		}
		out = append(out, ioc.Indicator{
			Type: ioc.TypeIP, Value: line, Confidence: 80, Severity: "High",
			Source: f.Source, Description: "CINS Army flagged attacker IP",
		})
	}
	return out, nil
}

// SyncResult is one feed's outcome from a sync pass.
type SyncResult struct {
	Name   string `json:"name"`
	Status string `json:"status"` // active | error | requires_config
	Added  int    `json:"added"`
	Total  int    `json:"total"`
	Error  string `json:"error,omitempty"`
}

// SyncSummary aggregates every feed's outcome, matching the shape of Node's runOnce() return
// value so CLI/HTTP consumers see a familiar totals block.
type SyncSummary struct {
	StartedAt time.Time    `json:"started_at"`
	Feeds     []SyncResult `json:"feeds"`
	Totals    struct {
		Feeds           int `json:"feeds"`
		Active          int `json:"active"`
		Errors          int `json:"errors"`
		WaitingOnConfig int `json:"waiting_on_config"`
		Added           int `json:"added"`
	} `json:"totals"`
}

// SyncAll runs every registered feed concurrently, bounded to max(4, NumCPU) simultaneous
// fetches so one slow/rate-limited source never blocks the rest — the Go analogue of the
// Node Promise.allSettled fan-out in runOnce(). force bypasses any persisted 429 cooldown.
func SyncAll(ctx context.Context, store *cache.Store, client *httpx.Client, force bool) (SyncSummary, error) {
	registry := Registry()
	results := make([]SyncResult, len(registry))

	limit := runtime.NumCPU()
	if limit < 4 {
		limit = 4
	}
	var g errgroup.Group
	g.SetLimit(limit)
	var mu sync.Mutex

	for i, feed := range registry {
		i, feed := i, feed
		g.Go(func() error {
			result := syncOne(ctx, store, client, feed, force)
			mu.Lock()
			results[i] = result
			mu.Unlock()
			return nil // never propagate — each feed's outcome is captured in `results`,
			// not in errgroup's aggregated error, so one failure never cancels the rest.
		})
	}
	_ = g.Wait()

	// Refresh each feed's cached IOCCount from the final store contents, regardless of this
	// run's outcome — matches Node's markFeedError() also reporting sourceCounts on failure.
	if stats, err := store.Stats(); err == nil {
		for i, feed := range registry {
			results[i].Total = stats.BySource[feed.Source]
			if meta, ok, _ := store.GetFeedMeta(feed.Name); ok {
				meta.IOCCount = stats.BySource[feed.Source]
				_ = store.SetFeedMeta(meta)
			}
		}
	}

	summary := SyncSummary{StartedAt: time.Now().UTC(), Feeds: results}
	for _, r := range results {
		summary.Totals.Feeds++
		switch r.Status {
		case "active":
			summary.Totals.Active++
		case "error":
			summary.Totals.Errors++
		case "requires_config":
			summary.Totals.WaitingOnConfig++
		}
		summary.Totals.Added += r.Added
	}
	return summary, nil
}

func syncOne(ctx context.Context, store *cache.Store, client *httpx.Client, feed *Feed, force bool) SyncResult {
	if feed.RequiresConfig && !feed.IsConfigured() {
		_ = store.SetFeedMeta(cache.FeedMeta{Name: feed.Name, URL: feed.URL, Type: feed.Type, Status: "requires_config"})
		return SyncResult{Name: feed.Name, Status: "requires_config", Error: "feed requires API credentials"}
	}

	meta, _, _ := store.GetFeedMeta(feed.Name)
	if !force && !meta.CooldownUntil.IsZero() && time.Now().Before(meta.CooldownUntil) {
		return SyncResult{
			Name: feed.Name, Status: "error", Total: meta.IOCCount,
			Error: fmt.Sprintf("rate limited — retrying after %s", meta.CooldownUntil.Format(time.Kitchen)),
		}
	}

	indicators, err := feed.Sync(ctx, client, feed)
	if err != nil {
		cooldown := meta.CooldownUntil
		if strings.Contains(err.Error(), "HTTP 429") {
			cooldown = time.Now().Add(cooldownDuration)
		}
		_ = store.SetFeedMeta(cache.FeedMeta{
			Name: feed.Name, URL: feed.URL, Type: feed.Type, Status: "error",
			LastError: err.Error(), CooldownUntil: cooldown, IOCCount: meta.IOCCount,
		})
		return SyncResult{Name: feed.Name, Status: "error", Total: meta.IOCCount, Error: err.Error()}
	}

	added, upsertErr := store.UpsertBatch(indicators)
	if upsertErr != nil {
		_ = store.SetFeedMeta(cache.FeedMeta{Name: feed.Name, URL: feed.URL, Type: feed.Type, Status: "error", LastError: upsertErr.Error()})
		return SyncResult{Name: feed.Name, Status: "error", Error: upsertErr.Error()}
	}

	_ = store.SetFeedMeta(cache.FeedMeta{
		Name: feed.Name, URL: feed.URL, Type: feed.Type, Status: "active", LastSync: time.Now().UTC(),
	})
	return SyncResult{Name: feed.Name, Status: "active", Added: added}
}
