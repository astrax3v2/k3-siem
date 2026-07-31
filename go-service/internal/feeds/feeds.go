// Package feeds ports the 13 threat-intel feed definitions and parsers from
// backend/src/services/connectors/feedSync.js so the Go cache stays directly comparable to
// what the Node backend produces: same feed names/sources/URLs, same confidence/severity
// rules per feed.
package feeds

import (
	"context"
	"os"

	"k3siem/goservice/internal/httpx"
	"k3siem/goservice/internal/ioc"
)

// SyncFunc fetches and parses one feed's raw data into indicators. Storage (dedup + persist)
// happens in the orchestrator, not here — these functions are pure parsing plus one network
// fetch, easy to unit test independently of the cache.
type SyncFunc func(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error)

// Feed is one threat-intel source: where to fetch it, its wire format, whether it needs an
// API key, and how to parse it.
type Feed struct {
	Name           string
	Source         string
	URL            string
	Type           string // REST | TXT | JSON | NDJSON | CSV
	RequiresConfig bool
	IsConfigured   func() bool
	Sync           SyncFunc
}

func alwaysConfigured() bool    { return true }
func abuseIPDBConfigured() bool { return os.Getenv("ABUSEIPDB_API_KEY") != "" }
func otxConfigured() bool       { return os.Getenv("OTX_API_KEY") != "" }

// Registry returns the 13 feed definitions in the same order/shape as the Node FEEDS array.
func Registry() []*Feed {
	return []*Feed{
		{
			Name: "AbuseIPDB", Source: "AbuseIPDB",
			URL:            "https://api.abuseipdb.com/api/v2/blacklist?limit=100&confidenceMinimum=75",
			Type:           "REST",
			RequiresConfig: true,
			IsConfigured:   abuseIPDBConfigured,
			Sync:           syncAbuseIPDB,
		},
		{
			Name: "OTX AlienVault", Source: "OTX AlienVault",
			// limit=1 on purpose: on accounts with very large subscribed pulses, even one
			// pulse's embedded indicator list can be 10+ MB — matches the Node comment.
			URL:            "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=1",
			Type:           "REST",
			RequiresConfig: true,
			IsConfigured:   otxConfigured,
			Sync:           syncOTX,
		},
		{
			Name: "OpenPhish Community", Source: "OpenPhish",
			URL:          "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
			Type:         "TXT",
			IsConfigured: alwaysConfigured,
			Sync:         syncOpenPhish,
		},
		{
			Name: "PhishTank Verified Online", Source: "PhishTank",
			URL:          "http://data.phishtank.com/data/online-valid.json",
			Type:         "JSON",
			IsConfigured: alwaysConfigured,
			Sync:         syncPhishTank,
		},
		{
			Name: "Spamhaus DROP IPv4", Source: "Spamhaus DROP IPv4",
			URL:          "https://www.spamhaus.org/drop/drop_v4.json",
			Type:         "NDJSON",
			IsConfigured: alwaysConfigured,
			Sync:         syncSpamhausDrop,
		},
		{
			Name: "Spamhaus DROP IPv6", Source: "Spamhaus DROP IPv6",
			URL:          "https://www.spamhaus.org/drop/drop_v6.json",
			Type:         "NDJSON",
			IsConfigured: alwaysConfigured,
			Sync:         syncSpamhausDrop,
		},
		{
			Name: "Feodo Tracker Recommended", Source: "Feodo Tracker",
			URL:          "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
			Type:         "TXT",
			IsConfigured: alwaysConfigured,
			Sync:         syncFeodoTracker,
		},
		{
			Name: "SSLBL JA3", Source: "SSLBL JA3",
			URL:          "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
			Type:         "CSV",
			IsConfigured: alwaysConfigured,
			Sync:         syncSslblJa3,
		},
		{
			Name: "URLhaus Recent", Source: "URLhaus",
			URL:          "https://urlhaus.abuse.ch/downloads/csv_recent/",
			Type:         "CSV",
			IsConfigured: alwaysConfigured,
			Sync:         syncUrlhaus,
		},
		{
			Name: "ThreatFox Recent IOCs", Source: "ThreatFox",
			URL:          "https://threatfox.abuse.ch/export/csv/recent/",
			Type:         "CSV",
			IsConfigured: alwaysConfigured,
			Sync:         syncThreatFox,
		},
		{
			Name: "MalwareBazaar Recent Samples", Source: "MalwareBazaar",
			URL:          "https://bazaar.abuse.ch/export/txt/sha256/recent/",
			Type:         "TXT",
			IsConfigured: alwaysConfigured,
			Sync:         syncMalwareBazaar,
		},
		{
			Name: "Blocklist.de Attackers", Source: "Blocklist.de",
			URL:          "https://lists.blocklist.de/lists/all.txt",
			Type:         "TXT",
			IsConfigured: alwaysConfigured,
			Sync:         syncBlocklistDe,
		},
		{
			Name: "CINS Army List", Source: "CINS Army",
			URL:          "https://cinsscore.com/list/ci-badguys.txt",
			Type:         "TXT",
			IsConfigured: alwaysConfigured,
			Sync:         syncCinsArmy,
		},
	}
}
