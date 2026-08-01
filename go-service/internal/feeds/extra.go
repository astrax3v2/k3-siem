package feeds

import (
	"context"
	"fmt"
	"net"
	"strings"

	"k3siem/goservice/internal/httpx"
	"k3siem/goservice/internal/ioc"
)

// ExtraRegistry is 10 additional keyless threat-intel feeds found and live-verified
// specifically for this Go service (2026 research pass) — none of these exist in the
// original Node feedSync.js. Each URL/format was confirmed with a real fetch, not just
// documentation, before being wired in here.
//
// Deliberately NOT included, with reasons:
//   - dan.me.uk Tor node list: broader Tor coverage than the official exit list below, but
//     enforces a hard 1-request-per-30-minutes limit per source IP and returns a plaintext
//     "wait 30 minutes" message (not an HTTP error) when exceeded — a real risk of silently
//     ingesting zero IOCs (or worse, a bogus "IP") if two syncs overlap. The official Tor
//     Project list has no such restriction and is authoritative for exit nodes specifically.
//   - Bambenek Consulting C2/DGA feeds: gated behind a commercial license since 2019 (confirmed
//     via a live 403 "PERMISSION DENIED" response) — no longer keyless.
//   - cybercrime-tracker.net, Qihoo 360 Netlab OpenData, montysecurity C2-Tracker: confirmed
//     dead/unreliable/bot-walled via live requests (redirect loops, expired TLS certs, or an
//     explicitly archived upstream repo).
//   - RansomLook / ransomwatch (ransomware leak-site trackers): genuinely valuable for
//     forensics, but their data is victim-name/group metadata, not IP/domain/hash/URL
//     indicators — they don't fit this package's IOC-matching model and would need a
//     different (organization-name matching) analyzer feature, tracked as separate work.
func ExtraRegistry() []*Feed {
	return []*Feed{
		{
			Name: "Tor Bulk Exit List", Source: "Tor Project",
			URL:          "https://check.torproject.org/torbulkexitlist",
			Type:         "TXT",
			IsConfigured: alwaysConfigured,
			Sync:         syncTorExitList,
		},
		{
			Name: "SANS ISC DShield Block List", Source: "SANS ISC/DShield",
			URL:          "https://feeds.dshield.org/block.txt",
			Type:         "TSV",
			IsConfigured: alwaysConfigured,
			Sync:         syncDShield,
		},
		{
			Name: "Team Cymru Fullbogons IPv4", Source: "Team Cymru",
			URL:          "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt",
			Type:         "TXT",
			IsConfigured: alwaysConfigured,
			Sync:         syncCymruBogons,
		},
		{
			Name: "GreenSnow Blocklist", Source: "GreenSnow",
			URL:          "https://blocklist.greensnow.co/greensnow.txt",
			Type:         "TXT",
			IsConfigured: alwaysConfigured,
			Sync:         syncGreenSnow,
		},
		{
			Name: "Emerging Threats Compromised IPs", Source: "Emerging Threats",
			URL:          "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
			Type:         "TXT",
			IsConfigured: alwaysConfigured,
			Sync:         syncEmergingThreats,
		},
		{
			Name: "DigitalSide OSINT IPs", Source: "DigitalSide",
			URL:          "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestips.txt",
			Type:         "TXT",
			IsConfigured: alwaysConfigured,
			Sync:         syncDigitalSideIPs,
		},
		{
			Name: "DigitalSide OSINT URLs", Source: "DigitalSide",
			URL:          "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latesturls.txt",
			Type:         "TXT",
			IsConfigured: alwaysConfigured,
			Sync:         syncDigitalSideURLs,
		},
		{
			Name: "DigitalSide OSINT Domains", Source: "DigitalSide",
			URL:          "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestdomains.txt",
			Type:         "TXT",
			IsConfigured: alwaysConfigured,
			Sync:         syncDigitalSideDomains,
		},
		{
			Name: "botvrij.eu Domain Blocklist", Source: "botvrij.eu",
			URL:          "https://www.botvrij.eu/data/blocklist/blocklist_domain.csv",
			Type:         "CSV",
			IsConfigured: alwaysConfigured,
			Sync:         syncBotvrij,
		},
		{
			Name: "PhishStats Recent", Source: "PhishStats",
			// Anonymous reads are capped at 50/day per the provider's docs — well within a
			// once-per-sync cadence (default every 30 days, or manual).
			URL:          "https://api.phishstats.info/api/phishing?_sort=-id&_size=200",
			Type:         "JSON",
			IsConfigured: alwaysConfigured,
			Sync:         syncPhishStats,
		},
	}
}

func isValidIP(s string) bool { return net.ParseIP(s) != nil }

func syncTorExitList(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	return parseTorExitText(text, f.Source), nil
}

func parseTorExitText(text, source string) []ioc.Indicator {
	var out []ioc.Indicator
	for _, line := range splitLines(text) {
		if strings.HasPrefix(line, "#") || !isValidIP(line) {
			continue
		}
		out = append(out, ioc.Indicator{
			Type: ioc.TypeIP, Value: line, Confidence: 70, Severity: "Medium",
			Source: source, Description: "Tor exit node — anonymized/untrusted traffic source",
		})
	}
	return out
}

func syncDShield(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	return parseDShieldText(text, f.Source), nil
}

// parseDShieldText parses feeds.dshield.org/block.txt's tab-separated rows:
// start_ip \t end_ip \t prefix_len \t attack_count \t org_name \t country \t email
// (confirmed via a live fetch — the org name column itself can contain spaces, hence
// tab-splitting rather than whitespace-splitting).
func parseDShieldText(text, source string) []ioc.Indicator {
	var out []ioc.Indicator
	for _, line := range splitLines(text) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) < 4 {
			continue
		}
		startIP := strings.TrimSpace(cols[0])
		prefix := strings.TrimSpace(cols[2])
		cidr := fmt.Sprintf("%s/%s", startIP, prefix)
		if _, _, cidrErr := net.ParseCIDR(cidr); cidrErr != nil {
			continue
		}
		count := parseIntDefault(strings.TrimSpace(cols[3]), 0)
		confidence := 60 + count/4
		if confidence > 99 {
			confidence = 99
		}
		severity := "High"
		if count >= 300 {
			severity = "Critical"
		}
		org := ""
		if len(cols) > 4 {
			org = strings.TrimSpace(cols[4])
		}
		desc := fmt.Sprintf("DShield top-attacking /%s subnet (%d targets reporting)", prefix, count)
		if org != "" && org != "-" {
			desc += " — " + org
		}
		out = append(out, ioc.Indicator{
			Type: ioc.TypeIP, Value: cidr, Confidence: confidence, Severity: severity,
			Source: source, Description: desc,
		})
	}
	return out
}

func syncCymruBogons(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	return parseCymruBogonsText(text, f.Source), nil
}

func parseCymruBogonsText(text, source string) []ioc.Indicator {
	var out []ioc.Indicator
	for _, line := range splitLines(text) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if _, _, cidrErr := net.ParseCIDR(line); cidrErr != nil {
			continue
		}
		out = append(out, ioc.Indicator{
			Type: ioc.TypeIP, Value: line, Confidence: 90, Severity: "Medium",
			Source: source, Description: "Unallocated/bogon IP space — traffic from here indicates spoofing or misconfiguration",
		})
	}
	return out
}

func syncGreenSnow(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
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
			Type: ioc.TypeIP, Value: line, Confidence: 78, Severity: "High",
			Source: f.Source, Description: "GreenSnow reported brute-force/scan source (SSH, FTP, SMTP, cPanel, ModSecurity)",
		})
	}
	return out, nil
}

func syncEmergingThreats(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
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
			Type: ioc.TypeIP, Value: line, Confidence: 85, Severity: "High",
			Source: f.Source, Description: "Emerging Threats (Proofpoint) known-compromised host",
		})
	}
	return out, nil
}

const digitalSideDesc = "DigitalSide OSINT — malware-analysis-derived indicator (7-day rolling window)"

func syncDigitalSideIPs(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	var out []ioc.Indicator
	for _, line := range splitLines(text) {
		if strings.HasPrefix(line, "#") || !isIPv4(line) {
			continue
		}
		out = append(out, ioc.Indicator{Type: ioc.TypeIP, Value: line, Confidence: 75, Severity: "High", Source: f.Source, Description: digitalSideDesc})
	}
	return out, nil
}

func syncDigitalSideURLs(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	var out []ioc.Indicator
	for _, line := range splitLines(text) {
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
			continue
		}
		out = append(out, ioc.Indicator{Type: ioc.TypeURL, Value: line, Confidence: 75, Severity: "High", Source: f.Source, Description: digitalSideDesc})
	}
	return out, nil
}

func syncDigitalSideDomains(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	var out []ioc.Indicator
	for _, line := range splitLines(text) {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		out = append(out, ioc.Indicator{Type: ioc.TypeDomain, Value: line, Confidence: 75, Severity: "High", Source: f.Source, Description: digitalSideDesc})
	}
	return out, nil
}

func syncBotvrij(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	text, err := client.FetchText(ctx, f.URL, httpx.FetchOptions{})
	if err != nil {
		return nil, err
	}
	return parseBotvrijText(text, f.Source), nil
}

func parseBotvrijText(text, source string) []ioc.Indicator {
	var out []ioc.Indicator
	for _, line := range splitLines(text) {
		if strings.HasPrefix(line, "value,") {
			continue // header row — real data rows are a bare domain per line, no commas
		}
		domain := strings.TrimSpace(strings.Split(line, ",")[0])
		if domain == "" {
			continue
		}
		out = append(out, ioc.Indicator{
			Type: ioc.TypeDomain, Value: domain, Confidence: 70, Severity: "Medium",
			Source: source, Description: "botvrij.eu community threat-intel domain",
		})
	}
	return out
}

// phishStatsRecord is one row of api.phishstats.info's JSON response. Several documented
// fields are omitted here (id, redirect_url, asn, ssl_issuer, ...) since they aren't used for
// indicator construction — decoding is still safe because encoding/json ignores unknown
// fields as well as extra fields not named in this struct.
type phishStatsRecord struct {
	URL         string `json:"url"`
	IP          string `json:"ip"`
	CountryName string `json:"countryname"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
}

func syncPhishStats(ctx context.Context, client *httpx.Client, f *Feed) ([]ioc.Indicator, error) {
	var records []phishStatsRecord
	if err := client.FetchJSON(ctx, f.URL, httpx.FetchOptions{}, &records); err != nil {
		return nil, err
	}
	return buildPhishStatsIndicators(records, f.Source), nil
}

func buildPhishStatsIndicators(records []phishStatsRecord, source string) []ioc.Indicator {
	var out []ioc.Indicator
	for _, rec := range records {
		geo := ""
		if rec.City != "" || rec.CountryName != "" {
			geo = fmt.Sprintf(" (hosted in %s%s%s)", rec.City, sepIfBoth(rec.City, rec.CountryName), rec.CountryName)
		}
		if rec.URL != "" {
			desc := "PhishStats recent phishing URL" + geo
			if rec.ISP != "" {
				desc += ", ISP " + rec.ISP
			}
			out = append(out, ioc.Indicator{Type: ioc.TypeURL, Value: rec.URL, Confidence: 82, Severity: "High", Source: source, Description: desc})
		}
		if rec.IP != "" && isValidIP(rec.IP) {
			out = append(out, ioc.Indicator{
				Type: ioc.TypeIP, Value: rec.IP, Confidence: 60, Severity: "Medium",
				Source: source, Description: "PhishStats — hosts a recently reported phishing URL" + geo,
			})
		}
	}
	return out
}

func sepIfBoth(a, b string) string {
	if a != "" && b != "" {
		return ", "
	}
	return ""
}
