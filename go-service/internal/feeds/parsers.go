package feeds

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
)

// parseIntDefault parses s as an int, falling back to def on any error — matches Node's
// `parseInt(x, 10) || fallback` idiom used e.g. for ThreatFox's confidence column.
func parseIntDefault(s string, def int) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return v
}

// splitLines mirrors the Node splitLines(): normalize CRLF, split, trim, drop blanks.
func splitLines(text string) []string {
	text = strings.ReplaceAll(text, "\r", "\n")
	rawLines := strings.Split(text, "\n")
	out := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// parseCSVLine is a hand-rolled quoted-CSV splitter for a single line, matching the Node
// parseCsvLine() used for feeds that aren't strictly RFC 4180 (embedded commas in quoted
// fields, doubled-quote escaping).
func parseCSVLine(line string) []string {
	var out []string
	var current strings.Builder
	inQuotes := false
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		ch := runes[i]
		if ch == '"' {
			if inQuotes && i+1 < len(runes) && runes[i+1] == '"' {
				current.WriteRune('"')
				i++
			} else {
				inQuotes = !inQuotes
			}
			continue
		}
		if ch == ',' && !inQuotes {
			out = append(out, strings.TrimSpace(current.String()))
			current.Reset()
			continue
		}
		current.WriteRune(ch)
	}
	out = append(out, strings.TrimSpace(current.String()))
	// Strip only a single wrapping quote pair (first char and last char both '"'), matching
	// the Node `part.replace(/^"(.*)"$/, '$1')` — NOT a general "trim every quote rune" strip,
	// which would also eat quotes embedded via the doubled-quote escaping above.
	for i, part := range out {
		if len(part) >= 2 && strings.HasPrefix(part, `"`) && strings.HasSuffix(part, `"`) {
			part = part[1 : len(part)-1]
		}
		out[i] = strings.TrimSpace(part)
	}
	return out
}

// spamhausRow is one entry from a Spamhaus DROP feed, either a JSON array or NDJSON-of-objects
// (both forms are served depending on the endpoint), matching the Node parseSpamhausLines().
type spamhausRow struct {
	CIDR  string `json:"cidr"`
	SBLID string `json:"sblid"`
}

func parseSpamhausLines(text string) []spamhausRow {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var rows []spamhausRow
		if err := json.Unmarshal([]byte(trimmed), &rows); err != nil {
			return nil
		}
		out := rows[:0]
		for _, r := range rows {
			if r.CIDR != "" {
				out = append(out, r)
			}
		}
		return out
	}
	var out []spamhausRow
	for _, line := range splitLines(trimmed) {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var row spamhausRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		if row.CIDR != "" {
			out = append(out, row)
		}
	}
	return out
}

// isIPv4 reports whether s parses as a dotted-quad IPv4 address, matching Node's
// `net.isIP(token) === 4` checks used by several TXT-list feeds to skip comments/garbage lines.
func isIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && !strings.Contains(s, ":")
}

// otxTypeMap mirrors the Node OTX_TYPE_MAP: OTX pulse indicator types we recognize, mapped to
// our ioc.Type constants. Types not present here are skipped (e.g. CVE, FilePath, Mutex).
var otxTypeMap = map[string]string{
	"IPv4":            "IP",
	"IPv6":            "IP",
	"domain":          "Domain",
	"hostname":        "Domain",
	"URL":             "URL",
	"FileHash-MD5":    "Hash",
	"FileHash-SHA1":   "Hash",
	"FileHash-SHA256": "Hash",
	"email":           "Email",
}
