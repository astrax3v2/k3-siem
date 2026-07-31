// Package ioc defines the shared indicator-of-compromise type used across the cache, feed
// sync, and analyzer packages. It mirrors the shape of the `iocs` table in the existing
// Node backend (backend/src/models/db.js) so results stay comparable across both systems.
package ioc

import (
	"net/netip"
	"strings"
	"time"
)

// Type is one of the indicator kinds the feed parsers and analyzer recognize.
type Type string

const (
	TypeIP     Type = "IP"
	TypeDomain Type = "Domain"
	TypeHash   Type = "Hash"
	TypeURL    Type = "URL"
	TypeEmail  Type = "Email"
)

// Indicator is a single threat-intel entry, keyed by (Type, Value).
type Indicator struct {
	ID          string    `json:"id"`
	Type        Type      `json:"type"`
	Value       string    `json:"value"`
	Confidence  int       `json:"confidence"`
	Severity    string    `json:"severity"`
	Source      string    `json:"source"`
	Description string    `json:"description,omitempty"`
	Hits        int       `json:"hits"`
	Active      bool      `json:"active"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
}

// NormalizeValue matches the Node normalizeIndicator() rule: hashes, domains, and emails are
// lowercased for case-insensitive dedup/matching; IPs and URLs are kept as-is.
func NormalizeValue(t Type, value string) string {
	v := strings.TrimSpace(value)
	switch t {
	case TypeHash, TypeDomain, TypeEmail:
		return strings.ToLower(v)
	default:
		return v
	}
}

// Key returns the dedup/lookup key for a (type, value) pair, matching the Node iocKey()
// convention of joining with a NUL byte so no legitimate indicator value can collide with it.
func Key(t Type, value string) string {
	return string(t) + "\x00" + value
}

// IsCIDR reports whether value looks like a CIDR range (contains a '/'), matching the Node
// `instr(value, '/') > 0` check used to split plain-IP IOCs from range IOCs.
func IsCIDR(value string) bool {
	return strings.Contains(value, "/")
}

// CIDRContains reports whether ip falls within the given CIDR range. Both IPv4 and IPv6 are
// supported natively via net/netip; a family mismatch (e.g. an IPv4 address against an IPv6
// prefix) simply returns false, matching the Node cidrContains() behavior.
func CIDRContains(cidr string, ip string) bool {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return prefix.Contains(addr)
}

// ClampConfidence mirrors Node's Math.max(0, Math.min(100, ...)) confidence clamp, defaulting
// to 50 when the input isn't a valid number.
func ClampConfidence(v int, ok bool) int {
	if !ok {
		return 50
	}
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
