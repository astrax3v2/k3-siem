package ocsf

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// jsonObj is our stand-in for the dynamic objects the Node parser navigates freely
// (obj.Event.System.Computer, etc.) — decoded JSON always lands in map[string]any/[]any/
// string/float64/bool/nil in Go, which we walk with the helpers below.
type jsonObj = map[string]any

func tryParseJSON(text string) jsonObj {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil
	}
	var out any
	if err := json.Unmarshal([]byte(trimmed), &out); err != nil {
		return nil
	}
	m, _ := out.(jsonObj)
	return m
}

func asObj(v any) jsonObj {
	m, _ := v.(jsonObj)
	return m
}

// get walks a dotted path of map keys, returning nil if any segment is missing or not an
// object — the Go analogue of JS's optional chaining (`obj?.a?.b`).
func get(obj jsonObj, path ...string) any {
	var cur any = obj
	for _, p := range path {
		m := asObj(cur)
		if m == nil {
			return nil
		}
		cur = m[p]
	}
	return cur
}

// toStr stringifies a decoded-JSON value the way JS's implicit String() coercion would:
// integral floats print without a trailing ".0", everything else uses Go's default formatting.
func toStr(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == math.Trunc(t) && !math.IsInf(t, 0) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return fmt.Sprint(t)
	}
}

func getStr(obj jsonObj, path ...string) string {
	return toStr(get(obj, path...))
}

// getDollar mirrors the `field?.['$'] ?? field` pattern used for XML->JSON attribute values
// (e.g. Windows Event Log's EventID, which can arrive as {"$": "4624"} or plain "4624").
func getDollar(obj jsonObj, key string) string {
	v := obj[key]
	if m, ok := v.(jsonObj); ok {
		return toStr(m["$"])
	}
	return toStr(v)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

var ipRe = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)

func pickIP(text string) string {
	m := ipRe.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

func pickIPs(text string) []string {
	return ipRe.FindAllString(text, -1)
}

var (
	failureRe = regexp.MustCompile(`(?i)fail|failed|deny|denied|drop|dropped|block|blocked|reject|rejected|quarantine|malware|phish|virus|attack`)
	successRe = regexp.MustCompile(`(?i)allow|allowed|accept|accepted|success|succeeded|delivered|connected|permitted`)
)

func detectOutcome(text string, fallback string) string {
	if failureRe.MatchString(text) {
		return "Failure"
	}
	if successRe.MatchString(text) {
		return "Success"
	}
	return fallback
}

var namedSeverity = map[string]string{
	"info": "Info", "informational": "Info", "debug": "Info",
	"notice": "Low", "low": "Low",
	"medium": "Medium", "med": "Medium", "warning": "Medium", "warn": "Medium",
	"high": "High", "error": "High",
	"critical": "Critical", "crit": "Critical", "alert": "Critical", "emergency": "Critical", "emerg": "Critical",
	"fatal": "Fatal",
}

// normalizeSeverity mirrors the Node normalizeSeverity(): named strings map directly, purely
// numeric input (or a numeric-looking string) falls through fixed thresholds, anything else
// returns fallback. Node's dual number/string entry points collapse into one string-typed
// function here since every caller already stringifies via getStr/firstNonEmpty first, and a
// numeric string takes the identical threshold path the number branch would have.
func normalizeSeverity(input string, fallback string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return fallback
	}
	if named, ok := namedSeverity[strings.ToLower(input)]; ok {
		return named
	}
	if n, err := strconv.Atoi(input); err == nil {
		switch {
		case n >= 9:
			return "Critical"
		case n >= 7:
			return "High"
		case n >= 4:
			return "Medium"
		case n >= 1:
			return "Low"
		default:
			return "Info"
		}
	}
	return fallback
}

func ciscoSeverityName(code string) string {
	n, err := strconv.Atoi(strings.TrimSpace(code))
	if err != nil {
		return "Info"
	}
	switch {
	case n <= 2:
		return "Critical"
	case n == 3:
		return "High"
	case n == 4:
		return "Medium"
	case n == 5:
		return "Low"
	default:
		return "Info"
	}
}

func inferIndexName(family string) string {
	switch family {
	case "windows":
		return "windows-security"
	case "linux", "aix":
		return "linux-syslog"
	case "firewall", "waf", "generic_network":
		return "network-flow"
	case "email", "email_security_gateway":
		return "email-security"
	default:
		return "default"
	}
}

// normalizeTimestamp best-effort parses whatever timestamp format a log source used, falling
// back to "now" rather than propagating an invalid/empty timestamp — matches the Node
// normalizeTimestamp() fallback chain (native parse, then "<token> <thisYear> UTC" for
// year-less syslog timestamps, then a yyyy/mm/dd -> yyyy-mm-dd rewrite).
func normalizeTimestamp(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Now().UTC()
	}
	for _, layout := range []string{
		time.RFC3339, time.RFC3339Nano, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05",
		"2006-01-02 15:04:05", "2006/01/02 15:04:05", "Jan 2 15:04:05", "Jan _2 15:04:05",
	} {
		if t, err := time.Parse(layout, value); err == nil {
			if t.Year() == 0 {
				t = t.AddDate(time.Now().UTC().Year(), 0, 0)
			}
			return t.UTC()
		}
	}
	if rewritten := yyyySlashRe.ReplaceAllString(value, "$1-$2-$3"); rewritten != value {
		if t, err := time.Parse("2006-01-02 15:04:05", rewritten); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

var yyyySlashRe = regexp.MustCompile(`^(\d{4})/(\d{2})/(\d{2})`)

// unquote strips one wrapping quote pair, matching the Node `value.replace(/^"(.*)"$/, '$1')`.
func unquote(value string) string {
	if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		return value[1 : len(value)-1]
	}
	return value
}

// splitEscaped splits input on delimiter, honoring backslash-escaping — used for CEF's
// backslash-escaped pipe-delimited header, matching the Node splitEscaped().
func splitEscaped(input string, delimiter byte, limit int) []string {
	var out []string
	var current strings.Builder
	escaped := false
	for i := 0; i < len(input); i++ {
		ch := input[i]
		if escaped {
			current.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == delimiter && (limit == 0 || len(out) < limit-1) {
			out = append(out, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(ch)
	}
	out = append(out, current.String())
	return out
}

// cefRecord is the parsed shape of one CEF ("Common Event Format") line.
type cefRecord struct {
	Version       string
	Vendor        string
	Product       string
	DeviceVersion string
	SignatureID   string
	Name          string
	Severity      string
	Extension     string
	KV            map[string]string
}

var cefExtensionRe = regexp.MustCompile(`([A-Za-z0-9_.-]+)=((?:"[^"]*")|(?:[^\s]+))`)

func parseCEF(text string) *cefRecord {
	if !strings.HasPrefix(text, "CEF:") {
		return nil
	}
	parts := splitEscaped(text, '|', 8)
	if len(parts) < 8 {
		return nil
	}
	kv := map[string]string{}
	ext := parts[7]
	for _, m := range cefExtensionRe.FindAllStringSubmatch(ext, -1) {
		kv[m[1]] = unquote(m[2])
	}
	return &cefRecord{
		Version: parts[0], Vendor: parts[1], Product: parts[2], DeviceVersion: parts[3],
		SignatureID: parts[4], Name: parts[5], Severity: parts[6], Extension: ext, KV: kv,
	}
}

func (c *cefRecord) kv(key string) string {
	if c == nil {
		return ""
	}
	return c.KV[key]
}

var kvPairRe = regexp.MustCompile(`([A-Za-z0-9_.-]+)=((?:"(?:[^"\\]|\\.)*")|(?:[^\s]+))`)

func parseKeyValuePairs(text string) map[string]string {
	kv := map[string]string{}
	for _, m := range kvPairRe.FindAllStringSubmatch(text, -1) {
		kv[m[1]] = unquote(m[2])
	}
	return kv
}

// syslogEnvelope is the outer `<pri>timestamp host program[pid]: message` wrapper most
// syslog-family sources share.
type syslogEnvelope struct {
	TimestampToken string
	Host           string
	Program        string
	ProgramRaw     string
	Message        string
}

var (
	syslogEnvelopeRe = regexp.MustCompile(`^(?:<\d+>)?([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|[0-9T:+.\-Z/ ]+)\s+(\S+)\s+([^:]+):\s*(.*)$`)
	pidSuffixRe      = regexp.MustCompile(`\[\d+\]$`)
)

func parseSyslogEnvelope(text string) *syslogEnvelope {
	m := syslogEnvelopeRe.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	programRaw := strings.TrimSpace(m[3])
	program := pidSuffixRe.ReplaceAllString(programRaw, "")
	return &syslogEnvelope{
		TimestampToken: strings.TrimSpace(m[1]),
		Host:           strings.TrimSpace(m[2]),
		Program:        program,
		ProgramRaw:     programRaw,
		Message:        strings.TrimSpace(m[4]),
	}
}

func (e *syslogEnvelope) host() string {
	if e == nil {
		return ""
	}
	return e.Host
}

func (e *syslogEnvelope) program() string {
	if e == nil {
		return ""
	}
	return e.Program
}

func (e *syslogEnvelope) timestampToken() string {
	if e == nil {
		return ""
	}
	return e.TimestampToken
}
