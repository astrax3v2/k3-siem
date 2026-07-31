package feeds

import (
	"reflect"
	"testing"
)

func TestSplitLines(t *testing.T) {
	got := splitLines("  a  \r\n\r\nb\nc  \n\n")
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitLines = %#v, want %#v", got, want)
	}
}

func TestParseCSVLine(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`a,b,c`, []string{"a", "b", "c"}},
		{`"a,b",c`, []string{"a,b", "c"}},
		{`"say ""hi""",c`, []string{`say "hi"`, "c"}},
		{`a, b , c`, []string{"a", "b", "c"}},
	}
	for _, c := range cases {
		got := parseCSVLine(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseCSVLine(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

func TestParseSpamhausLinesJSONArray(t *testing.T) {
	rows := parseSpamhausLines(`[{"cidr":"1.2.3.0/24","sblid":"SBL1"},{"cidr":"5.6.7.0/24"}]`)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	if rows[0].CIDR != "1.2.3.0/24" || rows[0].SBLID != "SBL1" {
		t.Errorf("unexpected first row: %#v", rows[0])
	}
	if rows[1].SBLID != "" {
		t.Errorf("expected empty sblid, got %q", rows[1].SBLID)
	}
}

func TestParseSpamhausLinesNDJSON(t *testing.T) {
	text := "{\"cidr\":\"1.2.3.0/24\",\"sblid\":\"SBL1\"}\n{\"cidr\":\"5.6.7.0/24\"}\nnot json\n"
	rows := parseSpamhausLines(text)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d: %#v", len(rows), rows)
	}
}

func TestIsIPv4(t *testing.T) {
	if !isIPv4("192.168.1.1") {
		t.Error("expected 192.168.1.1 to be IPv4")
	}
	if isIPv4("2001:db8::1") {
		t.Error("expected an IPv6 address not to be treated as IPv4")
	}
	if isIPv4("not-an-ip") {
		t.Error("expected garbage input to be rejected")
	}
}

func TestParseIntDefault(t *testing.T) {
	if got := parseIntDefault("42", 0); got != 42 {
		t.Errorf("parseIntDefault(42) = %d", got)
	}
	if got := parseIntDefault("nope", 75); got != 75 {
		t.Errorf("parseIntDefault fallback = %d, want 75", got)
	}
}
