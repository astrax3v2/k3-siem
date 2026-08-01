package feeds

import (
	"testing"

	"k3siem/goservice/internal/ioc"
)

func TestExtraRegistryCount(t *testing.T) {
	if got := len(ExtraRegistry()); got != 10 {
		t.Fatalf("expected 10 extra feeds, got %d", got)
	}
}

func TestParseDShieldTextRealFormat(t *testing.T) {
	// Row shape confirmed via a live fetch of feeds.dshield.org/block.txt:
	// start_ip \t end_ip \t prefix_len \t attack_count \t org_name \t country \t email
	text := "#\n# comment line\n69.5.169.0\t69.5.169.255\t24\t348\tOMNIS\tUS\tabuse@omnis.com\n66.132.186.0\t66.132.186.255\t24\t2\t-\t-\t-\n"
	out := parseDShieldText(text, "SANS ISC/DShield")
	if len(out) != 2 {
		t.Fatalf("expected 2 parsed rows, got %d: %#v", len(out), out)
	}
	if out[0].Value != "69.5.169.0/24" {
		t.Errorf("expected CIDR 69.5.169.0/24, got %q", out[0].Value)
	}
	if out[0].Severity != "Critical" {
		t.Errorf("expected Critical severity for count=348, got %s", out[0].Severity)
	}
	if out[1].Severity != "High" {
		t.Errorf("expected High severity for count=2, got %s", out[1].Severity)
	}
}

func TestParseCymruBogonsTextSkipsCommentsAndInvalid(t *testing.T) {
	text := "# last updated 123\n# comment\n0.0.0.0/8\n10.0.0.0/8\nnot-a-cidr\n"
	out := parseCymruBogonsText(text, "Team Cymru")
	if len(out) != 2 {
		t.Fatalf("expected 2 valid CIDRs, got %d: %#v", len(out), out)
	}
	if out[0].Type != ioc.TypeIP || out[0].Value != "0.0.0.0/8" {
		t.Errorf("unexpected first entry: %#v", out[0])
	}
}

func TestParseBotvrijTextSkipsHeaderRow(t *testing.T) {
	text := "value,decay_sore,value_type,event_id,event_info\nevil.example.com\nbad.example.org\n"
	out := parseBotvrijText(text, "botvrij.eu")
	if len(out) != 2 {
		t.Fatalf("expected 2 domains, got %d: %#v", len(out), out)
	}
	if out[0].Value != "evil.example.com" {
		t.Errorf("unexpected first domain: %q", out[0].Value)
	}
}

func TestBuildPhishStatsIndicatorsEmitsURLAndIP(t *testing.T) {
	records := []phishStatsRecord{
		{URL: "https://evil.example.com/login", IP: "104.21.35.59", CountryName: "United States", ISP: "CLOUDFLARENET"},
	}
	out := buildPhishStatsIndicators(records, "PhishStats")
	if len(out) != 2 {
		t.Fatalf("expected 1 URL + 1 IP indicator, got %d: %#v", len(out), out)
	}
	foundURL, foundIP := false, false
	for _, ind := range out {
		if ind.Type == ioc.TypeURL && ind.Value == "https://evil.example.com/login" {
			foundURL = true
		}
		if ind.Type == ioc.TypeIP && ind.Value == "104.21.35.59" {
			foundIP = true
		}
	}
	if !foundURL || !foundIP {
		t.Errorf("expected both URL and IP indicators, got %#v", out)
	}
}

func TestParseTorExitTextValidatesIPs(t *testing.T) {
	text := "# comment\n171.25.193.25\nnot-an-ip\n89.58.26.216\n"
	out := parseTorExitText(text, "Tor Project")
	if len(out) != 2 {
		t.Fatalf("expected 2 valid IPs, got %d: %#v", len(out), out)
	}
}
