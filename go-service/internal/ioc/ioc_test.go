package ioc

import "testing"

func TestNormalizeValue(t *testing.T) {
	cases := []struct {
		typ  Type
		in   string
		want string
	}{
		{TypeHash, "  ABC123  ", "abc123"},
		{TypeDomain, "EXAMPLE.COM", "example.com"},
		{TypeEmail, "User@Example.com", "user@example.com"},
		{TypeIP, "1.2.3.4", "1.2.3.4"},
		{TypeURL, "https://Example.com/Path", "https://Example.com/Path"},
	}
	for _, c := range cases {
		if got := NormalizeValue(c.typ, c.in); got != c.want {
			t.Errorf("NormalizeValue(%s, %q) = %q, want %q", c.typ, c.in, got, c.want)
		}
	}
}

func TestKeyUniqueness(t *testing.T) {
	if Key(TypeIP, "1.2.3.4") == Key(TypeDomain, "1.2.3.4") {
		t.Fatal("keys for different types with the same value must not collide")
	}
}

func TestIsCIDR(t *testing.T) {
	if !IsCIDR("1.2.3.0/24") {
		t.Error("expected 1.2.3.0/24 to be recognized as CIDR")
	}
	if IsCIDR("1.2.3.4") {
		t.Error("expected a plain IP not to be recognized as CIDR")
	}
}

func TestCIDRContains(t *testing.T) {
	cases := []struct {
		cidr string
		ip   string
		want bool
	}{
		{"192.168.1.0/24", "192.168.1.42", true},
		{"192.168.1.0/24", "192.168.2.1", false},
		{"10.0.0.0/8", "10.255.255.255", true},
		{"2001:db8::/32", "2001:db8::1", true},
		{"2001:db8::/32", "2001:db9::1", false},
		// family mismatch must never match, matching the Node net.isIP(ip) !== kind guard
		{"192.168.1.0/24", "2001:db8::1", false},
		{"not-a-cidr", "192.168.1.1", false},
		{"192.168.1.0/24", "not-an-ip", false},
	}
	for _, c := range cases {
		if got := CIDRContains(c.cidr, c.ip); got != c.want {
			t.Errorf("CIDRContains(%q, %q) = %v, want %v", c.cidr, c.ip, got, c.want)
		}
	}
}

func TestClampConfidence(t *testing.T) {
	if got := ClampConfidence(150, true); got != 100 {
		t.Errorf("expected clamp to 100, got %d", got)
	}
	if got := ClampConfidence(-5, true); got != 0 {
		t.Errorf("expected clamp to 0, got %d", got)
	}
	if got := ClampConfidence(0, false); got != 50 {
		t.Errorf("expected default 50 when not ok, got %d", got)
	}
}
