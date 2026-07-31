package ocsf

import "testing"

func TestParseLogRecordWindowsEvent(t *testing.T) {
	line := `{"Event":{"System":{"EventID":"4625","Computer":"WS-001","TimeCreated":{"@SystemTime":"2026-01-01T00:00:00Z"}},"EventData":{"TargetUserName":"bob","IpAddress":"1.2.3.4"}}}`
	rec := ParseLogRecord(line)
	if rec.Parser.ProfileID != "windows_evtx_json" {
		t.Fatalf("expected windows_evtx_json profile, got %s", rec.Parser.ProfileID)
	}
	if rec.EventID != "4625" || rec.Username != "bob" || rec.IPAddress != "1.2.3.4" {
		t.Errorf("unexpected fields: %#v", rec)
	}
	if rec.Severity != "High" {
		t.Errorf("expected High severity for 4625, got %s", rec.Severity)
	}
	if rec.Outcome != "Failure" {
		t.Errorf("expected Failure outcome for 4625, got %s", rec.Outcome)
	}

	ev := ToOCSF(rec)
	if ev.ClassUID != 3002 || ev.ActivityName != "Logon" || ev.Status != "Failure" {
		t.Errorf("unexpected OCSF classification: %#v", ev)
	}
}

func TestParseLogRecordLinuxAuth(t *testing.T) {
	line := `Jan 15 10:00:00 srv01 sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 4444 ssh2`
	rec := ParseLogRecord(line)
	if rec.Parser.ProfileID != "linux_syslog_auth" {
		t.Fatalf("expected linux_syslog_auth profile, got %s", rec.Parser.ProfileID)
	}
	if rec.Computer != "srv01" {
		t.Errorf("expected computer=srv01, got %q", rec.Computer)
	}
	if rec.Username != "admin" {
		t.Errorf("expected username=admin, got %q", rec.Username)
	}
	if rec.IPAddress != "10.0.0.5" {
		t.Errorf("expected ip=10.0.0.5, got %q", rec.IPAddress)
	}
	if rec.Severity != "High" {
		t.Errorf("expected High severity for a failed login, got %s", rec.Severity)
	}

	ev := ToOCSF(rec)
	if ev.ClassUID != 3002 || ev.ActivityName != "Logon" || ev.Status != "Failure" {
		t.Errorf("unexpected OCSF classification: %#v", ev)
	}
}

func TestParseLogRecordCiscoASA(t *testing.T) {
	// parseSyslogEnvelope's shared regex (ported as-is from Node) captures the pre-colon
	// token as the syslog "program" field — for a line shaped like
	// "<ts> <host> %ASA-4-106023: <message>", that swallows the %ASA tag itself into
	// `env.program`, leaving `env.message` without it. normalizeCiscoAsa (in both Node and
	// here) only searches `env.message` for the %ASA pattern, so event_id/severity fall back
	// to "asa"/Info for this input shape in the ORIGINAL Node implementation too — verified
	// directly against the shared regex, not a Go-porting regression. This test locks in that
	// parity rather than an idealized-but-incorrect expectation of what the code "should" do.
	line := `Jan 15 10:00:00 fw01 %ASA-4-106023: Deny tcp src 1.2.3.4/1234 dst 5.6.7.8/443`
	rec := ParseLogRecord(line)
	if rec.Parser.ProfileID != "cisco_asa_syslog" {
		t.Fatalf("expected cisco_asa_syslog profile, got %s", rec.Parser.ProfileID)
	}
	if rec.Computer != "fw01" {
		t.Errorf("expected computer=fw01, got %q", rec.Computer)
	}
	if rec.IPAddress != "1.2.3.4" || rec.DstIPAddress != "5.6.7.8" {
		t.Errorf("unexpected IPs: src=%q dst=%q", rec.IPAddress, rec.DstIPAddress)
	}
	if rec.EventID != "asa" {
		t.Errorf("expected event_id fallback %q, got %q", "asa", rec.EventID)
	}
	if rec.Severity != "Info" {
		t.Errorf("expected Info severity fallback, got %s", rec.Severity)
	}
}

func TestParseLogRecordGenericJSON(t *testing.T) {
	// Deliberately avoids the `source`/`action`/`raw` keys — any of those routes to
	// normalizeK3Event (our own already-normalized event shape) instead of generic_json,
	// matching the Node dispatcher's `json.action !== undefined || json.source !== undefined
	// || json.raw !== undefined` guard, which is checked before falling through to generic.
	line := `{"product":"CustomApp","user":"alice","ip":"9.9.9.9","message":"login attempt","severity":"high"}`
	rec := ParseLogRecord(line)
	if rec.Parser.ProfileID != "generic_json" {
		t.Fatalf("expected generic_json profile, got %s", rec.Parser.ProfileID)
	}
	if rec.Username != "alice" || rec.IPAddress != "9.9.9.9" || rec.Severity != "High" {
		t.Errorf("unexpected fields: %#v", rec)
	}
}

func TestParseLogRecordRawTextFallback(t *testing.T) {
	line := `something completely unstructured happened here`
	rec := ParseLogRecord(line)
	if rec.Parser.ProfileID != "raw_text" {
		t.Fatalf("expected raw_text fallback, got %s", rec.Parser.ProfileID)
	}
	if rec.Severity != "Info" {
		t.Errorf("expected Info severity, got %s", rec.Severity)
	}
}

func TestParseLogRecordCEFPaloAlto(t *testing.T) {
	line := `CEF:0|Palo Alto Networks|PAN-OS|1.0|threat|Spyware Detected|8|src=1.2.3.4 dst=5.6.7.8 suser=bob act=alert`
	rec := ParseLogRecord(line)
	if rec.Parser.ProfileID != "paloalto_cef" {
		t.Fatalf("expected paloalto_cef profile, got %s", rec.Parser.ProfileID)
	}
	if rec.IPAddress != "1.2.3.4" || rec.DstIPAddress != "5.6.7.8" || rec.Username != "bob" {
		t.Errorf("unexpected fields: %#v", rec)
	}
	// normalizeSeverity's numeric thresholds are >=9 Critical, >=7 High — 8 lands in High.
	if rec.Severity != "High" {
		t.Errorf("expected High severity for CEF sev=8, got %s", rec.Severity)
	}
}
