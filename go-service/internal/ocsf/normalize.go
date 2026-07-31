package ocsf

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func normalizeWindowsEvent(obj jsonObj) Record {
	event := asObj(obj["Event"])
	sys := asObj(event["System"])
	data := asObj(event["EventData"])
	eid := getDollar(sys, "EventID")

	hint := ""
	switch eid {
	case "4624":
		hint = "Successful logon"
	case "4625":
		hint = "Failed logon"
	case "4634":
		hint = "Logoff"
	case "4688":
		hint = firstNonEmpty(getStr(data, "NewProcessName"), getStr(data, "ProcessName"), "Process create")
	case "5156":
		hint = "Windows Filtering Platform allowed connection"
	case "7045":
		hint = firstNonEmpty(getStr(data, "ServiceName"), "Service installed")
	}

	action := hint
	if action == "" {
		action = firstNonEmpty(getStr(data, "ProcessName"), getStr(data, "ServiceName"), getStr(sys, "Provider", "@Name"), "Windows event")
	}
	severity := "Info"
	if eid == "4625" || eid == "7045" {
		severity = "High"
	}
	outcome := "Success"
	if h, ok := winAuthEventIDs[eid]; ok {
		outcome = h.Status
	}

	return finalizeRecord(rawFields{
		Shape:        "windows_event_log",
		Timestamp:    getStr(sys, "TimeCreated", "@SystemTime"),
		Source:       "Microsoft Windows Security",
		EventID:      eid,
		Computer:     getStr(sys, "Computer"),
		Username:     firstNonEmpty(getStr(data, "TargetUserName"), getStr(data, "SubjectUserName"), getStr(data, "AccountName")),
		IPAddress:    firstNonEmpty(getStr(data, "IpAddress"), getStr(data, "SourceAddress")),
		DstIPAddress: getStr(data, "DestinationAddress"),
		Action:       action,
		Severity:     severity,
		Message:      firstNonEmpty(getStr(data, "CommandLine"), getStr(data, "ParentProcessName"), hint, fmt.Sprintf("Windows event %s", eid)),
		Outcome:      outcome,
		Raw:          mustJSON(obj),
	}, "windows_evtx_json")
}

var journaldFailRe = regexp.MustCompile(`(?i)fail|error|denied`)

func normalizeJournald(obj jsonObj) Record {
	msg := getStr(obj, "MESSAGE")
	timestamp := getStr(obj, "timestamp")
	if rt := getStr(obj, "__REALTIME_TIMESTAMP"); rt != "" {
		if micros, err := strconv.ParseInt(rt, 10, 64); err == nil {
			timestamp = time.UnixMicro(micros).UTC().Format(time.RFC3339Nano)
		}
	}
	severity := "Info"
	if journaldFailRe.MatchString(msg) {
		severity = "High"
	}
	return finalizeRecord(rawFields{
		Shape:     "journald_json",
		Timestamp: timestamp,
		Source:    "Linux journald",
		EventID:   firstNonEmpty(getStr(obj, "SYSLOG_IDENTIFIER"), getStr(obj, "_SYSTEMD_UNIT"), "journald"),
		Computer:  getStr(obj, "_HOSTNAME"),
		Username:  firstNonEmpty(getStr(obj, "USER"), getStr(obj, "_UID")),
		IPAddress: pickIP(msg),
		Action:    msg,
		Severity:  severity,
		Message:   msg,
		Raw:       mustJSON(obj),
	}, "linux_journald_json")
}

var (
	asaSevRe    = regexp.MustCompile(`%ASA-(\d)-`)
	asaEventRe  = regexp.MustCompile(`%ASA-\d-(\d+)`)
	asaUserRe   = regexp.MustCompile(`(?i)user\s+("?[\w.\-@\\/]+"?)`)
	asaPrefixRe = regexp.MustCompile(`^%ASA-\d-\d+:\s*`)
)

func normalizeCiscoAsa(text string) Record {
	env := parseSyslogEnvelope(text)
	message := text
	if env != nil {
		message = env.Message
	}
	sevCode := ""
	if m := asaSevRe.FindStringSubmatch(message); m != nil {
		sevCode = m[1]
	}
	eventID := "asa"
	if m := asaEventRe.FindStringSubmatch(message); m != nil {
		eventID = m[1]
	}
	ips := pickIPs(message)
	ip0, ip1 := "", ""
	if len(ips) > 0 {
		ip0 = ips[0]
	}
	if len(ips) > 1 {
		ip1 = ips[1]
	}
	username := ""
	if m := asaUserRe.FindStringSubmatch(message); m != nil {
		username = m[1]
	}
	return finalizeRecord(rawFields{
		Shape:        "cisco_asa_syslog",
		Timestamp:    env.timestampToken(),
		Source:       "Cisco ASA Firewall",
		EventID:      eventID,
		Computer:     env.host(),
		Username:     username,
		IPAddress:    ip0,
		DstIPAddress: ip1,
		Action:       asaPrefixRe.ReplaceAllString(message, ""),
		Severity:     ciscoSeverityName(sevCode),
		Message:      message,
		Outcome:      detectOutcome(message, "Unknown"),
		Raw:          text,
	}, "cisco_asa_syslog")
}

func normalizeFortiGate(text string) Record {
	kv := parseKeyValuePairs(text)
	var actionParts []string
	for _, v := range []string{kv["type"], kv["subtype"], kv["action"]} {
		if v != "" {
			actionParts = append(actionParts, v)
		}
	}
	action := strings.Join(actionParts, " / ")
	if action == "" {
		action = "FortiGate event"
	}
	dateTime := strings.TrimSpace(kv["date"] + " " + kv["time"])
	return finalizeRecord(rawFields{
		Shape:        "fortigate_kv",
		Timestamp:    firstNonEmpty(kv["eventtime"], dateTime, kv["timestamp"]),
		Source:       firstNonEmpty(kv["devname"], "Fortinet FortiGate"),
		EventID:      firstNonEmpty(kv["logid"], kv["eventid"], kv["subtype"]),
		Computer:     firstNonEmpty(kv["devname"], kv["devid"]),
		Username:     firstNonEmpty(kv["user"], kv["srcuser"], kv["dstuser"]),
		IPAddress:    firstNonEmpty(kv["srcip"], kv["src"]),
		DstIPAddress: firstNonEmpty(kv["dstip"], kv["dst"]),
		Action:       action,
		Severity:     normalizeSeverity(firstNonEmpty(kv["level"], kv["severity"]), "Medium"),
		Message:      firstNonEmpty(kv["msg"], text),
		Outcome:      detectOutcome(firstNonEmpty(kv["action"], kv["status"], kv["msg"]), "Unknown"),
		Raw:          text,
	}, "fortigate_kv")
}

func normalizePaloAltoCef(text string, cef *cefRecord) Record {
	action := firstNonEmpty(cef.kv("act"), cef.Name, cef.kv("rule"), cef.kv("subtype"))
	cn1 := ""
	if cef.kv("cn1Label") == "user" {
		cn1 = cef.kv("cn1")
	}
	message := cef.Name
	if message == "" {
		message = text
	}
	return finalizeRecord(rawFields{
		Shape:        "cef",
		Timestamp:    firstNonEmpty(cef.kv("rt"), cef.kv("receive_time")),
		Source:       "Palo Alto PAN-OS",
		EventID:      firstNonEmpty(cef.SignatureID, cef.kv("subtype"), "pan-os"),
		Computer:     firstNonEmpty(cef.kv("dvchost"), cef.kv("dhost")),
		Username:     firstNonEmpty(cef.kv("suser"), cef.kv("duser"), cn1),
		IPAddress:    firstNonEmpty(cef.kv("src"), cef.kv("sourceAddress")),
		DstIPAddress: firstNonEmpty(cef.kv("dst"), cef.kv("destinationAddress")),
		Action:       action,
		Severity:     normalizeSeverity(cef.Severity, "Medium"),
		Message:      message,
		Outcome:      detectOutcome(firstNonEmpty(action, cef.Name), "Unknown"),
		Raw:          text,
	}, "paloalto_cef")
}

func normalizeCiscoCef(text string, cef *cefRecord) Record {
	action := firstNonEmpty(cef.kv("act"), cef.Name, cef.kv("cs1"), cef.kv("msg"))
	product := cef.Product
	if product == "" {
		product = "CEF Device"
	}
	message := cef.Name
	if message == "" {
		message = text
	}
	return finalizeRecord(rawFields{
		Shape:        "cef",
		Timestamp:    firstNonEmpty(cef.kv("rt"), cef.kv("end")),
		Source:       fmt.Sprintf("Cisco %s", product),
		EventID:      firstNonEmpty(cef.SignatureID, cef.kv("rule"), "cisco-cef"),
		Computer:     firstNonEmpty(cef.kv("dvchost"), cef.kv("dhost")),
		Username:     firstNonEmpty(cef.kv("suser"), cef.kv("duser")),
		IPAddress:    firstNonEmpty(cef.kv("src"), cef.kv("sourceAddress")),
		DstIPAddress: firstNonEmpty(cef.kv("dst"), cef.kv("destinationAddress")),
		Action:       action,
		Severity:     normalizeSeverity(cef.Severity, "Medium"),
		Message:      message,
		Outcome:      detectOutcome(firstNonEmpty(action, cef.Name), "Unknown"),
		Raw:          text,
	}, "cisco_cef")
}

var emailThreatRe = regexp.MustCompile(`(?i)spam|malware|phish|virus|quarantine`)

func normalizeEmailGateway(text string, cef *cefRecord) Record {
	action := firstNonEmpty(cef.kv("act"), cef.Name, "Email security event")
	env := parseSyslogEnvelope(text)
	vendorProduct := ""
	if cef != nil {
		vendorProduct = strings.TrimSpace(cef.Vendor + " " + cef.Product)
	}
	shape := "syslog_text"
	if cef != nil {
		shape = "cef"
	}
	severityInput := cef.Severity
	if severityInput == "" && emailThreatRe.MatchString(text) {
		severityInput = "High"
	}
	message := cef.Name
	if message == "" {
		message = text
	}
	return finalizeRecord(rawFields{
		Shape:        shape,
		Timestamp:    firstNonEmpty(cef.kv("rt"), env.timestampToken()),
		Source:       firstNonEmpty(vendorProduct, "Secure Email Gateway"),
		EventID:      firstNonEmpty(cef.SignatureID, "email-gateway"),
		Computer:     firstNonEmpty(cef.kv("dvchost"), env.host()),
		Username:     firstNonEmpty(cef.kv("suser"), cef.kv("duser"), emailRecipientMatch(text)),
		IPAddress:    firstNonEmpty(cef.kv("src"), pickIP(text)),
		DstIPAddress: cef.kv("dst"),
		Action:       action,
		Severity:     normalizeSeverity(severityInput, "Medium"),
		Message:      message,
		Outcome:      detectOutcome(firstNonEmpty(action, text), "Unknown"),
		Raw:          text,
	}, "email_security_gateway_cef")
}

var emailRecipientRe = regexp.MustCompile(`(?i)recipient[=:]\s*([^\s,]+)`)

func emailRecipientMatch(text string) string {
	if m := emailRecipientRe.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

var (
	paloAltoTypeRe   = regexp.MustCompile(`(?i)^(TRAFFIC|THREAT|SYSTEM|CONFIG)$`)
	paloAltoTsRe     = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} `)
	paloAltoActionRe = regexp.MustCompile(`(?i)^(allow|deny|drop|reset-|alert|block)`)
	paloAltoAtRe     = regexp.MustCompile(`@`)
	paloAltoThreatRe = regexp.MustCompile(`(?i)THREAT|deny|drop|block`)
)

func normalizePaloAltoCsv(text string) Record {
	rawTokens := strings.Split(text, ",")
	tokens := make([]string, len(rawTokens))
	for i, t := range rawTokens {
		tokens[i] = strings.TrimSpace(t)
	}

	typ := "TRAFFIC"
	typeIdx := -1
	for i, t := range tokens {
		if paloAltoTypeRe.MatchString(t) {
			typ = t
			typeIdx = i
			break
		}
	}
	subtype := ""
	if typeIdx >= 0 && typeIdx+1 < len(tokens) {
		subtype = tokens[typeIdx+1]
	}
	timestamp := ""
	for _, t := range tokens {
		if paloAltoTsRe.MatchString(t) {
			timestamp = t
			break
		}
	}
	ips := pickIPs(text)
	ip0, ip1 := "", ""
	if len(ips) > 0 {
		ip0 = ips[0]
	}
	if len(ips) > 1 {
		ip1 = ips[1]
	}
	actionToken := ""
	for _, t := range tokens {
		if paloAltoActionRe.MatchString(t) {
			actionToken = t
			break
		}
	}
	username := ""
	for _, t := range tokens {
		if paloAltoAtRe.MatchString(t) {
			username = t
			break
		}
	}
	computer := ""
	if len(tokens) > 2 {
		computer = tokens[2]
	}

	var actionParts []string
	for _, v := range []string{typ, subtype, actionToken} {
		if v != "" {
			actionParts = append(actionParts, v)
		}
	}
	severity := "Medium"
	if paloAltoThreatRe.MatchString(fmt.Sprintf("%s %s %s", typ, subtype, actionToken)) {
		severity = "High"
	}

	return finalizeRecord(rawFields{
		Shape:        "paloalto_csv",
		Timestamp:    timestamp,
		Source:       "Palo Alto PAN-OS",
		EventID:      firstNonEmpty(subtype, typ),
		Computer:     computer,
		Username:     username,
		IPAddress:    ip0,
		DstIPAddress: ip1,
		Action:       strings.Join(actionParts, " / "),
		Severity:     severity,
		Message:      text,
		Outcome:      detectOutcome(firstNonEmpty(actionToken, typ), "Unknown"),
		Raw:          text,
	}, "paloalto_syslog_csv")
}

var linuxAuthProgramRe = regexp.MustCompile(`(?i)sshd|sudo|login|su|cron|systemd`)
var linuxUserRe1 = regexp.MustCompile(`for (?:invalid user )?(\S+)`)
var linuxUserRe2 = regexp.MustCompile(`(?i)user(?:name)?[=:]\s*([^\s,]+)`)
var linuxFailRe = regexp.MustCompile(`(?i)fail|invalid|deny|error`)

func normalizeLinuxSyslog(text string) Record {
	env := parseSyslogEnvelope(text)
	message := text
	if env != nil {
		message = env.Message
	}
	source := "Linux Syslog"
	if env != nil && linuxAuthProgramRe.MatchString(env.Program) {
		source = "Linux Auth"
	}
	username := ""
	if m := linuxUserRe1.FindStringSubmatch(message); m != nil {
		username = m[1]
	} else if m := linuxUserRe2.FindStringSubmatch(message); m != nil {
		username = m[1]
	}
	severity := "Info"
	if linuxFailRe.MatchString(message) {
		severity = "High"
	}
	eventID := "syslog"
	if env != nil && env.Program != "" {
		eventID = env.Program
	}
	return finalizeRecord(rawFields{
		Shape:     "syslog_text",
		Timestamp: env.timestampToken(),
		Source:    source,
		EventID:   eventID,
		Computer:  env.host(),
		Username:  username,
		IPAddress: pickIP(message),
		Action:    message,
		Severity:  severity,
		Message:   message,
		Outcome:   detectOutcome(message, "Unknown"),
		Raw:       text,
	}, "linux_syslog_auth")
}

var aixUserRe = regexp.MustCompile(`(?i)for user\s+([^\s,]+)`)
var aixFailRe = regexp.MustCompile(`(?i)fail|denied|error`)

func normalizeAixSyslog(text string, hinted jsonObj) Record {
	env := parseSyslogEnvelope(text)
	message := text
	if env != nil {
		message = env.Message
	}
	username := getStr(hinted, "user")
	if username == "" {
		if m := aixUserRe.FindStringSubmatch(message); m != nil {
			username = m[1]
		}
	}
	severityInput := getStr(hinted, "severity")
	if severityInput == "" && aixFailRe.MatchString(message) {
		severityInput = "High"
	}
	eventID := env.program()
	if eventID == "" {
		eventID = getStr(hinted, "event_id")
	}
	if eventID == "" {
		eventID = "aix"
	}
	return finalizeRecord(rawFields{
		Shape:     "syslog_text",
		Timestamp: firstNonEmpty(getStr(hinted, "timestamp"), env.timestampToken()),
		Source:    "IBM AIX Syslog",
		EventID:   eventID,
		Computer:  firstNonEmpty(getStr(hinted, "host"), getStr(hinted, "computer"), env.host()),
		Username:  username,
		IPAddress: firstNonEmpty(getStr(hinted, "ip"), getStr(hinted, "src_ip"), pickIP(message)),
		Action:    firstNonEmpty(getStr(hinted, "action"), message),
		Severity:  normalizeSeverity(severityInput, "Info"),
		Message:   message,
		Outcome:   detectOutcome(message, "Unknown"),
		Raw:       text,
	}, "aix_syslog")
}

var modsecIDRe = regexp.MustCompile(`(?i)\[id "?(\d+)"?\]`)
var modsecClientRe = regexp.MustCompile(`(?i)\[client (\d+\.\d+\.\d+\.\d+)\]`)
var modsecAccessDeniedRe = regexp.MustCompile(`(?i)access denied`)
var modsecThreatRe = regexp.MustCompile(`(?i)sql|xss|rce|scanner|attack|denied`)

func normalizeModSecurity(text string) Record {
	env := parseSyslogEnvelope(text)
	message := text
	if env != nil {
		message = env.Message
	}
	eventID := "modsecurity"
	if m := modsecIDRe.FindStringSubmatch(message); m != nil {
		eventID = m[1]
	}
	ip := ""
	if m := modsecClientRe.FindStringSubmatch(message); m != nil {
		ip = m[1]
	} else {
		ip = pickIP(message)
	}
	action := "WAF event"
	if modsecAccessDeniedRe.MatchString(message) {
		action = "Blocked web request"
	}
	severity := "Medium"
	if modsecThreatRe.MatchString(message) {
		severity = "High"
	}
	return finalizeRecord(rawFields{
		Shape:     "waf_text",
		Timestamp: env.timestampToken(),
		Source:    "OWASP ModSecurity WAF",
		EventID:   eventID,
		Computer:  env.host(),
		IPAddress: ip,
		Action:    action,
		Severity:  severity,
		Message:   message,
		Outcome:   "Failure",
		Raw:       text,
	}, "modsecurity_waf")
}

var awsWafBlockRe = regexp.MustCompile(`(?i)block`)

func normalizeAwsWaf(obj jsonObj) Record {
	action := getStr(obj, "action")
	severity := "Medium"
	if awsWafBlockRe.MatchString(action) {
		severity = "High"
	}
	return finalizeRecord(rawFields{
		Shape:     "aws_waf_json",
		Timestamp: firstNonEmpty(getStr(obj, "timestamp"), getStr(obj, "@timestamp")),
		Source:    "AWS WAF",
		EventID:   firstNonEmpty(getStr(obj, "terminatingRuleId"), getStr(obj, "ruleGroupId"), "aws-waf"),
		Computer:  firstNonEmpty(getStr(obj, "webaclId"), getStr(obj, "httpSourceName")),
		Username:  firstNonEmpty(getStr(obj, "user"), getStr(obj, "username")),
		IPAddress: firstNonEmpty(getStr(obj, "httpRequest", "clientIp"), getStr(obj, "clientIp")),
		Action:    firstNonEmpty(action, getStr(obj, "httpSourceId"), "WAF request"),
		Severity:  severity,
		Message:   firstNonEmpty(getStr(obj, "terminatingRuleId"), action, "AWS WAF event"),
		Outcome:   detectOutcome(action, "Unknown"),
		Raw:       mustJSON(obj),
	}, "aws_waf_json")
}

var postfixQueueIDRe = regexp.MustCompile(`^([A-F0-9]+):`)
var postfixToRe = regexp.MustCompile(`to=<([^>]+)>`)
var postfixFromRe = regexp.MustCompile(`from=<([^>]+)>`)
var postfixRejectRe = regexp.MustCompile(`(?i)reject|deferred|warning|bounced`)
var postfixSentRe = regexp.MustCompile(`(?i)status=sent`)
var postfixSevereRe = regexp.MustCompile(`(?i)reject|bounce|virus|spam`)

func normalizePostfix(text string) Record {
	env := parseSyslogEnvelope(text)
	message := text
	if env != nil {
		message = env.Message
	}
	eventID := ""
	if m := postfixQueueIDRe.FindStringSubmatch(message); m != nil {
		eventID = m[1]
	} else {
		eventID = env.program()
	}
	if eventID == "" {
		eventID = "postfix"
	}
	username := ""
	if m := postfixToRe.FindStringSubmatch(message); m != nil {
		username = m[1]
	} else if m := postfixFromRe.FindStringSubmatch(message); m != nil {
		username = m[1]
	}
	action := "Email event"
	switch {
	case postfixRejectRe.MatchString(message):
		action = "Email rejected"
	case postfixSentRe.MatchString(message):
		action = "Email delivered"
	}
	severity := "Info"
	if postfixSevereRe.MatchString(message) {
		severity = "High"
	}
	return finalizeRecord(rawFields{
		Shape:     "email_syslog",
		Timestamp: env.timestampToken(),
		Source:    "Postfix Mail Server",
		EventID:   eventID,
		Computer:  env.host(),
		Username:  username,
		IPAddress: pickIP(message),
		Action:    action,
		Severity:  severity,
		Message:   message,
		Outcome:   detectOutcome(message, "Unknown"),
		Raw:       text,
	}, "email_postfix")
}

var exchangeThreatRe = regexp.MustCompile(`(?i)malware|phish|spam|blocked|quarantine`)

func normalizeExchangeJSON(obj jsonObj) Record {
	action := firstNonEmpty(getStr(obj, "action"), getStr(obj, "operation"), getStr(obj, "eventName"), "Email activity")
	verdict := getStr(obj, "verdict")
	threat := getStr(obj, "threat")
	severity := "Info"
	if exchangeThreatRe.MatchString(fmt.Sprintf("%s %s %s", action, verdict, threat)) {
		severity = "High"
	}
	status := getStr(obj, "status")
	return finalizeRecord(rawFields{
		Shape:     "email_json",
		Timestamp: firstNonEmpty(getStr(obj, "timestamp"), getStr(obj, "time"), getStr(obj, "CreationTime"), getStr(obj, "@timestamp")),
		Source:    firstNonEmpty(getStr(obj, "source"), getStr(obj, "workload"), "Microsoft Exchange"),
		EventID:   firstNonEmpty(getStr(obj, "event_id"), getStr(obj, "Id"), getStr(obj, "Operation"), "exchange"),
		Computer:  firstNonEmpty(getStr(obj, "server"), getStr(obj, "host"), getStr(obj, "ClientIP")),
		Username:  firstNonEmpty(getStr(obj, "user"), getStr(obj, "UserId"), getStr(obj, "MailboxOwnerUPN"), getStr(obj, "sender"), getStr(obj, "recipient")),
		IPAddress: firstNonEmpty(getStr(obj, "ip"), getStr(obj, "ip_address"), getStr(obj, "ClientIP")),
		Action:    action,
		Severity:  severity,
		Message:   firstNonEmpty(getStr(obj, "subject"), verdict, getStr(obj, "message"), action),
		Outcome:   detectOutcome(fmt.Sprintf("%s %s %s", action, verdict, status), "Unknown"),
		Raw:       mustJSON(obj),
	}, "exchange_email_json")
}

func normalizeGenericCef(text string, cef *cefRecord) Record {
	vendorProduct := strings.TrimSpace(cef.Vendor + " " + cef.Product)
	message := cef.Name
	if message == "" {
		message = text
	}
	return finalizeRecord(rawFields{
		Shape:        "cef",
		Timestamp:    firstNonEmpty(cef.kv("rt"), cef.kv("end")),
		Source:       firstNonEmpty(vendorProduct, "CEF Device"),
		EventID:      firstNonEmpty(cef.SignatureID, cef.Name),
		Computer:     firstNonEmpty(cef.kv("dvchost"), cef.kv("dhost")),
		Username:     firstNonEmpty(cef.kv("suser"), cef.kv("duser")),
		IPAddress:    firstNonEmpty(cef.kv("src"), cef.kv("sourceAddress")),
		DstIPAddress: firstNonEmpty(cef.kv("dst"), cef.kv("destinationAddress")),
		Action:       firstNonEmpty(cef.kv("act"), cef.Name, text),
		Severity:     normalizeSeverity(cef.Severity, "Medium"),
		Message:      message,
		Outcome:      detectOutcome(strings.TrimSpace(cef.kv("act")+" "+cef.Name), "Unknown"),
		Raw:          text,
	}, "generic_cef")
}

func normalizeGenericJSON(obj jsonObj) Record {
	source := firstNonEmpty(getStr(obj, "source"), getStr(obj, "product"), getStr(obj, "vendor"), getStr(obj, "device_type"), "Generic JSON Log")
	action := getStr(obj, "action")
	status := getStr(obj, "status")
	verdict := getStr(obj, "verdict")
	return finalizeRecord(rawFields{
		Shape:        "generic_json",
		Timestamp:    firstNonEmpty(getStr(obj, "timestamp"), getStr(obj, "time"), getStr(obj, "@timestamp")),
		Source:       source,
		EventID:      firstNonEmpty(getStr(obj, "event_id"), getStr(obj, "id"), getStr(obj, "logid"), getStr(obj, "operation")),
		Computer:     firstNonEmpty(getStr(obj, "hostname"), getStr(obj, "host"), getStr(obj, "computer"), getStr(obj, "device")),
		Username:     firstNonEmpty(getStr(obj, "user"), getStr(obj, "username"), getStr(obj, "account"), getStr(obj, "sender"), getStr(obj, "recipient")),
		IPAddress:    firstNonEmpty(getStr(obj, "ip"), getStr(obj, "ip_address"), getStr(obj, "src_ip"), getStr(obj, "client_ip")),
		DstIPAddress: firstNonEmpty(getStr(obj, "dst_ip"), getStr(obj, "destination_ip")),
		Action:       firstNonEmpty(action, getStr(obj, "message"), getStr(obj, "msg"), getStr(obj, "operation"), source),
		Severity:     normalizeSeverity(getStr(obj, "severity"), "Info"),
		Message:      firstNonEmpty(getStr(obj, "message"), getStr(obj, "msg"), getStr(obj, "description"), action),
		Outcome:      detectOutcome(strings.TrimSpace(action+" "+status+" "+verdict), "Unknown"),
		Raw:          mustJSON(obj),
		Additional:   map[string]any{"vendor": obj["vendor"], "product": obj["product"]},
	}, "generic_json")
}

// normalizeK3Event handles our own already-normalized event shape (as produced by the
// existing Node ingestion pipeline / demo generator: {source, event_id, computer, username,
// ip_address, action, severity, raw, index, ...}) — mapped onto the generic_json profile,
// same as the Node normalizeK3Event().
func normalizeK3Event(obj jsonObj) Record {
	source := firstNonEmpty(getStr(obj, "source"), getStr(obj, "product"), getStr(obj, "vendor"), "K3 Normalized Event")
	action := getStr(obj, "action")
	message := getStr(obj, "message")
	rawStr, ok := obj["raw"].(string)
	if !ok {
		rawStr = mustJSON(obj)
	}
	return finalizeRecord(rawFields{
		Shape:        "k3_normalized",
		Timestamp:    getStr(obj, "timestamp"),
		Source:       source,
		EventID:      getStr(obj, "event_id"),
		Computer:     getStr(obj, "computer"),
		Username:     getStr(obj, "username"),
		IPAddress:    firstNonEmpty(getStr(obj, "ip_address"), getStr(obj, "src_ip")),
		DstIPAddress: getStr(obj, "dst_ip"),
		Action:       action,
		Severity:     firstNonEmpty(getStr(obj, "severity"), "Info"),
		Message:      firstNonEmpty(message, action),
		Outcome:      detectOutcome(strings.TrimSpace(action+" "+message), "Unknown"),
		Raw:          rawStr,
		IndexName:    firstNonEmpty(getStr(obj, "index"), getStr(obj, "index_name")),
	}, "generic_json")
}

var rawTextThreatRe = regexp.MustCompile(`(?i)fail|denied|blocked|attack|malware|phish|virus|error`)

func normalizeRawText(text string) Record {
	severity := "Info"
	if rawTextThreatRe.MatchString(text) {
		severity = "High"
	}
	return finalizeRecord(rawFields{
		Shape:     "raw_text",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Source:    "Unknown",
		IPAddress: pickIP(text),
		Action:    text,
		Severity:  severity,
		Message:   text,
		Outcome:   detectOutcome(text, "Unknown"),
		Raw:       text,
	}, "raw_text")
}

var (
	fortiHintRe      = regexp.MustCompile(`devname=|devid=|logid=`)
	fortiVendorRe    = regexp.MustCompile(`(?i)forti|FortiGate`)
	fortiModelRe     = regexp.MustCompile(`\bFGT[A-Z0-9-]*\b`)
	asaMarkerRe      = regexp.MustCompile(`%ASA-\d-\d+`)
	paloAltoVendorRe = regexp.MustCompile(`(?i)palo\s*alto`)
	emailGatewayRe   = regexp.MustCompile(`(?i)proofpoint|mimecast|ironport|email security|esa`)
	ciscoVendorRe    = regexp.MustCompile(`(?i)cisco`)
	paloAltoCsvRe    = regexp.MustCompile(`(?i)^\d+,20\d{2}/\d{2}/\d{2} .*?,(TRAFFIC|THREAT|SYSTEM|CONFIG),`)
	modsecMarkerRe   = regexp.MustCompile(`(?i)ModSecurity:`)
	postfixProgramRe = regexp.MustCompile(`(?i)^postfix/`)
	aixMarkerRe      = regexp.MustCompile(`(?i)\bAIX\b`)
	linuxProgramRe   = regexp.MustCompile(`(?i)sshd|sudo|login|su|cron|systemd|kernel`)
)

// ParseLogRecord dispatches a single log line/JSON blob to the right vendor normalizer,
// mirroring the Node parseLogRecord() decision tree exactly (same order, same guards).
func ParseLogRecord(input string) Record {
	ctx := buildContext(input)
	json := ctx.JSON
	text := ctx.Text

	var cef *cefRecord
	if text != "" && strings.HasPrefix(text, "CEF:") {
		cef = parseCEF(text)
	}
	var env *syslogEnvelope
	if text != "" {
		env = parseSyslogEnvelope(text)
	}

	switch {
	case get(json, "Event", "System") != nil:
		return normalizeWindowsEvent(json)
	case getStr(json, "__REALTIME_TIMESTAMP") != "" || getStr(json, "SYSLOG_IDENTIFIER") != "" || getStr(json, "_HOSTNAME") != "":
		return normalizeJournald(json)
	case get(json, "httpRequest") != nil && (getStr(json, "terminatingRuleId") != "" || getStr(json, "action") != ""):
		return normalizeAwsWaf(json)
	case json != nil && (matchesExchangeWorkload(json) || json["sender"] != nil || json["recipient"] != nil):
		return normalizeExchangeJSON(json)
	case json != nil && mentionsAIX(json):
		aixText := ctx.EmbeddedRawText
		if aixText == "" {
			aixText = ctx.RawText
		}
		return normalizeAixSyslog(aixText, json)
	case json != nil && (json["action"] != nil || json["source"] != nil || json["raw"] != nil):
		return normalizeK3Event(json)
	case text != "" && fortiHintRe.MatchString(text) && (fortiVendorRe.MatchString(text) || fortiModelRe.MatchString(text)):
		return normalizeFortiGate(text)
	case text != "" && asaMarkerRe.MatchString(text):
		return normalizeCiscoAsa(text)
	case cef != nil && paloAltoVendorRe.MatchString(cef.Vendor+" "+cef.Product):
		return normalizePaloAltoCef(text, cef)
	case cef != nil && emailGatewayRe.MatchString(cef.Vendor+" "+cef.Product+" "+cef.Name):
		return normalizeEmailGateway(text, cef)
	case cef != nil && ciscoVendorRe.MatchString(cef.Vendor+" "+cef.Product):
		return normalizeCiscoCef(text, cef)
	case cef != nil:
		return normalizeGenericCef(text, cef)
	case text != "" && paloAltoCsvRe.MatchString(text):
		return normalizePaloAltoCsv(text)
	case text != "" && modsecMarkerRe.MatchString(text):
		return normalizeModSecurity(text)
	case env != nil && postfixProgramRe.MatchString(env.Program):
		return normalizePostfix(text)
	case (env != nil && aixMarkerRe.MatchString(env.Host+" "+env.ProgramRaw+" "+env.Message)) || aixMarkerRe.MatchString(text):
		return normalizeAixSyslog(text, nil)
	case env != nil && linuxProgramRe.MatchString(env.Program):
		return normalizeLinuxSyslog(text)
	case env != nil:
		return normalizeLinuxSyslog(text)
	case json != nil:
		return normalizeGenericJSON(json)
	default:
		return normalizeRawText(text)
	}
}

// matchesExchangeWorkload mirrors the Node guard exactly: `workload` may match "exchange" or
// "office", but `product` is only checked against the narrower "exchange" pattern.
func matchesExchangeWorkload(obj jsonObj) bool {
	workload := getStr(obj, "workload")
	product := getStr(obj, "product")
	return exchangeWorkloadRe.MatchString(workload) || exchangeProductRe.MatchString(product)
}

var (
	exchangeWorkloadRe = regexp.MustCompile(`(?i)exchange|office`)
	exchangeProductRe  = regexp.MustCompile(`(?i)exchange`)
)

func mentionsAIX(obj jsonObj) bool {
	vendor := strings.ToLower(getStr(obj, "vendor"))
	product := strings.ToLower(getStr(obj, "product"))
	source := strings.ToLower(getStr(obj, "source"))
	return strings.Contains(vendor, "aix") || strings.Contains(product, "aix") || strings.Contains(source, "aix")
}
