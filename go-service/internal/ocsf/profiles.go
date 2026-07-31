// Package ocsf ports backend/src/services/ocsfParser.js: a heuristic multi-vendor log parser
// that normalizes arbitrary log lines/JSON into a common Record shape, then maps that onto an
// OCSF 1.3.0-shaped Event. 17 vendor profiles are recognized; anything else falls back to a
// generic JSON or raw-text profile.
package ocsf

const Version = "1.3.0"

// Profile describes one recognized log source: how to recognize it and what OCSF metadata to
// stamp onto records it produces. Mirrors the Node PROFILE_CATALOG entries exactly.
type Profile struct {
	ID          string
	Title       string
	Family      string
	Vendor      string
	Product     string
	DeviceType  string
	Formats     []string
	Description string
}

// Catalog is the 17 recognized vendor profiles, in the same order as the Node PROFILE_CATALOG.
var Catalog = []Profile{
	{ID: "windows_evtx_json", Title: "Windows Event Log", Family: "windows", Vendor: "Microsoft", Product: "Windows Security Event Log", DeviceType: "endpoint_os", Formats: []string{"wevtutil-json", "event-json"}, Description: "Windows Security events, including logon, privilege, process, and firewall telemetry."},
	{ID: "linux_journald_json", Title: "Linux Journald", Family: "linux", Vendor: "Linux", Product: "journald", DeviceType: "server_os", Formats: []string{"journald-json"}, Description: "Structured Linux systemd/journald records."},
	{ID: "linux_syslog_auth", Title: "Linux Syslog/Auth", Family: "linux", Vendor: "Linux", Product: "Syslog", DeviceType: "server_os", Formats: []string{"syslog"}, Description: "Linux syslog and auth.log events such as SSH, sudo, login, and service activity."},
	{ID: "aix_syslog", Title: "IBM AIX Syslog", Family: "aix", Vendor: "IBM", Product: "AIX Syslog", DeviceType: "unix_os", Formats: []string{"syslog"}, Description: "AIX auth, cron, and operating-system syslog events."},
	{ID: "cisco_asa_syslog", Title: "Cisco ASA Firewall", Family: "firewall", Vendor: "Cisco", Product: "ASA Firewall", DeviceType: "firewall", Formats: []string{"syslog"}, Description: "Cisco ASA and related syslog patterns such as connection build, deny, and teardown."},
	{ID: "cisco_cef", Title: "Cisco CEF", Family: "firewall", Vendor: "Cisco", Product: "CEF Device", DeviceType: "network_security", Formats: []string{"cef"}, Description: "Cisco device events emitted in CEF format."},
	{ID: "paloalto_cef", Title: "Palo Alto PAN-OS (CEF)", Family: "firewall", Vendor: "Palo Alto Networks", Product: "PAN-OS", DeviceType: "firewall", Formats: []string{"cef"}, Description: "Palo Alto firewall and threat events wrapped in CEF."},
	{ID: "paloalto_syslog_csv", Title: "Palo Alto PAN-OS Syslog", Family: "firewall", Vendor: "Palo Alto Networks", Product: "PAN-OS", DeviceType: "firewall", Formats: []string{"csv-syslog"}, Description: "Native Palo Alto TRAFFIC, THREAT, SYSTEM, and CONFIG syslog feeds."},
	{ID: "fortigate_kv", Title: "Fortinet FortiGate", Family: "firewall", Vendor: "Fortinet", Product: "FortiGate", DeviceType: "firewall", Formats: []string{"key-value", "syslog"}, Description: "FortiGate traffic, utm, and event logs using key-value pairs."},
	{ID: "modsecurity_waf", Title: "ModSecurity WAF", Family: "waf", Vendor: "OWASP", Product: "ModSecurity", DeviceType: "waf", Formats: []string{"syslog", "text"}, Description: "ModSecurity and CRS WAF findings including blocks, SQLi, XSS, and anomaly scores."},
	{ID: "aws_waf_json", Title: "AWS WAF", Family: "waf", Vendor: "Amazon Web Services", Product: "AWS WAF", DeviceType: "waf", Formats: []string{"json"}, Description: "AWS WAF rule, action, and request telemetry."},
	{ID: "email_postfix", Title: "Postfix Email", Family: "email", Vendor: "Postfix", Product: "Postfix", DeviceType: "mail_server", Formats: []string{"syslog"}, Description: "Email delivery, rejection, and relay events from Postfix and similar MTAs."},
	{ID: "exchange_email_json", Title: "Exchange / M365 Email", Family: "email", Vendor: "Microsoft", Product: "Exchange", DeviceType: "mail_service", Formats: []string{"json"}, Description: "Structured email activity from Microsoft Exchange and M365 mail workloads."},
	{ID: "email_security_gateway_cef", Title: "Email Security Gateway", Family: "email_security_gateway", Vendor: "Email Security Vendor", Product: "Secure Email Gateway", DeviceType: "email_gateway", Formats: []string{"cef", "syslog"}, Description: "Proofpoint, Mimecast, Cisco ESA, and similar secure email gateway telemetry."},
	{ID: "generic_cef", Title: "Generic CEF", Family: "generic_network", Vendor: "Generic", Product: "CEF Device", DeviceType: "security_device", Formats: []string{"cef"}, Description: "Fallback for security tools that emit CEF but do not match a more specific profile."},
	{ID: "generic_json", Title: "Generic JSON", Family: "generic", Vendor: "Generic", Product: "JSON Log", DeviceType: "generic", Formats: []string{"json"}, Description: "Best-effort mapping for arbitrary JSON logs."},
	{ID: "raw_text", Title: "Raw Text Fallback", Family: "generic", Vendor: "Generic", Product: "Raw Text Log", DeviceType: "generic", Formats: []string{"text"}, Description: "Catch-all parser for unstructured raw text lines."},
}

func profileByID(id string) Profile {
	for _, p := range Catalog {
		if p.ID == id {
			return p
		}
	}
	for _, p := range Catalog {
		if p.ID == "raw_text" {
			return p
		}
	}
	return Profile{}
}

// Class is one OCSF event class: its identity plus category.
type Class struct {
	ClassUID     int
	ClassName    string
	CategoryUID  int
	CategoryName string
}

var (
	classAuthentication = Class{3002, "Authentication", 3, "Identity & Access Management"}
	classProcess        = Class{1007, "Process Activity", 1, "System Activity"}
	classFile           = Class{1001, "File System Activity", 1, "System Activity"}
	classScheduledJob   = Class{1006, "Scheduled Job Activity", 1, "System Activity"}
	classNetwork        = Class{4001, "Network Activity", 4, "Network Activity"}
	classDNS            = Class{4003, "DNS Activity", 4, "Network Activity"}
	classFinding        = Class{2001, "Security Finding", 2, "Findings"}
	classBase           = Class{0, "Base Event", 0, "Uncategorized"}
)

// ClassReference lists every OCSF class this parser can emit, for API discovery endpoints.
var ClassReference = []Class{classAuthentication, classProcess, classFile, classScheduledJob, classNetwork, classDNS, classFinding, classBase}

var severityID = map[string]int{
	"Info": 1, "Informational": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5, "Fatal": 6,
}

var severityName = map[int]string{
	0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Fatal", 99: "Other",
}

var statusID = map[string]int{
	"Success": 1, "Failure": 2, "Other": 99, "Unknown": 0,
}

var authActivity = map[string]int{
	"Logon": 1, "Logoff": 2, "Authentication Ticket": 3, "Preauth": 6,
}

var processActivity = map[string]int{
	"Launch": 1, "Terminate": 2, "Open": 3,
}

type winAuthHint struct {
	Activity string
	Status   string
}

var winAuthEventIDs = map[string]winAuthHint{
	"4624": {"Logon", "Success"},
	"4625": {"Logon", "Failure"},
	"4634": {"Logoff", "Success"},
	"4648": {"Logon", "Success"},
	"4672": {"Logon", "Success"},
	"4776": {"Authentication Ticket", "Success"},
}

var winProcessEventIDs = map[string]string{"4688": "Launch", "4689": "Terminate"}
var winNetworkEventIDs = map[string]bool{"5156": true}
var winServiceEventIDs = map[string]bool{"4697": true, "7045": true}
