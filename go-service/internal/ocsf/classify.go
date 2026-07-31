package ocsf

import (
	"fmt"
	"regexp"
)

type classification struct {
	Class
	ActivityName string
	ActivityID   int
	Status       string
}

var (
	authKeywordsRe    = regexp.MustCompile(`(?i)logon|login|logoff|logout|password|publickey|authentication|sudo|su `)
	authLogoffRe      = regexp.MustCompile(`(?i)logoff|logout`)
	authFailRe        = regexp.MustCompile(`(?i)fail|invalid|denied`)
	authSudoRe        = regexp.MustCompile(`(?i)sudo|su `)
	processKeywordsRe = regexp.MustCompile(`(?i)process|exec|launch|started|spawned|terminated`)
	processTermRe     = regexp.MustCompile(`(?i)terminate|terminated|exit`)
	scheduledJobRe    = regexp.MustCompile(`(?i)cron|systemd|service install|scheduled`)
	fileActivityRe    = regexp.MustCompile(`(?i)file |open |read |write |delete `)
	dnsRe             = regexp.MustCompile(`(?i)dns`)
	findingRe         = regexp.MustCompile(`(?i)threat|attack|malware|spyware|virus|exploit|scan|sql|xss|blocked|deny|drop`)
	networkDenyRe     = regexp.MustCompile(`(?i)deny|denied|block|blocked|drop|rejected|reset`)
	emailFindingRe    = regexp.MustCompile(`(?i)spam|phish|phishing|malware|virus|quarantine|reject|blocked`)
	emailSendRe       = regexp.MustCompile(`(?i)send|deliver|relay`)
)

// classifyRecord maps a normalized Record onto an OCSF class + activity, mirroring the Node
// classifyRecord() decision tree (event-ID hints first, then family-specific keyword rules,
// falling back to a generic Base Event).
func classifyRecord(rec Record) classification {
	action := rec.Action + " " + rec.Message
	eid := rec.EventID
	family := rec.Parser.Family

	if hint, ok := winAuthEventIDs[eid]; ok {
		return classification{Class: classAuthentication, ActivityName: hint.Activity, ActivityID: authActivityID(hint.Activity), Status: hint.Status}
	}
	if activity, ok := winProcessEventIDs[eid]; ok {
		return classification{Class: classProcess, ActivityName: activity, ActivityID: processActivityID(activity), Status: "Success"}
	}
	if winNetworkEventIDs[eid] {
		return classification{Class: classNetwork, ActivityName: "Traffic", ActivityID: 6, Status: "Success"}
	}
	if winServiceEventIDs[eid] {
		return classification{Class: classScheduledJob, ActivityName: "Create", ActivityID: 1, Status: "Success"}
	}

	if family == "firewall" || family == "waf" || family == "generic_network" {
		if dnsRe.MatchString(action) {
			return classification{Class: classDNS, ActivityName: "Query", ActivityID: 1, Status: detectOutcome(action, "Unknown")}
		}
		if findingRe.MatchString(action) {
			return classification{Class: classFinding, ActivityName: "Create", ActivityID: 1, Status: detectOutcome(action, "Unknown")}
		}
		denied := networkDenyRe.MatchString(action)
		activityName, activityID := "Allow", 1
		if denied {
			activityName, activityID = "Deny", 2
		}
		status := rec.Outcome
		if status == "" {
			if denied {
				status = "Failure"
			} else {
				status = "Success"
			}
		}
		return classification{Class: classNetwork, ActivityName: activityName, ActivityID: activityID, Status: status}
	}

	if family == "email" || family == "email_security_gateway" {
		if emailFindingRe.MatchString(action) {
			return classification{Class: classFinding, ActivityName: "Create", ActivityID: 1, Status: detectOutcome(action, "Unknown")}
		}
		activityName, activityID := "Traffic", 6
		if emailSendRe.MatchString(action) {
			activityName, activityID = "Allow", 1
		}
		status := rec.Outcome
		if status == "" {
			status = "Success"
		}
		return classification{Class: classNetwork, ActivityName: activityName, ActivityID: activityID, Status: status}
	}

	if family == "linux" || family == "aix" || family == "windows" {
		if authKeywordsRe.MatchString(action) {
			isLogoff := authLogoffRe.MatchString(action)
			failed := authFailRe.MatchString(action) || rec.Outcome == "Failure"
			activityName := "Logon"
			activityID := 1
			switch {
			case isLogoff:
				activityName, activityID = "Logoff", 2
			case authSudoRe.MatchString(action):
				activityName, activityID = "Authentication Ticket", 3
			}
			status := "Success"
			if failed {
				status = "Failure"
			}
			return classification{Class: classAuthentication, ActivityName: activityName, ActivityID: activityID, Status: status}
		}
		if processKeywordsRe.MatchString(action) {
			terminate := processTermRe.MatchString(action)
			activityName, activityID := "Launch", 1
			if terminate {
				activityName, activityID = "Terminate", 2
			}
			return classification{Class: classProcess, ActivityName: activityName, ActivityID: activityID, Status: "Success"}
		}
		if scheduledJobRe.MatchString(action) {
			return classification{Class: classScheduledJob, ActivityName: "Create", ActivityID: 1, Status: "Success"}
		}
		if fileActivityRe.MatchString(action) {
			status := rec.Outcome
			if status == "" {
				status = "Success"
			}
			return classification{Class: classFile, ActivityName: "Read", ActivityID: 1, Status: status}
		}
	}

	status := rec.Outcome
	if status == "" {
		status = "Unknown"
	}
	return classification{Class: classBase, ActivityName: "Unknown", ActivityID: 0, Status: status}
}

func authActivityID(name string) int {
	if id, ok := authActivity[name]; ok {
		return id
	}
	return 99
}

func processActivityID(name string) int {
	if id, ok := processActivity[name]; ok {
		return id
	}
	return 99
}

// Observable is one extracted field of interest, matching the Node buildObservables() shape.
type Observable struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

func buildObservables(rec Record) []Observable {
	var out []Observable
	if rec.IPAddress != "" {
		out = append(out, Observable{Name: "src_endpoint.ip", Type: "IP Address", Value: rec.IPAddress})
	}
	if rec.DstIPAddress != "" {
		out = append(out, Observable{Name: "dst_endpoint.ip", Type: "IP Address", Value: rec.DstIPAddress})
	}
	if rec.Username != "" {
		out = append(out, Observable{Name: "actor.user.name", Type: "User Name", Value: rec.Username})
	}
	if rec.Computer != "" {
		out = append(out, Observable{Name: "device.hostname", Type: "Hostname", Value: rec.Computer})
	}
	return out
}

// Actor/Endpoint/Device/Metadata/Event mirror the nested OCSF JSON shape the Node toOCSF()
// produces — omitempty on the optional nested objects matches Node's `undefined` fields being
// dropped from the JSON.stringify output.
type Actor struct {
	User struct {
		Name string `json:"name"`
	} `json:"user"`
}

type Endpoint struct {
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

type Device struct {
	Hostname string `json:"hostname,omitempty"`
	Type     string `json:"type,omitempty"`
}

type Product struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
}

type Metadata struct {
	Version        string     `json:"version"`
	Product        Product    `json:"product"`
	LogName        string     `json:"log_name"`
	OriginalFormat string     `json:"original_format"`
	Parser         ParserInfo `json:"parser"`
}

type Unmapped struct {
	Source        string         `json:"source"`
	EventID       string         `json:"event_id"`
	IndexName     string         `json:"index_name"`
	ParserProfile string         `json:"parser_profile"`
	Additional    map[string]any `json:"additional,omitempty"`
}

// Event is the OCSF 1.3.0-shaped record produced from a Record, matching the Node toOCSF()
// output field-for-field.
type Event struct {
	ActivityID   int          `json:"activity_id"`
	ActivityName string       `json:"activity_name"`
	CategoryUID  int          `json:"category_uid"`
	CategoryName string       `json:"category_name"`
	ClassUID     int          `json:"class_uid"`
	ClassName    string       `json:"class_name"`
	TypeUID      int          `json:"type_uid"`
	TypeName     string       `json:"type_name"`
	Time         int64        `json:"time"`
	TimeISO      string       `json:"time_iso"`
	SeverityID   int          `json:"severity_id"`
	Severity     string       `json:"severity"`
	StatusID     int          `json:"status_id"`
	Status       string       `json:"status"`
	Message      string       `json:"message"`
	Metadata     Metadata     `json:"metadata"`
	Actor        *Actor       `json:"actor,omitempty"`
	SrcEndpoint  *Endpoint    `json:"src_endpoint,omitempty"`
	DstEndpoint  *Endpoint    `json:"dst_endpoint,omitempty"`
	Device       *Device      `json:"device,omitempty"`
	Observables  []Observable `json:"observables"`
	RawData      string       `json:"raw_data"`
	Unmapped     Unmapped     `json:"unmapped"`
}

// ToOCSF maps a normalized Record onto the OCSF 1.3.0 event shape, mirroring the Node toOCSF().
func ToOCSF(rec Record) Event {
	cls := classifyRecord(rec)
	sevID := severityID[rec.Severity]
	stID := statusID[cls.Status]
	timeMs := rec.Timestamp.UnixMilli()
	typeUID := cls.ClassUID*100 + cls.ActivityID

	var actor *Actor
	if rec.Username != "" {
		actor = &Actor{}
		actor.User.Name = rec.Username
	}
	var src *Endpoint
	if rec.IPAddress != "" || rec.Computer != "" {
		src = &Endpoint{IP: rec.IPAddress, Hostname: rec.Computer}
	}
	var dst *Endpoint
	if rec.DstIPAddress != "" {
		dst = &Endpoint{IP: rec.DstIPAddress}
	}
	var device *Device
	if rec.Computer != "" {
		device = &Device{Hostname: rec.Computer, Type: rec.Parser.DeviceType}
	}

	return Event{
		ActivityID:   cls.ActivityID,
		ActivityName: cls.ActivityName,
		CategoryUID:  cls.CategoryUID,
		CategoryName: cls.CategoryName,
		ClassUID:     cls.ClassUID,
		ClassName:    cls.ClassName,
		TypeUID:      typeUID,
		TypeName:     fmt.Sprintf("%s: %s", cls.ClassName, cls.ActivityName),
		Time:         timeMs,
		TimeISO:      rec.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z"),
		SeverityID:   sevID,
		Severity:     severityName[sevID],
		StatusID:     stID,
		Status:       cls.Status,
		Message:      firstNonEmpty(rec.Message, rec.Action),
		Metadata: Metadata{
			Version:        Version,
			Product:        Product{Name: orDefault(rec.Parser.Product, "K3 Parsing Engine"), VendorName: orDefault(rec.Parser.Vendor, "K3")},
			LogName:        rec.Source,
			OriginalFormat: rec.Shape,
			Parser:         rec.Parser,
		},
		Actor:       actor,
		SrcEndpoint: src,
		DstEndpoint: dst,
		Device:      device,
		Observables: buildObservables(rec),
		RawData:     rec.Raw,
		Unmapped: Unmapped{
			Source:        rec.Source,
			EventID:       rec.EventID,
			IndexName:     rec.IndexName,
			ParserProfile: rec.Parser.ProfileID,
			Additional:    rec.Additional,
		},
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// ParseToOCSF parses one log line and maps it directly to an OCSF Event, matching the Node
// parseToOCSF() convenience wrapper.
func ParseToOCSF(input string) Event {
	return ToOCSF(ParseLogRecord(input))
}
