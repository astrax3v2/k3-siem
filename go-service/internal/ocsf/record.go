package ocsf

import (
	"encoding/json"
	"strings"
	"time"
)

// ParserInfo is the parser metadata stamped onto every normalized Record, mirroring the Node
// `record.parser` shape.
type ParserInfo struct {
	ProfileID   string `json:"profile_id"`
	ProfileName string `json:"profile_name"`
	Family      string `json:"family"`
	Vendor      string `json:"vendor"`
	Product     string `json:"product"`
	DeviceType  string `json:"device_type"`
	Format      string `json:"format"`
}

// Record is the common normalized shape every vendor-specific normalizer produces, matching
// the Node parseLogRecord() return value.
type Record struct {
	Shape        string         `json:"shape"`
	Timestamp    time.Time      `json:"timestamp"`
	Source       string         `json:"source"`
	EventID      string         `json:"event_id"`
	Computer     string         `json:"computer"`
	Username     string         `json:"username"`
	IPAddress    string         `json:"ip_address"`
	DstIPAddress string         `json:"dst_ip_address"`
	Action       string         `json:"action"`
	Severity     string         `json:"severity"`
	Message      string         `json:"message"`
	Outcome      string         `json:"outcome"`
	Raw          string         `json:"raw"`
	IndexName    string         `json:"index_name"`
	Parser       ParserInfo     `json:"parser"`
	Additional   map[string]any `json:"additional,omitempty"`
}

// rawFields is what each vendor normalizer builds before finalizeRecord fills in defaults —
// the Go analogue of the object literal each Node normalizeXxx() passes to finalizeRecord().
type rawFields struct {
	Shape        string
	Timestamp    string
	Source       string
	EventID      string
	Computer     string
	Username     string
	IPAddress    string
	DstIPAddress string
	Action       string
	Severity     string
	Message      string
	Outcome      string
	Raw          string
	IndexName    string
	Additional   map[string]any
}

func finalizeRecord(rf rawFields, profileID string) Record {
	profile := profileByID(profileID)
	parser := ParserInfo{
		ProfileID: profile.ID, ProfileName: profile.Title, Family: profile.Family,
		Vendor: profile.Vendor, Product: profile.Product, DeviceType: profile.DeviceType,
		Format: strings.Join(profile.Formats, ", "),
	}

	shape := rf.Shape
	if shape == "" {
		shape = profile.ID
	}
	source := rf.Source
	if source == "" {
		source = profile.Vendor + " " + profile.Product
	}
	action := rf.Action
	if action == "" {
		action = rf.Message
	}
	message := rf.Message
	if message == "" {
		message = rf.Action
	}
	outcome := rf.Outcome
	if outcome == "" {
		outcome = detectOutcome(action+" "+message, "Unknown")
	}
	indexName := rf.IndexName
	if indexName == "" {
		indexName = inferIndexName(profile.Family)
	}
	additional := rf.Additional
	if additional == nil {
		additional = map[string]any{}
	}

	return Record{
		Shape:        shape,
		Timestamp:    normalizeTimestamp(rf.Timestamp),
		Source:       source,
		EventID:      rf.EventID,
		Computer:     rf.Computer,
		Username:     rf.Username,
		IPAddress:    rf.IPAddress,
		DstIPAddress: rf.DstIPAddress,
		Action:       action,
		Severity:     normalizeSeverity(rf.Severity, "Info"),
		Message:      message,
		Outcome:      outcome,
		Raw:          rf.Raw,
		IndexName:    indexName,
		Parser:       parser,
		Additional:   additional,
	}
}

// parseContext mirrors the Node buildContext(): try to JSON-decode the input, and honor an
// embedded `raw` string field (our own K3-normalized events carry the original raw line this
// way) as the text used for regex-based field extraction.
type parseContext struct {
	RawText         string
	JSON            jsonObj
	EmbeddedRawText string
	Text            string
}

func buildContext(input string) parseContext {
	rawText := strings.TrimSpace(input)
	j := tryParseJSON(rawText)
	embeddedRawText := ""
	if j != nil {
		if rawVal, ok := j["raw"].(string); ok {
			embeddedRawText = strings.TrimSpace(rawVal)
		}
	}
	text := embeddedRawText
	if text == "" {
		text = rawText
	}
	return parseContext{RawText: rawText, JSON: j, EmbeddedRawText: embeddedRawText, Text: text}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
