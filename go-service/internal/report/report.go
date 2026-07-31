// Package report renders an analyzer.Result as JSON (for programmatic consumption) or a
// single self-contained HTML file (inline CSS only, no external assets — so the report opens
// standalone in any browser, including air-gapped machines with no network at all).
package report

import (
	"encoding/json"
	"html/template"
	"io"
	"os"
	"strings"

	"k3siem/goservice/internal/analyzer"
)

// WriteJSON writes result as indented JSON to path.
func WriteJSON(result analyzer.Result, path string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

const htmlTemplateSource = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>K3 SIEM Offline Analysis Report</title>
<style>
  body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .muted { color: #94a3b8; font-size: 13px; }
  .stats { display: flex; gap: 16px; margin: 20px 0; flex-wrap: wrap; }
  .stat { background: #1e293b; border-radius: 8px; padding: 12px 16px; min-width: 120px; }
  .stat .label { font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: .5px; }
  .stat .value { font-size: 22px; font-weight: 700; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }
  th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #1e293b; vertical-align: top; }
  th { color: #94a3b8; text-transform: uppercase; font-size: 10px; letter-spacing: .4px; }
  .excerpt { font-family: Consolas, monospace; color: #cbd5e1; word-break: break-all; max-width: 420px; }
  .osint { color: #90cdf4; max-width: 220px; }
  .sev-critical { color: #fc8181; font-weight: 600; }
  .sev-high { color: #f6ad55; font-weight: 600; }
  .sev-medium { color: #63b3ed; font-weight: 600; }
  .sev-low { color: #68d391; font-weight: 600; }
  .empty { color: #94a3b8; padding: 20px 0; }
</style>
</head>
<body>
  <h1>K3 SIEM — Offline Analysis Report</h1>
  <div class="muted">{{.Input}} &middot; scanned {{.LinesScanned}} lines &middot; {{.StartedAt.Format "2006-01-02 15:04:05 MST"}} &rarr; {{.FinishedAt.Format "15:04:05 MST"}}</div>

  <div class="stats">
    <div class="stat"><div class="label">Lines Scanned</div><div class="value">{{.LinesScanned}}</div></div>
    <div class="stat"><div class="label">Total Hits</div><div class="value">{{len .Hits}}</div></div>
    {{range $sev, $count := .HitsBySeverity}}
    <div class="stat"><div class="label">{{$sev}}</div><div class="value">{{$count}}</div></div>
    {{end}}
  </div>

  {{if .Hits}}
  <table>
    <thead><tr><th>Line</th><th>Type</th><th>Match</th><th>Value</th><th>Severity</th><th>Confidence</th><th>Source</th><th>Description</th><th>OSINT</th><th>Excerpt</th></tr></thead>
    <tbody>
      {{range .Hits}}
      <tr>
        <td>{{.LineNumber}}</td>
        <td>{{.Indicator.Type}}</td>
        <td>{{.MatchType}}</td>
        <td class="excerpt">{{.Indicator.Value}}</td>
        <td class="sev-{{.Indicator.Severity | severityClass}}">{{.Indicator.Severity}}</td>
        <td>{{.Indicator.Confidence}}%</td>
        <td>{{.Indicator.Source}}</td>
        <td>{{.Indicator.Description}}</td>
        <td class="osint">{{osintSummary .}}</td>
        <td class="excerpt">{{.Excerpt}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No indicator matches found in this input.</div>
  {{end}}
</body>
</html>
`

// osintSummary condenses a hit's cached OSINT sources into one short line for the report
// table — a full per-source breakdown is still available in the JSON report for anything that
// needs it programmatically.
func osintSummary(hit analyzer.Hit) string {
	if hit.OSINT == nil {
		return ""
	}
	var parts []string
	if geo, ok := hit.OSINT.Sources["geo"]; ok && geo.Data != nil {
		if m, ok := geo.Data.(map[string]any); ok {
			if country, _ := m["country"].(string); country != "" {
				parts = append(parts, "Geo: "+country)
			}
		}
	}
	for _, name := range []string{"abuseipdb", "virustotal", "shodan"} {
		if src, ok := hit.OSINT.Sources[name]; ok && src.Configured && src.Data != nil {
			parts = append(parts, name+": cached")
		}
	}
	if len(parts) == 0 {
		return "cached (no configured sources)"
	}
	return strings.Join(parts, " · ")
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"severityClass": func(s string) string {
		switch s {
		case "Critical":
			return "critical"
		case "High":
			return "high"
		case "Medium":
			return "medium"
		default:
			return "low"
		}
	},
	"osintSummary": osintSummary,
}).Parse(htmlTemplateSource))

// RenderHTML writes result as a single self-contained HTML document to w — used directly by
// the HTTP API to stream a report without touching disk, and by WriteHTML below for the CLI's
// file-output flag.
func RenderHTML(w io.Writer, result analyzer.Result) error {
	return htmlTemplate.Execute(w, result)
}

// WriteHTML renders result as a single self-contained HTML file at path.
func WriteHTML(result analyzer.Result, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return RenderHTML(f, result)
}
