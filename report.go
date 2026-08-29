package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
)

func summarize(findings []Finding) map[string]int {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

func consoleReport(findings []Finding) {
	colors := map[string]string{
		SeverityCritical: "\033[1;31m",
		SeverityHigh:     "\033[1;33m",
		SeverityMedium:   "\033[1;36m",
		SeverityLow:      "\033[0;37m",
		SeverityInfo:     "\033[0;90m",
	}
	reset := "\033[0m"

	fmt.Printf("\n%-9s %-26s %-45s %s\n", "SEVERITY", "RULE", "LOCATION", "DETAIL")
	fmt.Println(strings.Repeat("-", 120))
	for _, f := range findings {
		loc := f.Path
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
		}
		detail := f.Description
		if f.Match != "" {
			detail = f.Match + " - " + f.Description
		}
		fmt.Printf("%s%-9s%s %-26s %-45s %s\n",
			colors[f.Severity], f.Severity, reset, f.RuleID, truncate(loc, 45), detail)
	}

	s := summarize(findings)
	fmt.Println(strings.Repeat("-", 120))
	fmt.Printf("Total %d findings | CRITICAL:%d HIGH:%d MEDIUM:%d LOW:%d INFO:%d\n\n",
		len(findings), s[SeverityCritical], s[SeverityHigh], s[SeverityMedium], s[SeverityLow], s[SeverityInfo])
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return "..." + string(r[len(r)-(n-3):])
}

func writeJSONReport(findings []Finding, path string) error {
	out := map[string]any{
		"summary":  summarize(findings),
		"total":    len(findings),
		"findings": findings,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

const htmlTemplate = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>LEAKPROBE Report</title><style>
body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;margin:0;padding:24px}
h1{font-size:20px}.summary{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.card{padding:12px 16px;border-radius:8px;background:#1b1e26;min-width:90px}
.card b{display:block;font-size:22px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #262a33;vertical-align:top}
th{color:#9aa0ab;font-weight:600}
.badge{padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700}
.CRITICAL{background:#5b1a1a;color:#ff9b9b}.HIGH{background:#5b4a1a;color:#ffe08a}
.MEDIUM{background:#1a445b;color:#8fd6ff}.LOW{background:#2a2f3a;color:#cfd4dd}.INFO{background:#22262e;color:#8b909b}
code{color:#9aa0ab;word-break:break-all}
</style></head><body>
<h1>LEAKPROBE: Sensitive File / Data Exposure Report</h1>
<div class="summary">
<div class="card"><b>{{.Total}}</b>Total</div>
<div class="card"><b>{{index .Summary "CRITICAL"}}</b>Critical</div>
<div class="card"><b>{{index .Summary "HIGH"}}</b>High</div>
<div class="card"><b>{{index .Summary "MEDIUM"}}</b>Medium</div>
<div class="card"><b>{{index .Summary "LOW"}}</b>Low</div>
<div class="card"><b>{{index .Summary "INFO"}}</b>Info</div>
</div>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Detail</th></tr></thead><tbody>
{{range .Findings}}<tr>
<td><span class="badge {{.Severity}}">{{.Severity}}</span></td>
<td>{{.RuleID}}</td>
<td><code>{{.Path}}{{if .Line}}:{{.Line}}{{end}}</code></td>
<td>{{if .Match}}<code>{{.Match}}</code> - {{end}}{{.Description}}</td>
</tr>{{end}}
</tbody></table></body></html>`

func writeHTMLReport(findings []Finding, path string) error {
	t, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return t.Execute(f, map[string]any{
		"Total":    len(findings),
		"Summary":  summarize(findings),
		"Findings": findings,
	})
}

// sarifLevel maps our severity scale to SARIF's error/warning/note levels.
// GitHub Code Scanning and other CI integrations filter/color by this.
func sarifLevel(severity string) string {
	switch severity {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// sarifURI turns a finding's location into a valid SARIF artifactLocation.uri.
// Web findings already start with http(s):// (used as-is); file-mode findings
// carry a local filesystem path and get a file:// prefix (backslashes normalized).
func sarifURI(path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "file://") {
		return path
	}
	clean := strings.ReplaceAll(path, `\`, "/")
	if !strings.HasPrefix(clean, "/") {
		clean = "/" + clean
	}
	return "file://" + clean
}

type sarifRule struct {
	ID    string
	Title string
}

func writeSARIFReport(findings []Finding, path string) error {
	seenRules := map[string]bool{}
	var rules []sarifRule
	var results []map[string]any

	for _, f := range findings {
		if !seenRules[f.RuleID] {
			seenRules[f.RuleID] = true
			title := f.Description
			if title == "" {
				title = f.RuleID
			}
			rules = append(rules, sarifRule{ID: f.RuleID, Title: title})
		}

		region := map[string]any{}
		if f.Line > 0 {
			region["startLine"] = f.Line
		}
		location := map[string]any{
			"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": sarifURI(f.Path)},
			},
		}
		if len(region) > 0 {
			location["physicalLocation"].(map[string]any)["region"] = region
		}

		message := f.Description
		if f.Match != "" {
			message = f.Description + " (match: " + f.Match + ")"
		}

		results = append(results, map[string]any{
			"ruleId":    f.RuleID,
			"level":     sarifLevel(f.Severity),
			"message":   map[string]any{"text": message},
			"locations": []any{location},
		})
	}

	var sarifRules []map[string]any
	for _, r := range rules {
		sarifRules = append(sarifRules, map[string]any{
			"id":               r.ID,
			"shortDescription": map[string]any{"text": r.Title},
		})
	}
	if results == nil {
		results = []map[string]any{}
	}
	if sarifRules == nil {
		sarifRules = []map[string]any{}
	}

	out := map[string]any{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":  "leakprobe",
						"rules": sarifRules,
					},
				},
				"results": results,
			},
		},
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
