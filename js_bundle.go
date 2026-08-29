package main

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var scriptSrcPattern = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)
var sourceMapPattern = regexp.MustCompile(`//[#@]\s*sourceMappingURL=([^\s]+)`)

const jsBundleMaxFiles = 40

// extractScriptLinks resolves the <script src="..."> links on an HTML page
// and returns only the ones on the SAME origin. No requests are made to a
// third-party CDN or origin, which keeps things in scope.
func extractScriptLinks(body []byte, base *url.URL) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range scriptSrcPattern.FindAllSubmatch(body, -1) {
		src := string(m[1])
		if src == "" || strings.HasPrefix(strings.ToLower(src), "data:") {
			continue
		}
		resolved, err := base.Parse(src)
		if err != nil || resolved.Host != base.Host || resolved.Scheme != base.Scheme {
			continue
		}
		resolved.Fragment = ""
		key := resolved.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}

// sourceMapURL resolves the "//# sourceMappingURL=..." comment at the end of
// a JS file. Source maps often embed the ORIGINAL, uncompiled source, comments
// included, so they can leak far more than the bundle itself.
func sourceMapURL(body []byte, jsURL *url.URL) string {
	m := sourceMapPattern.FindSubmatch(body)
	if m == nil {
		return ""
	}
	raw := string(m[1])
	if strings.HasPrefix(raw, "data:") {
		return ""
	}
	resolved, err := jsURL.Parse(raw)
	if err != nil || resolved.Host != jsURL.Host {
		return ""
	}
	return resolved.String()
}

// ScanJSBundles fetches each target's homepage, finds same-origin <script>
// files, downloads them and scans the content for secret patterns. If a
// source map is referenced, it is fetched and scanned too. API keys and
// secrets usually don't leak in raw HTML, they leak in compiled JS bundles.
func ScanJSBundles(client *http.Client, targets []string, rules *RuleSet, maxBody int64, ua string, results chan<- Finding) {
	seen := map[string]bool{}
	for _, t := range targets {
		base, err := url.Parse(strings.TrimRight(t, "/") + "/")
		if err != nil {
			continue
		}
		status, body := httpGet(client, base.String(), maxBody, ua)
		if status != 200 || len(body) == 0 {
			continue
		}
		links := extractScriptLinks(body, base)
		if len(links) > jsBundleMaxFiles {
			links = links[:jsBundleMaxFiles]
		}
		for _, jsRaw := range links {
			if seen[jsRaw] {
				continue
			}
			seen[jsRaw] = true
			jsURL, err := url.Parse(jsRaw)
			if err != nil {
				continue
			}
			jsStatus, jsBody := httpGet(client, jsRaw, maxBody, ua)
			if jsStatus != 200 || len(jsBody) == 0 {
				continue
			}
			for _, m := range findAllSecrets(jsBody, rules) {
				results <- Finding{
					Path:        jsRaw,
					RuleID:      "web:js-bundle:" + m.Rule.ID,
					Description: m.Rule.Description + " (found in a compiled JS file)",
					Severity:    m.Rule.Severity,
					Match:       m.Match,
				}
			}
			mapURL := sourceMapURL(jsBody, jsURL)
			if mapURL == "" || seen[mapURL] {
				continue
			}
			seen[mapURL] = true
			mapStatus, mapBody := httpGet(client, mapURL, maxBody, ua)
			if mapStatus != 200 || len(mapBody) == 0 {
				continue
			}
			results <- Finding{
				Path:        mapURL,
				RuleID:      "web:source-map-exposed",
				Description: "Source map (.map) file is reachable; uncompiled original code, including comments, may leak",
				Severity:    SeverityMedium,
			}
			for _, m := range findAllSecrets(mapBody, rules) {
				results <- Finding{
					Path:        mapURL,
					RuleID:      "web:js-bundle:" + m.Rule.ID,
					Description: m.Rule.Description + " (found in a source map .map file)",
					Severity:    m.Rule.Severity,
					Match:       m.Match,
				}
			}
		}
	}
}
