package main

import (
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed web_paths.json
var embeddedWebPaths []byte

type WebPath struct {
	Path        string   `json:"path"`
	Severity    string   `json:"severity"`
	Signatures  []string `json:"signatures"`
	Description string   `json:"description"`
}

type WebPathSet struct {
	Paths []WebPath `json:"paths"`
}

type WebConfig struct {
	Targets          []string
	Paths            []WebPath
	Rules            *RuleSet
	Workers          int
	Delay            time.Duration
	Timeout          time.Duration
	SkipTLSVerify    bool
	MinSeverity      string
	MaxBodySize      int64
	Proxy            string
	DirectoryListing bool
	UserAgent        string
	JSBundles        bool
}

// defaultUserAgent is used when no -user-agent is supplied. leakprobe never
// sends a self-identifying User-Agent (e.g. "leakprobe/1.0"). That would let
// any WAF or log review instantly flag the traffic as an automated scanner.
const defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

type baselineInfo struct {
	status   int
	length   int
	catchAll bool
	variable bool
}

type webJob struct {
	url      string
	path     WebPath
	baseline baselineInfo
}

func loadWebPaths() (*WebPathSet, error) {
	var set WebPathSet
	if err := json.Unmarshal(embeddedWebPaths, &set); err != nil {
		return nil, err
	}
	return &set, nil
}

// newHTTPClient is shared by web-mode scanning and git-dump mode. Proxy
// (http/socks5), TLS verification skip and a sane redirect cap (5 hops) are
// all defined in one place.
func newHTTPClient(proxy string, skipTLSVerify bool, workers int, timeout time.Duration) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: skipTLSVerify},
		MaxIdleConnsPerHost: workers,
	}
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid -proxy value: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}, nil
}

func ScanWeb(cfg WebConfig) []Finding {
	client, err := newHTTPClient(cfg.Proxy, cfg.SkipTLSVerify, cfg.Workers, cfg.Timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ua := cfg.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}

	baselines := map[string]baselineInfo{}
	for _, t := range cfg.Targets {
		baselines[t] = measureBaseline(client, t, cfg, ua)
	}
	extCache := &extProbeCache{results: map[string]bool{}}

	jobs := make(chan webJob, 256)
	results := make(chan Finding, 256)

	go func() {
		defer close(jobs)
		for _, t := range cfg.Targets {
			for _, p := range cfg.Paths {
				jobs <- webJob{url: t, path: p, baseline: baselines[t]}
			}
		}
	}()

	var workers sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := range jobs {
				scanWebPath(client, j, cfg, ua, extCache, results)
				if cfg.Delay > 0 {
					time.Sleep(cfg.Delay)
				}
			}
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()

	seen := map[string]bool{}
	var findings []Finding
	add := func(f Finding) {
		key := f.Path + "|" + f.RuleID
		if seen[key] {
			return
		}
		seen[key] = true
		if severityOrder[f.Severity] <= severityOrder[cfg.MinSeverity] {
			findings = append(findings, f)
		}
	}
	for f := range results {
		add(f)
	}

	if cfg.DirectoryListing {
		seeds := buildDirSeeds(cfg.Targets)
		dirResults := make(chan Finding, 256)
		go func() {
			defer close(dirResults)
			ScanDirectoryListings(client, seeds, cfg.Rules, cfg.MaxBodySize, ua, dirResults)
		}()
		for f := range dirResults {
			add(f)
		}
	}

	if cfg.JSBundles {
		jsResults := make(chan Finding, 256)
		go func() {
			defer close(jsResults)
			ScanJSBundles(client, cfg.Targets, cfg.Rules, cfg.MaxBodySize, ua, jsResults)
		}()
		for f := range jsResults {
			add(f)
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if severityOrder[findings[i].Severity] != severityOrder[findings[j].Severity] {
			return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
		}
		return findings[i].Path < findings[j].Path
	})
	return findings
}

func measureBaseline(client *http.Client, target string, cfg WebConfig, ua string) baselineInfo {
	s1, b1 := httpGet(client, target+"/leakprobe-no-such-path-4b9x2", cfg.MaxBodySize, ua)
	s2, b2 := httpGet(client, target+"/leakprobe-another-no-such-path-7z3q1a", cfg.MaxBodySize, ua)
	catchAll := s1 == 200 || s2 == 200
	variable := s1 == 200 && s2 == 200 && abs(len(b1)-len(b2)) >= 128
	return baselineInfo{status: s1, length: len(b1), catchAll: catchAll, variable: variable}
}

// extProbeCache remembers, per target+extension, whether a made-up file with
// that extension also comes back as 200. It's shared across the worker pool
// (guarded by a mutex) so the same extension is only probed once per target
// even though many paths can share it.
type extProbeCache struct {
	mu      sync.Mutex
	results map[string]bool
}

// trailingExt returns the extension of a URL path's last segment, e.g.
// "/db.sql.gz" -> ".gz". Empty if the segment has no dot.
func trailingExt(urlPath string) string {
	base := urlPath
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.LastIndex(base, "."); i >= 0 {
		return base[i:]
	}
	return ""
}

// extensionServesJunk checks whether the target serves a made-up file with
// the given extension as 200. Some servers 404 correctly for plain random
// paths but still return a soft-404 page (status 200) for anything that
// LOOKS like a static asset of a given type, a pattern the two generic
// baseline probes in measureBaseline don't catch. This only matters for
// rules with no content signature, since those rely entirely on the status
// code to confirm a finding. The result is cached per target+extension so
// repeated paths sharing an extension only cost one extra request.
func extensionServesJunk(client *http.Client, target, ext string, maxBody int64, ua string, cache *extProbeCache) bool {
	if ext == "" {
		return false
	}
	key := target + ext
	cache.mu.Lock()
	if v, ok := cache.results[key]; ok {
		cache.mu.Unlock()
		return v
	}
	cache.mu.Unlock()

	probeURL := strings.TrimRight(target, "/") + "/leakprobe-junk-8f2a1c" + ext
	status, _ := httpGet(client, probeURL, maxBody, ua)
	result := status == 200

	cache.mu.Lock()
	cache.results[key] = result
	cache.mu.Unlock()
	return result
}

func scanWebPath(client *http.Client, j webJob, cfg WebConfig, ua string, extCache *extProbeCache, results chan<- Finding) {
	fullURL := strings.TrimRight(j.url, "/") + j.path.Path
	status, body := httpGet(client, fullURL, cfg.MaxBodySize, ua)
	if status != 200 || len(body) == 0 {
		return
	}

	secret := findFirstSecret(body, cfg.Rules)
	sigMatched, sig := matchSignature(body, j.path.Signatures)
	looksLikeBaseline := j.baseline.status == 200 && abs(len(body)-j.baseline.length) < 128

	confirmed := false
	evidence := ""
	switch {
	case secret != "":
		confirmed, evidence = true, secret
	case j.baseline.catchAll:
		if !j.baseline.variable && !looksLikeBaseline && sigMatched {
			confirmed, evidence = true, sig
		}
	case sigMatched:
		confirmed, evidence = true, sig
	case len(j.path.Signatures) == 0:
		if !extensionServesJunk(client, j.url, trailingExt(j.path.Path), cfg.MaxBodySize, ua, extCache) {
			confirmed, evidence = true, fmt.Sprintf("200, %d bytes", len(body))
		}
	}
	if !confirmed {
		return
	}

	description := j.path.Description
	if description == "" {
		description = "Sensitive resource reachable via HTTP 200"
	}
	results <- Finding{
		Path:        fullURL,
		RuleID:      "web:" + strings.TrimPrefix(j.path.Path, "/"),
		Description: description,
		Severity:    j.path.Severity,
		Match:       evidence,
	}
}

func httpGet(client *http.Client, target string, max int64, ua string) (int, []byte) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return 0, nil
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, max))
	return resp.StatusCode, body
}

func matchSignature(body []byte, signatures []string) (bool, string) {
	lower := strings.ToLower(string(body))
	for _, sig := range signatures {
		if strings.Contains(lower, strings.ToLower(sig)) {
			return true, sig
		}
	}
	return false, ""
}

func findFirstSecret(body []byte, set *RuleSet) string {
	if set == nil {
		return ""
	}
	for _, r := range set.Rules {
		if r.Type != "content" {
			continue
		}
		for _, re := range r.compiled {
			if loc := re.FindIndex(body); loc != nil {
				return maskMatch(string(body[loc[0]:loc[1]]))
			}
		}
	}
	return ""
}

type contentMatch struct {
	Rule  Rule
	Match string
}

// findAllSecrets, unlike findFirstSecret, returns EVERY matching rule instead
// of stopping at the first one. A single body (e.g. a JS bundle) can carry
// more than one type of secret (an AWS key AND a JWT, for example). Each
// rule is reported at most once even if it has several patterns.
func findAllSecrets(body []byte, set *RuleSet) []contentMatch {
	if set == nil {
		return nil
	}
	var out []contentMatch
	for _, r := range set.Rules {
		if r.Type != "content" {
			continue
		}
		for _, re := range r.compiled {
			if loc := re.FindIndex(body); loc != nil {
				out = append(out, contentMatch{Rule: r, Match: maskMatch(string(body[loc[0]:loc[1]]))})
				break
			}
		}
	}
	return out
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
