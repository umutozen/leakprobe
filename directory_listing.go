package main

import (
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var listingSignatures = []string{
	"<title>index of ",
	">index of /",
	"parent directory</a>",
	`alt="[dir]"`,
}

var hrefPattern = regexp.MustCompile(`(?i)href\s*=\s*["']([^"'#?][^"']*)["']`)

func isDirectoryListing(body []byte) bool {
	lower := strings.ToLower(string(body))
	for _, sig := range listingSignatures {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}

type dirEntry struct {
	URL   string
	IsDir bool
}

// extractLinks resolves the <a href> links on an "Index of /" page and keeps
// only the ones that stay UNDER the current directory (parent-dir links,
// sort-order links, and off-origin links are all filtered out). base must be
// the URL of the listing page itself.
func extractLinks(body []byte, base *url.URL) []dirEntry {
	basePath := base.Path
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}
	seen := map[string]bool{}
	var entries []dirEntry
	for _, m := range hrefPattern.FindAllSubmatch(body, -1) {
		href := string(m[1])
		if href == "" || href == "../" || strings.HasPrefix(href, "?") {
			continue
		}
		lowerHref := strings.ToLower(href)
		if strings.HasPrefix(lowerHref, "mailto:") || strings.HasPrefix(lowerHref, "javascript:") {
			continue
		}
		resolved, err := base.Parse(href)
		if err != nil || resolved.Host != base.Host || resolved.Scheme != base.Scheme {
			continue
		}
		if !strings.HasPrefix(resolved.Path, basePath) || resolved.Path == basePath {
			continue
		}
		resolved.Fragment = ""
		resolved.RawQuery = ""
		key := resolved.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		entries = append(entries, dirEntry{URL: key, IsDir: strings.HasSuffix(resolved.Path, "/")})
	}
	return entries
}

// matchFileRules applies the file-mode name/ext/suffix rules to a URL's
// final path segment: the same rule set, just against a URL instead of a
// filesystem path.
func matchFileRules(urlPath string, set *RuleSet) []Rule {
	if set == nil {
		return nil
	}
	name := strings.ToLower(path.Base(strings.TrimSuffix(urlPath, "/")))
	ext := strings.ToLower(path.Ext(name))
	var matched []Rule
	for _, r := range set.Rules {
		switch r.Type {
		case "name":
			for _, p := range r.Patterns {
				if name == p {
					matched = append(matched, r)
				}
			}
		case "ext":
			for _, p := range r.Patterns {
				if ext == p {
					matched = append(matched, r)
				}
			}
		case "suffix":
			for _, p := range r.Patterns {
				if strings.HasSuffix(name, p) {
					matched = append(matched, r)
				}
			}
		}
	}
	return matched
}

// escalateSeverity: a file found through an OPEN directory listing is worse
// than the same file found by guessing its path. An attacker doesn't need
// to guess anything, they just see it. Severity is bumped one notch.
func escalateSeverity(severity string) string {
	switch severity {
	case SeverityLow:
		return SeverityMedium
	case SeverityMedium:
		return SeverityHigh
	default:
		return severity
	}
}

type dirQueueItem struct {
	URL   string
	Depth int
}

const (
	dirMaxDepth          = 5
	dirMaxRequests       = 250
	dirMaxFilesPerListing = 60
)

// commonDirSeeds are directory names generally known to be at risk of being
// left with listing enabled ("Index of /"). This is general public knowledge,
// not specific to any target; the same fixed seed list is used for every scan.
var commonDirSeeds = []string{
	"/", "/uploads/", "/upload/", "/wp-content/uploads/", "/files/", "/file/",
	"/media/", "/assets/", "/static/", "/data/", "/download/", "/downloads/",
	"/backup/", "/backups/", "/old/", "/archive/", "/archives/", "/tmp/", "/temp/",
	"/logs/", "/log/", "/db/", "/database/", "/export/", "/exports/",
	"/attachments/", "/documents/", "/docs/", "/storage/",
}

// knownPluginBackupPaths exists because directory listing is enabled
// per-directory (Apache "Options +Indexes" / nginx "autoindex on" is NOT
// inherited from the parent). If a plugin creates its own subdirectory and
// forgets to disable listing there, that subdirectory can be wide open even
// while its PARENT (e.g. /wp-content/uploads/) is properly locked down. A
// purely recursive crawl that only follows links from an already-open
// listing would never find that case, because the parent never exposed a
// link to it. This list is tried directly regardless of whether the parent
// is listable. It's general knowledge of common plugin backup locations,
// not target-specific.
var knownPluginBackupPaths = []string{
	"/wp-content/uploads/wp-file-manager-pro/fm_backup/",
	"/wp-content/uploads/ai1wm-backups/",
	"/wp-content/uploads/backup-guard/",
	"/wp-content/uploads/wpvivid-backups/",
	"/wp-content/uploads/updraft/",
	"/wp-content/updraft/",
	"/wp-content/uploads/backupbuddy_backups/",
	"/wp-content/uploads/wp-clone-backup/",
	"/wp-content/uploads/backup/",
	"/wp-content/uploads/backups/",
	"/wp-content/uploads/wp-migrate-db/",
	"/wp-content/wp-db-backup/",
}

func buildDirSeeds(targets []string) []dirQueueItem {
	var seeds []dirQueueItem
	for _, t := range targets {
		base := strings.TrimRight(t, "/")
		for _, p := range commonDirSeeds {
			seeds = append(seeds, dirQueueItem{URL: base + p, Depth: 0})
		}
		for _, p := range knownPluginBackupPaths {
			seeds = append(seeds, dirQueueItem{URL: base + p, Depth: 0})
		}
	}
	return seeds
}

// ScanDirectoryListings starts from the seed URLs, detects open "Index of /"
// pages, recursively follows subdirectory links (bounded depth/request
// budget) and classifies file links against the rule set. Every open
// directory found is reported on its own, even with no interesting files
// inside, since an open listing is a misconfiguration in itself.
func ScanDirectoryListings(client *http.Client, seeds []dirQueueItem, rules *RuleSet, maxBody int64, ua string, results chan<- Finding) {
	seen := map[string]bool{}
	queue := append([]dirQueueItem{}, seeds...)
	requestCount := 0

	for len(queue) > 0 && requestCount < dirMaxRequests {
		item := queue[0]
		queue = queue[1:]
		if seen[item.URL] || item.Depth > dirMaxDepth {
			continue
		}
		seen[item.URL] = true
		requestCount++

		status, body := httpGet(client, item.URL, maxBody, ua)
		if status != 200 || len(body) == 0 || !isDirectoryListing(body) {
			continue
		}
		base, err := url.Parse(item.URL)
		if err != nil {
			continue
		}

		results <- Finding{
			Path:        item.URL,
			RuleID:      "web:directory-listing",
			Description: "Directory listing is open; contents are directly browsable, no filename guessing required",
			Severity:    SeverityMedium,
		}

		fileCount := 0
		for _, e := range extractLinks(body, base) {
			if e.IsDir {
				queue = append(queue, dirQueueItem{URL: e.URL, Depth: item.Depth + 1})
				continue
			}
			if fileCount >= dirMaxFilesPerListing {
				continue
			}
			fileCount++
			for _, r := range matchFileRules(e.URL, rules) {
				results <- Finding{
					Path:        e.URL,
					RuleID:      "web:open-directory:" + r.ID,
					Description: r.Description + " (found directly in an open directory listing)",
					Severity:    escalateSeverity(r.Severity),
				}
			}
		}
	}
}
