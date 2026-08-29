package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type Finding struct {
	Path        string `json:"path"`
	RuleID      string `json:"rule"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Line        int    `json:"line,omitempty"`
	Match       string `json:"match,omitempty"`
}

type Options struct {
	RootDir      string
	Rules        *RuleSet
	Workers      int
	MaxSize      int64
	MinSeverity  string
	ExcludeDirs  []string
}

func Scan(opt Options) []Finding {
	jobs := make(chan string, 512)
	results := make(chan Finding, 512)

	var producer sync.WaitGroup
	producer.Add(1)
	go func() {
		defer producer.Done()
		defer close(jobs)
		walkErr := filepath.WalkDir(opt.RootDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			name := strings.ToLower(d.Name())
			if d.IsDir() {
				if shouldSkipDir(name, opt.ExcludeDirs) {
					return filepath.SkipDir
				}
				applyDirRules(path, name, opt.Rules, results)
				return nil
			}
			jobs <- path
			return nil
		})
		if walkErr != nil {
			fmt.Fprintln(os.Stderr, "Failed to walk directory:", walkErr)
		}
	}()

	var workers sync.WaitGroup
	for i := 0; i < opt.Workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for path := range jobs {
				scanFile(path, opt, results)
			}
		}()
	}

	go func() {
		producer.Wait()
		workers.Wait()
		close(results)
	}()

	seen := map[string]bool{}
	var findings []Finding
	for f := range results {
		key := f.Path + "|" + f.RuleID
		if seen[key] {
			continue
		}
		seen[key] = true
		if severityOrder[f.Severity] <= severityOrder[opt.MinSeverity] {
			findings = append(findings, f)
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

func shouldSkipDir(name string, exclude []string) bool {
	for _, e := range exclude {
		if name == strings.ToLower(e) {
			return true
		}
	}
	return false
}

func applyDirRules(path, name string, set *RuleSet, results chan<- Finding) {
	for _, r := range set.Rules {
		if r.Type != "dir" {
			continue
		}
		for _, p := range r.Patterns {
			if name == p {
				results <- Finding{Path: path, RuleID: r.ID, Description: r.Description, Severity: r.Severity}
			}
		}
	}
}

func scanFile(path string, opt Options, results chan<- Finding) {
	name := strings.ToLower(filepath.Base(path))
	needsContent := applyNameRules(path, name, opt.Rules, results)

	if archiveType := detectArchiveType(name); archiveType != "" {
		scanArchive(path, archiveType, opt, results)
	}

	if !needsContent {
		return
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 || info.Size() > opt.MaxSize {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	applyContentRules(path, data, opt.Rules, results)
}

func newFinding(location string, r Rule) Finding {
	return Finding{Path: location, RuleID: r.ID, Description: r.Description, Severity: r.Severity}
}

func applyNameRules(location, name string, set *RuleSet, results chan<- Finding) bool {
	ext := strings.ToLower(filepath.Ext(name))
	needsContent := false
	for _, r := range set.Rules {
		switch r.Type {
		case "name":
			for _, p := range r.Patterns {
				if name == p {
					results <- newFinding(location, r)
				}
			}
		case "ext":
			for _, p := range r.Patterns {
				if ext == p {
					results <- newFinding(location, r)
				}
			}
		case "suffix":
			for _, p := range r.Patterns {
				if strings.HasSuffix(name, p) {
					results <- newFinding(location, r)
				}
			}
		case "content":
			needsContent = true
		}
	}
	return needsContent
}

func applyContentRules(location string, data []byte, set *RuleSet, results chan<- Finding) {
	if bytes.IndexByte(data, 0) != -1 {
		return
	}
	for _, r := range set.Rules {
		if r.Type != "content" {
			continue
		}
		for _, re := range r.compiled {
			idx := re.FindIndex(data)
			if idx == nil {
				continue
			}
			f := newFinding(location, r)
			f.Line = bytes.Count(data[:idx[0]], []byte("\n")) + 1
			f.Match = maskMatch(string(data[idx[0]:idx[1]]))
			results <- f
		}
	}
}

func maskMatch(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		s = s[:80]
	}
	r := []rune(s)
	if len(r) <= 8 {
		return s
	}
	return string(r[:4]) + strings.Repeat("*", 6) + string(r[len(r)-4:])
}
