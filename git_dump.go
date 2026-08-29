package main

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// fetchGitObject downloads and inflates a loose git object from
// .git/objects/xx/yyyy..., splitting off the "type size\0content" header.
// Only "loose" objects are supported. Once a repo has been through `git gc`,
// objects live packed inside .git/objects/pack/*.pack, and this function does
// not parse the packfile format (delta resolution is a lot more involved and
// was left out of scope).
func fetchGitObject(client *http.Client, baseGitURL, sha string, maxBody int64, ua string) (objType string, content []byte, err error) {
	if len(sha) != 40 {
		return "", nil, fmt.Errorf("invalid sha: %s", sha)
	}
	target := baseGitURL + "objects/" + sha[:2] + "/" + sha[2:]
	status, raw := httpGet(client, target, maxBody, ua)
	if status != 200 || len(raw) == 0 {
		return "", nil, fmt.Errorf("could not fetch object (status %d)", status)
	}
	r, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return "", nil, fmt.Errorf("zlib inflate failed: %w", err)
	}
	defer r.Close()
	full, err := io.ReadAll(r)
	if err != nil {
		return "", nil, err
	}
	space := bytes.IndexByte(full, ' ')
	nul := bytes.IndexByte(full, 0)
	if space < 0 || nul < 0 || nul < space {
		return "", nil, fmt.Errorf("invalid git object header")
	}
	return string(full[:space]), full[nul+1:], nil
}

type gitTreeEntry struct {
	Name string
	SHA  string
	Type string
}

// parseGitTree decodes the binary body of a "tree" object (repeated
// "<mode> <name>\0<20-byte-sha>" records) into a list of entries.
func parseGitTree(content []byte) []gitTreeEntry {
	var entries []gitTreeEntry
	i := 0
	for i < len(content) {
		space := bytes.IndexByte(content[i:], ' ')
		if space < 0 {
			break
		}
		mode := string(content[i : i+space])
		i += space + 1
		nul := bytes.IndexByte(content[i:], 0)
		if nul < 0 {
			break
		}
		name := string(content[i : i+nul])
		i += nul + 1
		if i+20 > len(content) {
			break
		}
		sha := hex.EncodeToString(content[i : i+20])
		i += 20
		entryType := "blob"
		if mode == "40000" || mode == "040000" {
			entryType = "tree"
		}
		entries = append(entries, gitTreeEntry{Name: name, SHA: sha, Type: entryType})
	}
	return entries
}

const gitMaxObjects = 5000

// resolveHeadCommit reads .git/HEAD and finds the commit it points to,
// first via the direct ref file (.git/refs/heads/<branch>), falling back to
// .git/packed-refs if that ref has been packed.
func resolveHeadCommit(client *http.Client, baseGitURL string, maxBody int64, ua string) (string, error) {
	status, headBody := httpGet(client, baseGitURL+"HEAD", maxBody, ua)
	if status != 200 {
		return "", fmt.Errorf(".git/HEAD could not be fetched (status %d)", status)
	}
	head := strings.TrimSpace(string(headBody))

	if len(head) == 40 && !strings.Contains(head, " ") {
		return head, nil // detached HEAD - already a SHA
	}
	if !strings.HasPrefix(head, "ref: ") {
		return "", fmt.Errorf("HEAD has an unexpected format: %q", truncate(head, 60))
	}
	refPath := strings.TrimPrefix(head, "ref: ")

	status, refBody := httpGet(client, baseGitURL+refPath, maxBody, ua)
	if status == 200 {
		if sha := strings.TrimSpace(string(refBody)); len(sha) == 40 {
			return sha, nil
		}
	}
	status, packedBody := httpGet(client, baseGitURL+"packed-refs", maxBody, ua)
	if status == 200 {
		for _, line := range strings.Split(string(packedBody), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasSuffix(line, " "+refPath) && len(line) > 40 {
				return line[:40], nil
			}
		}
	}
	return "", fmt.Errorf("ref (%s) was found neither directly nor in packed-refs", refPath)
}

// ReconstructGitRepo walks .git/HEAD -> ref/packed-refs -> commit -> tree and
// writes every file from that commit into outputDir. Only loose objects are
// supported (see fetchGitObject); if the repo has been packed (hasPackfile
// is true), reconstruction may recover nothing at all.
func ReconstructGitRepo(client *http.Client, targetGitURL, outputDir string, maxBody int64, ua string, log func(string)) (fileCount int, hasPackfile bool, err error) {
	baseGitURL := strings.TrimRight(targetGitURL, "/") + "/"

	commitSHA, err := resolveHeadCommit(client, baseGitURL, maxBody, ua)
	if err != nil {
		return 0, false, err
	}
	log("commit found: " + commitSHA)

	objType, content, err := fetchGitObject(client, baseGitURL, commitSHA, maxBody, ua)
	if err != nil {
		status, _ := httpGet(client, baseGitURL+"objects/pack/", maxBody, ua)
		if status == 200 || status == 403 {
			return 0, true, fmt.Errorf("commit object not found as a loose object (%v); the repo may have been packed by 'git gc', which this tool does not decode", err)
		}
		return 0, false, fmt.Errorf("could not fetch commit object: %w", err)
	}
	if objType != "commit" {
		return 0, false, fmt.Errorf("expected 'commit', got '%s'", objType)
	}

	treeSHA := ""
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "tree ") {
			treeSHA = strings.TrimSpace(strings.TrimPrefix(line, "tree "))
			break
		}
	}
	if treeSHA == "" {
		return 0, false, fmt.Errorf("no tree reference found inside the commit")
	}

	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return 0, false, err
	}

	count := 0
	var walkTree func(sha, relPath string) error
	walkTree = func(sha, relPath string) error {
		if count >= gitMaxObjects {
			return nil
		}
		objType, content, err := fetchGitObject(client, baseGitURL, sha, maxBody, ua)
		if err != nil {
			log("  skipped (tree unreachable): " + relPath)
			return nil
		}
		if objType != "tree" {
			return nil
		}
		for _, e := range parseGitTree(content) {
			if count >= gitMaxObjects {
				return nil
			}
			childPath := filepath.Join(relPath, e.Name)
			if e.Type == "tree" {
				if err := walkTree(e.SHA, childPath); err != nil {
					return err
				}
				continue
			}
			blobType, blobContent, err := fetchGitObject(client, baseGitURL, e.SHA, maxBody, ua)
			if err != nil || blobType != "blob" {
				log("  skipped (file unreachable): " + childPath)
				continue
			}
			outPath := filepath.Join(outputDir, childPath)
			if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
				continue
			}
			if err := os.WriteFile(outPath, blobContent, 0600); err != nil {
				continue
			}
			log("  recovered: " + childPath)
			count++
		}
		return nil
	}
	if err := walkTree(treeSHA, ""); err != nil {
		return count, false, err
	}
	return count, false, nil
}

// runGitDump is the entry point for the -git-dump CLI mode. It is entirely
// separate from the normal scanning flow: a single-target, opt-in command
// the user runs deliberately after a regular scan has already confirmed a
// .git exposure.
func runGitDump(targetGitURL, outputDir, proxy string, skipTLSVerify bool, timeoutSec int, userAgent string) {
	fmt.Fprintln(os.Stderr, "! LEAKPROBE git-dump mode: only use this against targets you own or are authorized to test.")
	fmt.Fprintln(os.Stderr, "  Note: only decodes 'loose' git objects; does not work on repositories packed by 'git gc'.")

	client, err := newHTTPClient(proxy, skipTLSVerify, 1, time.Duration(timeoutSec)*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ua := userAgent
	if ua == "" {
		ua = defaultUserAgent
	}

	fileCount, hasPackfile, err := ReconstructGitRepo(client, targetGitURL, outputDir, 10*1024*1024, ua, func(m string) {
		fmt.Fprintln(os.Stderr, m)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		if hasPackfile {
			fmt.Fprintln(os.Stderr, "  (.git/objects/pack/ was reachable, the repo is packed, this tool can't be used here)")
		}
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "\nDone: %d files recovered into '%s'.\n", fileCount, outputDir)
	if fileCount == 0 {
		os.Exit(1)
	}
}
