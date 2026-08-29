package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	archiveEntrySizeMax  = 50 * 1024 * 1024
	archiveTotalSizeMax  = 500 * 1024 * 1024
	archiveEntryCountMax = 5000
	archiveDepthMax      = 2
)

type archiveBudget struct {
	remainingBytes   int64
	remainingEntries int
}

func detectArchiveType(name string) string {
	switch {
	case strings.HasSuffix(name, ".zip"):
		return "zip"
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"):
		return "targz"
	case strings.HasSuffix(name, ".tar"):
		return "tar"
	case strings.HasSuffix(name, ".gz"):
		return "gz"
	}
	return ""
}

func scanArchive(path, archiveType string, opt Options, results chan<- Finding) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	budget := &archiveBudget{remainingBytes: archiveTotalSizeMax, remainingEntries: archiveEntryCountMax}

	switch archiveType {
	case "zip":
		info, err := f.Stat()
		if err != nil {
			return
		}
		walkZip(path, f, info.Size(), opt, results, 0, budget)
	case "tar":
		walkTar(path, f, opt, results, 0, budget)
	case "targz":
		gr, err := gzip.NewReader(f)
		if err != nil {
			return
		}
		defer gr.Close()
		walkTar(path, gr, opt, results, 0, budget)
	case "gz":
		gr, err := gzip.NewReader(f)
		if err != nil {
			return
		}
		defer gr.Close()
		scanGzip(path, strings.TrimSuffix(filepath.Base(path), ".gz"), gr, opt, results, 0, budget)
	}
}

func scanArchiveContent(label, archiveType string, data []byte, opt Options, results chan<- Finding, depth int, budget *archiveBudget) {
	switch archiveType {
	case "zip":
		walkZip(label, bytes.NewReader(data), int64(len(data)), opt, results, depth, budget)
	case "tar":
		walkTar(label, bytes.NewReader(data), opt, results, depth, budget)
	case "targz":
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return
		}
		defer gr.Close()
		walkTar(label, gr, opt, results, depth, budget)
	case "gz":
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return
		}
		defer gr.Close()
		scanGzip(label, strings.TrimSuffix(path.Base(label), ".gz"), gr, opt, results, depth, budget)
	}
}

func walkZip(label string, ra io.ReaderAt, size int64, opt Options, results chan<- Finding, depth int, budget *archiveBudget) {
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return
	}
	for _, f := range zr.File {
		if budget.remainingEntries <= 0 || budget.remainingBytes <= 0 {
			return
		}
		if f.FileInfo().IsDir() {
			continue
		}
		budget.remainingEntries--
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, _ := readLimited(rc, min(int64(archiveEntrySizeMax), budget.remainingBytes))
		rc.Close()
		budget.remainingBytes -= int64(len(data))
		inspectEntry(label, f.Name, data, opt, results, depth, budget)
	}
}

func walkTar(label string, r io.Reader, opt Options, results chan<- Finding, depth int, budget *archiveBudget) {
	tr := tar.NewReader(r)
	for {
		if budget.remainingEntries <= 0 || budget.remainingBytes <= 0 {
			return
		}
		h, err := tr.Next()
		if err != nil {
			return
		}
		if h.FileInfo().IsDir() {
			continue
		}
		budget.remainingEntries--
		data, _ := readLimited(tr, min(int64(archiveEntrySizeMax), budget.remainingBytes))
		budget.remainingBytes -= int64(len(data))
		inspectEntry(label, h.Name, data, opt, results, depth, budget)
	}
}

func scanGzip(label, innerName string, r io.Reader, opt Options, results chan<- Finding, depth int, budget *archiveBudget) {
	if budget.remainingBytes <= 0 {
		return
	}
	data, _ := readLimited(r, min(int64(archiveEntrySizeMax), budget.remainingBytes))
	budget.remainingBytes -= int64(len(data))
	budget.remainingEntries--
	inspectEntry(label, innerName, data, opt, results, depth, budget)
}

func inspectEntry(outerLabel, innerPath string, data []byte, opt Options, results chan<- Finding, depth int, budget *archiveBudget) {
	clean := strings.ReplaceAll(innerPath, "\\", "/")
	location := outerLabel + " -> " + clean
	name := strings.ToLower(path.Base(clean))

	applyNameRules(location, name, opt.Rules, results)
	applyContentRules(location, data, opt.Rules, results)

	if depth+1 <= archiveDepthMax {
		if archiveType := detectArchiveType(name); archiveType != "" {
			scanArchiveContent(location, archiveType, data, opt, results, depth+1, budget)
		}
	}
}

func readLimited(r io.Reader, max int64) ([]byte, bool) {
	if max < 0 {
		max = 0
	}
	data, _ := io.ReadAll(io.LimitReader(r, max+1))
	truncated := int64(len(data)) > max
	if truncated {
		data = data[:max]
	}
	return data, truncated
}
