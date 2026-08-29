package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

func main() {
	rulesPath := flag.String("rules", "", "Extra/override JSON rules file")
	jsonPath := flag.String("json", "", "JSON report output path")
	htmlPath := flag.String("html", "", "HTML report output path")
	sarifPath := flag.String("sarif", "", "SARIF 2.1.0 report output path (for GitHub Code Scanning / CI)")
	workers := flag.Int("workers", runtime.NumCPU(), "Concurrent workers for file mode")
	maxSize := flag.Int64("max-size", 5*1024*1024, "Upper size limit for content scanning (bytes)")
	minSeverity := flag.String("severity", SeverityInfo, "Minimum severity: CRITICAL|HIGH|MEDIUM|LOW|INFO")
	exclude := flag.String("exclude", "node_modules,vendor,.terraform", "Directory names to skip (comma-separated)")

	url := flag.String("url", "", "Scan a single target URL (example: https://site.com)")
	urlList := flag.String("url-list", "", "File with one URL per line")
	domain := flag.String("domain", "", "Apex domain: subfinder -> httpx -> scan chain")
	subfinderPath := flag.String("subfinder", "subfinder", "Path to the subfinder binary")
	httpxPath := flag.String("httpx", "httpx", "Path to the httpx binary")
	webWorkers := flag.Int("web-workers", 8, "Concurrent requests for web mode")
	delay := flag.Int("delay", 100, "Delay after each request (ms)")
	timeout := flag.Int("timeout", 10, "HTTP request timeout (seconds)")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification")
	proxy := flag.String("proxy", "", "HTTP/SOCKS5 proxy URL (example: socks5://127.0.0.1:8898) - web mode only")
	dirListing := flag.Bool("dir-listing", true, "Find open 'Index of /' directory listings and recurse into them, classifying files")
	jsBundles := flag.Bool("js", true, "Scan the homepage's <script> JS files (and their source maps) for secrets")
	userAgent := flag.String("user-agent", "", "HTTP User-Agent (a realistic default Chrome UA is used if empty) - web mode only")
	gitDump := flag.String("git-dump", "", "URL of an exposed .git directory (example: https://site.com/.git/) - reconstructs the commit tree at HEAD into a local directory")
	gitOutput := flag.String("git-output", "git-dump", "Output directory for -git-dump")
	flag.Parse()

	if *gitDump != "" {
		runGitDump(*gitDump, *gitOutput, *proxy, *insecure, *timeout, *userAgent)
		return
	}

	if _, ok := severityOrder[*minSeverity]; !ok {
		fmt.Fprintf(os.Stderr, "Invalid -severity value: %s\n", *minSeverity)
		os.Exit(2)
	}

	set, err := loadRules(*rulesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to load rules:", err)
		os.Exit(1)
	}

	webMode := *url != "" || *urlList != "" || *domain != ""

	var findings []Finding
	if webMode {
		findings = runWebMode(webModeConfig{
			url: *url, urlList: *urlList, domain: *domain,
			subfinderPath: *subfinderPath, httpxPath: *httpxPath,
			webWorkers: *webWorkers, delay: *delay, timeout: *timeout,
			insecure: *insecure, minSeverity: *minSeverity, rules: set,
			proxy: *proxy, dirListing: *dirListing, userAgent: *userAgent, jsBundles: *jsBundles,
		})
	} else {
		if flag.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "Usage:")
			fmt.Fprintln(os.Stderr, "  File mode : leakprobe [options] <directory>")
			fmt.Fprintln(os.Stderr, "  URL mode  : leakprobe -url https://site.com")
			fmt.Fprintln(os.Stderr, "  Discovery : leakprobe -domain site.com   (requires subfinder+httpx)")
			fmt.Fprintln(os.Stderr, "  Git dump  : leakprobe -git-dump https://site.com/.git/ -git-output ./out")
			flag.PrintDefaults()
			os.Exit(2)
		}
		rootDir := flag.Arg(0)
		fmt.Fprintf(os.Stderr, "LEAKPROBE file scan: %s (%d rules)\n", rootDir, len(set.Rules))
		findings = Scan(Options{
			RootDir: rootDir, Rules: set, Workers: max(*workers, 1),
			MaxSize: *maxSize, MinSeverity: *minSeverity, ExcludeDirs: splitTrim(*exclude),
		})
	}

	consoleReport(findings)

	if *jsonPath != "" {
		if err := writeJSONReport(findings, *jsonPath); err != nil {
			fmt.Fprintln(os.Stderr, "JSON report error:", err)
		} else {
			fmt.Fprintln(os.Stderr, "JSON report:", *jsonPath)
		}
	}
	if *sarifPath != "" {
		if err := writeSARIFReport(findings, *sarifPath); err != nil {
			fmt.Fprintln(os.Stderr, "SARIF report error:", err)
		} else {
			fmt.Fprintln(os.Stderr, "SARIF report:", *sarifPath)
		}
	}
	if *htmlPath != "" {
		if err := writeHTMLReport(findings, *htmlPath); err != nil {
			fmt.Fprintln(os.Stderr, "HTML report error:", err)
		} else {
			fmt.Fprintln(os.Stderr, "HTML report:", *htmlPath)
		}
	}

	if summarize(findings)[SeverityCritical] > 0 {
		os.Exit(3)
	}
}

type webModeConfig struct {
	url, urlList, domain      string
	subfinderPath, httpxPath  string
	webWorkers, delay, timeout int
	insecure                  bool
	minSeverity               string
	rules                     *RuleSet
	proxy                     string
	dirListing                bool
	userAgent                 string
	jsBundles                 bool
}

func runWebMode(c webModeConfig) []Finding {
	fmt.Fprintln(os.Stderr, "! LEAKPROBE web mode: only use this against targets you own or are authorized to test.")

	var targets []string
	switch {
	case c.domain != "":
		fmt.Fprintf(os.Stderr, "Discovering: subfinder -d %s ...\n", c.domain)
		subs, err := discoverSubdomains(c.domain, c.subfinderPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		subs = append(subs, c.domain)
		fmt.Fprintf(os.Stderr, "%d subdomains found, probing with httpx ...\n", len(subs))
		live, err := liveHosts(subs, c.httpxPath, c.insecure)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		targets = live
		fmt.Fprintf(os.Stderr, "%d live hosts.\n", len(targets))
	case c.urlList != "":
		targets = readLines(c.urlList)
	default:
		targets = []string{c.url}
	}

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "No live targets to scan.")
		return nil
	}

	pathSet, err := loadWebPaths()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to load web path list:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "%d target(s) x %d path(s) being scanned (%d workers) ...\n",
		len(targets), len(pathSet.Paths), c.webWorkers)

	return ScanWeb(WebConfig{
		Targets:          targets,
		Paths:            pathSet.Paths,
		Rules:            c.rules,
		Workers:          max(c.webWorkers, 1),
		Delay:            time.Duration(c.delay) * time.Millisecond,
		Timeout:          time.Duration(c.timeout) * time.Second,
		SkipTLSVerify:    c.insecure,
		MinSeverity:      c.minSeverity,
		MaxBodySize:      512 * 1024,
		Proxy:            c.proxy,
		DirectoryListing: c.dirListing,
		UserAgent:        c.userAgent,
		JSBundles:        c.jsBundles,
	})
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not open file:", err)
		os.Exit(1)
	}
	defer f.Close()
	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		s := strings.TrimSpace(scanner.Text())
		if s != "" && !strings.HasPrefix(s, "#") {
			out = append(out, s)
		}
	}
	return out
}

func splitTrim(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
