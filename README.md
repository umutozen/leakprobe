# leakprobe

**A single Go binary for finding sensitive files, secrets, and exposed data, both on disk and on a live web target.**

leakprobe checks a target for the things that actually leak in the real world: `.env` files, database dumps, cloud credentials, backup copies of source code, open `.git` directories, secrets baked into compiled JS bundles, and directories with listing left enabled. It's built to be low-noise. Every finding is backed by a content signature or a real content match, not a bare guess.

```
$ leakprobe -url https://example.com

SEVERITY  RULE                       LOCATION                                      DETAIL
------------------------------------------------------------------------------------------------------------------------
CRITICAL  web:.env                   https://example.com/.env                      APP_KEY - Sensitive resource reachable via HTTP 200
HIGH      web:open-directory:database-ext ...ploads/wp-file-manager-pro/fm_backup/site.sql  Database file (found directly in an open directory listing)
MEDIUM    web:directory-listing      https://example.com/wp-content/uploads/...    Directory listing is open
------------------------------------------------------------------------------------------------------------------------
Total 3 findings | CRITICAL:1 HIGH:1 MEDIUM:1 LOW:0 INFO:0
```

## Why leakprobe

Most tools in this space do one of two things: scan a **local git history** for committed secrets (gitleaks, trufflehog), or fuzz a **fixed wordlist** of paths against a live target (dirsearch, ffuf). leakprobe combines both angles into one binary, purpose-built for exposure hunting on a running target.

- **101 hand-curated sensitive paths** (`.env` variants, framework configs, Terraform state, Kubernetes config, package-manager auth files, Spring Actuator endpoints, and more), each verified with a real content signature instead of a blind 200-OK guess.
- **Recursive directory-listing discovery.** Finds an open `Index of /`, follows the links, walks into subdirectories, and classifies every file it finds. This includes a seed list of known plugin backup locations that stay exposed even when their *parent* directory is properly locked down, since listing is enabled per-directory in Apache/nginx, not inherited.
- **JS bundle and source map scanning.** Fetches the homepage's `<script>` files and follows `sourceMappingURL`. Secrets usually don't leak in raw HTML; they leak in compiled JS, and source maps can hand you the original, uncompiled source.
- **`.git` exposure, reconstructed.** If `.git/HEAD` is reachable, `-git-dump` walks HEAD → commit → tree and rebuilds every file from that commit into a local directory. That turns "there's an exposed .git folder" into an actual checkout you can read.
- **One binary, four modes**: local directory, single URL, URL list, or full subdomain discovery (`subfinder` + `httpx`), all through the same detection engine.

## Install

```bash
go install github.com/umutozen/leakprobe@latest
```

Prebuilt binaries for Linux, macOS, and Windows (amd64/arm64) are on the [Releases](https://github.com/umutozen/leakprobe/releases) page.

Building from source works the same way as any Go module:

```bash
git clone https://github.com/umutozen/leakprobe
cd leakprobe
go build -o leakprobe .
```

## Usage

**Scan a local directory** (source tree, extracted backup, mounted filesystem):

```bash
leakprobe /path/to/directory
```

**Scan a single live target:**

```bash
leakprobe -url https://example.com
```

**Scan a list of URLs:**

```bash
leakprobe -url-list targets.txt
```

**Discover subdomains and scan every live host.** Requires [subfinder](https://github.com/projectdiscovery/subfinder) and [httpx](https://github.com/projectdiscovery/httpx) on `$PATH`:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

```bash
leakprobe -domain example.com
```

**Reconstruct an exposed `.git` directory.** Run this after a normal scan has already confirmed `.git/HEAD` is reachable:

```bash
leakprobe -git-dump https://example.com/.git/ -git-output ./recovered
```

This only decodes "loose" git objects. Repositories that have been through `git gc` store objects in packfiles, which this tool doesn't parse. It will say so clearly rather than silently returning nothing.

**Common flags:**

| Flag | Default | What it does |
|---|---|---|
| `-severity` | `INFO` | Minimum severity to report: `CRITICAL\|HIGH\|MEDIUM\|LOW\|INFO` |
| `-proxy` | none | HTTP/SOCKS5 proxy for web mode, e.g. a local Tor daemon |
| `-user-agent` | realistic Chrome UA | Never sends a self-identifying UA by default, so there's nothing to fingerprint |
| `-dir-listing` | `true` | Toggle recursive directory-listing discovery |
| `-js` | `true` | Toggle JS bundle and source map scanning |
| `-delay` | `100` | Delay between requests, in ms |
| `-rules` | none | Extra/override rules file, merged into the embedded set by `id` |
| `-json` / `-html` / `-sarif` | none | Report output paths |

Run `leakprobe -h` for the full list.

## Output formats

- **Console**: a colored table, meant to be read directly.
- **JSON** (`-json out.json`): full structured findings for scripting.
- **HTML** (`-html out.html`): a self-contained, shareable report.
- **SARIF** (`-sarif out.sarif`): feed it to [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning) via `github/codeql-action/upload-sarif` and findings show up as inline PR annotations. No manual triage needed.

The process exits with code `3` if any `CRITICAL` finding was reported, which is convenient for gating a CI pipeline.

## Rules

Detection rules live in two embedded JSON files:

- `default_rules.json`: file-mode rules (`name`, `ext`, `suffix`, `dir`, `content` types; `content` rules are regex-based secret patterns like AWS keys, JWTs, Slack tokens, and connection strings).
- `web_paths.json`: the web-mode path list, with each entry backed by content signatures to keep false positives low.

Both can be extended or overridden without recompiling:

```bash
leakprobe -rules my-rules.json -url https://example.com
```

Rules in the override file are merged by `id`. Matching IDs replace the embedded rule; new IDs are appended.

## Responsible use

leakprobe actively probes for and can retrieve sensitive data, including database contents, private keys, and reconstructed source code. Only use it against targets you own or are explicitly authorized to test. The tool prints this reminder every time web mode or git-dump mode runs, and it means it.

## License

[MIT](LICENSE)
