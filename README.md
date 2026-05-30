# OmniScan

**Unified Vulnerability Hunting Platform — 13 tools, one interface.**

```
   ___                        _   ____
  / _ \   _ __ ___    _ __   (_) / ___|    ___    __ _   _ __
 | | | | | '_ ` _ \  | '_ \  | | \___ \   / __|  / _` | | '_ \
 | |_| | | | | | | | | | | | | |  ___) | | (__  | (_| | | | | |
  \___/  |_| |_| |_| |_| |_| |_| |____/   \___|  \__,_| |_| |_|
```

OmniScan integrates 13 security scanning tools into a single real-time TUI with unified reporting, intelligent deduplication, CVE→CWE→OWASP mapping, EPSS scoring, and bug bounty intelligence.

## Features

- **Unified Coverage** — Run nuclei, nmap, nikto, ZAP, ffuf, subfinder, httpx, katana, gospider, gau, semgrep, trufflehog, and OpenVAS from one interface (via full scan mode)
- **Interactive CLI** — Numbered menu with 12 scan categories (custom scanners only) and full-scan mode (all tools + external scanners)
- **40+ Built-in Scanners** — Subdomain enumeration, SQLi, XSS, SSRF, path traversal, XXE, CORS, CSRF, JWT, rate limiting, command injection, deserialization, and more
- **Real-time TUI** — Bubble Tea-powered terminal UI with live scan progress, recon panel, and report preview
- **Dedup Engine** — Smart deduplication by URL+CVE, URL+CWE+param, and CVE fingerprints
- **CVE→CWE→OWASP Mapping** — Automatic normalization and mapping to OWASP 2025 categories
- **Bug Bounty Intelligence** — Duplicate detection, program scope loading, weaponization checks, and rate-limit awareness
- **EPSS Scoring** — Real-time Exploit Prediction Scoring via FIRST.org API
- **Submission-Ready Reports** — HTML, JSON, Markdown, and CSV report generation
- **Resumable Scans** — Checkpoint-based resume for long-running engagements

## Installation

### Go install
```bash
go install github.com/Eliahhango/OmniScan/cmd/omniscan@latest
```

### Docker
```bash
docker build -t omniscan:latest .
docker run -it omniscan:latest          # Interactive CLI menu
docker run -it omniscan:latest tui      # TUI mode
```

### One-command installer (Linux)
```bash
curl -sL https://raw.githubusercontent.com/Eliahhango/OmniScan/master/install.sh | sudo bash
```

## Quick Start

```bash
# Launch the interactive CLI (numbered menu — pick scans by category or run all)
omniscan

# Show usage / help menu
omniscan help

# Launch the interactive TUI (Bubble Tea GUI)
omniscan tui

# Interactive sub-commands (also available inside the interactive menu):
#   [0]-[11]  Run specific scan categories (custom scanners only)
#   [12]      Pick individual scanners by number
#   [A]       Run everything (including external tools: nuclei, nmap, zap, etc.)
#   [B]       Enter a new target
#   [Q]       Quit

# Run a full scan from the CLI (bypasses interactive menu)
omniscan scan -t example.com

# Resume a previous scan
omniscan scan -t example.com -resume

# Compare two scan results
omniscan diff 1 2

# Bug bounty mode with program scope
omniscan bounty -t example.com -program hackerone

# Install all 13 integrated tools
omniscan setup

# Update OmniScan and all tools to latest versions
omniscan update

# Show version information
omniscan version

# Start the daemon (WebSocket dashboard + API)
omniscan daemon --listen :9090
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    TUI Layer                         │
│  Bubble Tea · Live Panels · Real-time Updates       │
├─────────────────────────────────────────────────────┤
│                 Orchestration Layer                  │
│  Scan Pipeline · Concurrency · Checkpoint/Resume    │
├─────────────────────────────────────────────────────┤
│                  Normalizer Layer                    │
│  Dedup Engine · CVE→CWE→OWASP · EPSS Scoring       │
├─────────────────────────────────────────────────────┤
│                 Scanning Engines                     │
│  Nuclei  Nmap  Nikto  ZAP  ffuf  Subfinder  Httpx  │
│  Katana  Gospider  Gau  Semgrep  TruffleHog  OpenVAS│
└─────────────────────────────────────────────────────┘
```

## Integrated Tools

| Tool         | Category        | Purpose                          |
|-------------|-----------------|----------------------------------|
| Nuclei      | Vuln Scanner    | Template-based vulnerability scan|
| Nmap        | Network Scanner | Port scanning & service detection|
| Nikto       | Web Scanner     | Web server vulnerability scan    |
| ZAP         | DAST            | Dynamic application security test|
| ffuf        | Fuzzer          | Web fuzzing & directory discovery|
| Subfinder   | Recon           | Subdomain enumeration            |
| Httpx       | Recon           | HTTP probing & alive detection   |
| Katana      | Crawler         | Web crawling & endpoint discovery|
| Gospider    | Crawler         | Spidering & asset discovery      |
| Gau         | Recon           | URL fetching from AlienVault etc |
| Semgrep     | SAST            | Static analysis & custom rules   |
| TruffleHog  | Secrets         | Secret & credential scanning     |
| OpenVAS     | Vuln Scanner    | Comprehensive vulnerability scan |

## Development

### Prerequisites
- Go 1.26+
- Make

### Setup
```bash
git clone https://github.com/Eliahhango/OmniScan.git
cd omniscan
make deps
make build
```

### Commands
```bash
make build    # Build binary
make run      # Run CLI
make tui      # Launch TUI
make test     # Run tests
make lint     # Run go vet
make clean    # Clean artifacts
```

### Project Structure
```
cmd/omniscan/       Entry point
internal/
  config/           Configuration loading
  db/               SQLite database layer
  normalizer/       Dedup, CVE→CWE→OWASP mapping
  interactive/      Interactive CLI menu (numbered scan selection)
  recon/            Subdomain discovery, crawling, probing
  report/           Report generation (HTML, JSON, MD, CSV)
  scanner/          Tool orchestrators, installers, 40+ custom scanners
  tui/              Bubble Tea TUI
pkg/types/          Shared types
```

## Disclaimer

**OmniScan is a security testing tool. Misuse of this tool may violate applicable laws.**

By using this software, you acknowledge and agree that:
- You will only use OmniScan against systems you own or have **explicit written authorization** to test
- Unauthorized scanning or testing of computer systems is illegal in many jurisdictions
- You are solely responsible for complying with all applicable laws and regulations
- The developer(s) assume **no liability** and **provide no warranty** for any damages or legal consequences arising from use of this tool

This tool is provided for **legitimate security research, educational purposes, and authorized penetration testing only.**

## License

OmniScan is released under the **OmniScan Ethical Use License** — see the [LICENSE](LICENSE) file for details.

Key terms:
- ✅ Lawful security research and authorized testing
- ✅ Educational purposes
- ❌ Unauthorized access or exploitation
- ❌ Malicious use of any kind
- ❌ No warranty — use at your own risk
