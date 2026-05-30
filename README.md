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

- **Unified Coverage** — Run nuclei, nmap, nikto, ZAP, ffuf, subfinder, httpx, katana, gospider, gau, semgrep, trufflehog, and OpenVAS from one interface
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
docker run -it omniscan:latest tui
```

### One-command installer (Linux)
```bash
curl -sL https://raw.githubusercontent.com/Eliahhango/OmniScan/master/install.sh | sudo bash
```

## Quick Start

```bash
# Launch the interactive TUI
omniscan tui

# Run a full scan from the CLI
omniscan scan -t example.com

# Resume a previous scan
omniscan scan -t example.com -resume

# Bug bounty mode with program scope
omniscan bounty -t example.com -program hackerone

# Install all 13 integrated tools
omniscan setup
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
  recon/            Subdomain discovery, crawling, probing
  report/           Report generation (HTML, JSON, MD, CSV)
  scanner/          Tool orchestrators, installers
  tui/              Bubble Tea TUI
pkg/types/          Shared types
```

## License

MIT
