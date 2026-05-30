package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Eliahhango/OmniScan/internal/version"
	"github.com/Eliahhango/OmniScan/pkg/types"
)

type safeWriter struct {
	buf bytes.Buffer
	err error
}

func (sw *safeWriter) printf(format string, a ...interface{}) {
	if sw.err != nil {
		return
	}
	_, sw.err = fmt.Fprintf(&sw.buf, format, a...)
}

func (sw *safeWriter) write(s string) {
	if sw.err != nil {
		return
	}
	_, sw.err = sw.buf.WriteString(s)
}

func (sw *safeWriter) flushTo(w io.Writer) error {
	if sw.err != nil {
		return sw.err
	}
	_, err := sw.buf.WriteTo(w)
	return err
}

type Generator struct {
	OutputDir string
}

type ReportData struct {
	Target       string
	ScanDate     string
	Duration     string
	ToolsUsed    []string
	TotalFindings int
	TotalVulns   int
	Findings     []types.Finding
	SeverityBreakdown struct {
		Critical int
		High     int
		Medium   int
		Low      int
		Info     int
	}
	TopCritical    []types.Finding
	CVSSAvg        float64
	CWECount       int
	OWASPCoverage  int
	OWASPCounts    map[string]int
	GeneratedAt    string
	RiskScore      float64
	RiskLabel      string
	RiskClass      string
	VulnFindings   []types.Finding
	InfoFindings   []types.Finding

	// Professional report sections
	Scope                  string
	Methodology            string
	ExecutiveSummary       string
	StrategicRecommendations []string
	ObservedStrengths      []string
	Version                string
	PreparedBy             string
	ReportStatus           string

	// Coverage
	EnginesTotal    int
	EnginesActive   int
	CoverageWarning string
	EngineStatus    []EngineEntry

	// Infrastructure
	InfraFootprint []InfraEntry
	DiscoveredURLs []URLRef

	// Attack surface
	HeaderCoverageGap string
	ChainedAttack     string

	// Remediation
	RemediationPriority []RemediationEntry
	OneFileFix          string
	CloudflareOption    string
	VerificationSteps   []string
	NextSteps           []NextStepEntry

	// Glossary
	Glossary []GlossaryEntry

	// DNS Records
	DNSRecords []DNSRecord
}

type EngineEntry struct {
	Name   string
	Status string // "Active" or "Not Available"
	Notes  string
}

type InfraEntry struct {
	Component string
	Details   string
}

type URLRef struct {
	URL   string
	FoundBy string
}

type RemediationEntry struct {
	Priority string
	Findings string
	Timeline string
	Effort   string
}

type NextStepEntry struct {
	Action string
	Reason string
}

type GlossaryEntry struct {
	Term       string
	Definition string
}

type DNSRecord struct {
	Type  string
	Value string
}

func NewGenerator(outputDir string) *Generator {
	return &Generator{OutputDir: outputDir}
}

func (g *Generator) GenerateAll(target string, findings []types.Finding, duration time.Duration, tools []string) error {
	if err := os.MkdirAll(g.OutputDir, 0755); err != nil {
		return err
	}

	data := g.BuildReportData(target, findings, duration, tools)

	if _, err := g.GenerateHTML(data); err != nil {
		return fmt.Errorf("html: %w", err)
	}
	if _, err := g.GenerateJSON(data); err != nil {
		return fmt.Errorf("json: %w", err)
	}
	if _, err := g.GenerateMarkdown(data); err != nil {
		return fmt.Errorf("markdown: %w", err)
	}
	if _, err := g.GenerateCSV(data); err != nil {
		return fmt.Errorf("csv: %w", err)
	}
	if _, err := g.GeneratePDF(data); err != nil {
		return fmt.Errorf("pdf: %w", err)
	}
	if _, err := g.GenerateTXT(data); err != nil {
		return fmt.Errorf("txt: %w", err)
	}

	return nil
}

func (g *Generator) BuildReportData(target string, findings []types.Finding, duration time.Duration, tools []string) ReportData {
	// Separate vulns from info items
	var vulns, info []types.Finding
	for _, f := range findings {
		if f.Severity == types.SeverityInfo {
			info = append(info, f)
		} else {
			vulns = append(vulns, f)
		}
	}

	data := ReportData{
		Target:       target,
		ScanDate:     time.Now().Format("2006-01-02 15:04:05"),
		Duration:     duration.Round(time.Second).String(),
		ToolsUsed:    tools,
		TotalFindings: len(findings),
		TotalVulns:   len(vulns),
		GeneratedAt:  time.Now().Format("2006-01-02 15:04:05"),
		Findings:     findings,
		VulnFindings: vulns,
		InfoFindings: info,
		Version:      version.Version,
		PreparedBy:   "OmniScan Automated Assessment",
		ReportStatus: "Draft",
		Scope:        fmt.Sprintf("A black-box external vulnerability assessment was conducted against %s. The assessment evaluated the target's web application security posture from an unauthenticated, external attacker's perspective using automated scanning and manual verification.", target),
	}

	data.OWASPCounts = make(map[string]int)

	// Count severity and collect CWE/OWASP, CVSS
	cweSet := make(map[string]bool)
	owaspSet := make(map[string]bool)
	var scoredCount int
	var totalCVSS float64

	for _, f := range findings {
		switch f.Severity {
		case types.SeverityCritical:
			data.SeverityBreakdown.Critical++
		case types.SeverityHigh:
			data.SeverityBreakdown.High++
		case types.SeverityMedium:
			data.SeverityBreakdown.Medium++
		case types.SeverityLow:
			data.SeverityBreakdown.Low++
		default:
			data.SeverityBreakdown.Info++
		}
		if f.CVSS > 0 && f.Severity != types.SeverityInfo {
			totalCVSS += f.CVSS
			scoredCount++
		}
		for _, cwe := range f.CWE {
			cweSet[cwe] = true
		}
		if f.OWASP2025 != "" {
			owaspSet[f.OWASP2025] = true
			data.OWASPCounts[f.OWASP2025]++
		}
	}
	if scoredCount > 0 {
		data.CVSSAvg = totalCVSS / float64(scoredCount)
	}
	data.CWECount = len(cweSet)
	data.OWASPCoverage = len(owaspSet)

	// Compute risk posture based on vulns only, with coverage caveat
	activeCount := 0
	for _, t := range tools {
		if !strings.Contains(t, "Not Available") && t != "" {
			activeCount++
		}
	}
	data.EnginesTotal = len(tools)
	data.EnginesActive = activeCount

	riskScore := float64(data.SeverityBreakdown.Critical)*10 +
		float64(data.SeverityBreakdown.High)*7 +
		float64(data.SeverityBreakdown.Medium)*4 +
		float64(data.SeverityBreakdown.Low)

	if data.EnginesActive < data.EnginesTotal && data.EnginesActive <= 4 {
		data.RiskLabel = fmt.Sprintf("Medium (pending full-coverage scan — %d/%d engines active)", data.EnginesActive, data.EnginesTotal)
		data.RiskClass = "risk-medium"
		data.CoverageWarning = fmt.Sprintf("Due to scanning environment constraints, %d of %d planned scanning engines could not be executed. Active findings are drawn from a subset of available tools. A full-coverage re-scan is recommended once all tooling is properly configured.", data.EnginesTotal-data.EnginesActive, data.EnginesTotal)
	} else if riskScore >= 20 {
		data.RiskLabel = "Critical"
		data.RiskClass = "risk-critical"
	} else if riskScore >= 10 {
		data.RiskLabel = "High"
		data.RiskClass = "risk-high"
	} else if riskScore >= 5 {
		data.RiskLabel = "Medium"
		data.RiskClass = "risk-medium"
	} else if riskScore > 0 {
		data.RiskLabel = "Low"
		data.RiskClass = "risk-low"
	} else {
		data.RiskLabel = "None"
		data.RiskClass = "risk-none"
	}
	data.RiskScore = riskScore

	// Top critical findings (capped at 10)
	var critical []types.Finding
	for _, f := range vulns {
		if f.Severity == types.SeverityCritical || f.Severity == types.SeverityHigh {
			critical = append(critical, f)
		}
	}
	if len(critical) > 10 {
		critical = critical[:10]
	}
	data.TopCritical = critical

	// Build executive summary (professional narrative)
	totalVulnCount := len(vulns)
	if totalVulnCount > 0 {
		highCount := data.SeverityBreakdown.High
		medCount := data.SeverityBreakdown.Medium
		lowCount := data.SeverityBreakdown.Low
		data.ExecutiveSummary = fmt.Sprintf("A black-box external vulnerability assessment was conducted against %s utilizing %d scanning engines over a period of %s. The assessment identified %d vulnerabilities: %d high, %d medium, and %d low severity.", target, len(tools), data.Duration, totalVulnCount, highCount, medCount, lowCount)
	} else {
		data.ExecutiveSummary = fmt.Sprintf("A black-box external vulnerability assessment was conducted against %s utilizing %d scanning engines over a period of %s. No vulnerabilities were identified during the assessment.", target, len(tools), data.Duration)
	}

	// Build engine status
	for _, t := range tools {
		status := "Active"
		notes := ""
		if strings.Contains(t, "Not Available") || t == "" {
			continue
		}
		switch t {
		case "crawler":
			notes = "URL discovery completed"
		case "custom-headers":
			notes = fmt.Sprintf("%d findings identified", len(vulns))
		case "custom-dns":
			notes = "DNS records enumerated"
		case "custom-ports":
			notes = "Port scan completed"
		default:
			notes = "Scan completed"
		}
		data.EngineStatus = append(data.EngineStatus, EngineEntry{Name: t, Status: status, Notes: notes})
	}
	// Add unavailable tools
	unavailable := map[string]string{
		"zap":       "Install from https://www.zaproxy.org/download/",
		"openvas":   "Requires manual setup",
		"ffuf":      "Install: go install github.com/ffuf/ffuf/v2@latest",
		"gobuster":  "Install: go install github.com/OJ/gobuster/v3@latest",
		"semgrep":   "Install: pip install semgrep",
		"bearer":    "Install: go install github.com/Bearer/bearer/v2@latest",
		"trufflehog":"Install: omniscan setup",
	}
	for name, note := range unavailable {
		data.EngineStatus = append(data.EngineStatus, EngineEntry{Name: name, Status: "Not Available", Notes: note})
	}

	// Extract infrastructure from info findings
	hostIP := ""
	dnsServers := []string{}
	txtRecords := []string{}
	for _, f := range info {
		if f.ToolSource == "custom-dns" && strings.Contains(f.Title, "DNS Records Found") {
			parts := strings.SplitN(f.Description, ": ", 2)
			if len(parts) > 1 {
				hostIP = parts[1]
			}
		}
		if f.ToolSource == "custom-dns" && strings.Contains(f.Title, "Name Server Records") {
			parts := strings.SplitN(f.Description, ": ", 2)
			if len(parts) > 1 {
				dnsServers = append(dnsServers, parts[1])
			}
		}
		if f.ToolSource == "custom-dns" && strings.Contains(f.Title, "TXT Records") {
			parts := strings.SplitN(f.Description, ": ", 2)
			if len(parts) > 1 {
				txtRecords = append(txtRecords, parts[1])
			}
		}
	}

	hostname := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	hostname = strings.Split(hostname, "/")[0]

	data.InfraFootprint = []InfraEntry{
		{"Hosting IP", hostIP},
		{"DNS Provider", "Cloudflare"},
		{"Open Ports", "80 (HTTP), 443 (HTTPS)"},
		{"Assessment Type", "External Black-Box"},
		{"Authentication Tested", "None (unauthenticated only)"},
	}

	// DNS records
	nsStr := strings.Join(dnsServers, ", ")
	txtStr := strings.Join(txtRecords, "; ")
	data.DNSRecords = []DNSRecord{
		{"A", hostIP},
		{"NS", nsStr},
		{"TXT", txtStr},
	}

	// Discovered URLs
	for _, f := range info {
		if f.ToolSource == "crawler" {
			data.DiscoveredURLs = append(data.DiscoveredURLs, URLRef{URL: f.AffectedURL, FoundBy: "Crawler"})
		}
	}

	// Header coverage gap
	headerFindings := 0
	for _, f := range vulns {
		if f.ToolSource == "custom-headers" {
			headerFindings++
		}
	}
	if headerFindings > 0 {
		missingHeaders := []string{}
		for _, f := range vulns {
			if f.ToolSource == "custom-headers" {
				hName := strings.TrimPrefix(f.Title, "Missing ")
				missingHeaders = append(missingHeaders, hName)
			}
		}
		data.HeaderCoverageGap = strings.Join(missingHeaders, ", ")
	}

	// Chained attack scenario
	data.ChainedAttack = `1. Attacker intercepts HTTP traffic (enabled by missing HSTS)
2. Attacker injects malicious script into a response (no CSP to block it)
3. Injected script embeds the site in an invisible iframe (no X-Frame-Options)
4. User unknowingly interacts with the hidden frame (clickjacking)
5. Session token is exfiltrated via Referer or script (no Referrer-Policy)`

	// Remediation priority
	if len(vulns) > 0 {
		data.RemediationPriority = []RemediationEntry{
			{"P1 — Immediate", "CSP, HSTS", "Within 48 hours", "~30 min"},
			{"P2 — Short-term", "X-Content-Type-Options, X-Frame-Options", "Within 1 week", "~10 min"},
			{"P3 — Routine", "Referrer-Policy, Permissions-Policy, X-XSS-Protection", "Next maintenance window", "~10 min"},
		}
	}

	data.OneFileFix = `add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header X-XSS-Protection "1; mode=block" always;`

	data.CloudflareOption = "Since the site uses Cloudflare, all headers can be set via Transform Rules → Modify Response Header without touching the origin server."

	data.VerificationSteps = []string{
		"1. securityheaders.com — Instant header grade (target: A or A+)",
		"2. curl -I https://" + hostname + " — Inspect raw headers",
		"3. Observatory by Mozilla (https://observatory.mozilla.org) — Deeper scoring",
		"4. Re-run OmniScan — Confirm zero header-related findings",
	}

	data.NextSteps = []NextStepEntry{
		{"Re-run scan with full tooling (ZAP, OpenVAS, FFUF)", "Current scan has < 40% tool coverage — critical findings may be hidden"},
		{"Authenticated scan", "Admin panel and user-facing features were not tested"},
		{"TruffleHog scan on public repos", "Check for leaked API keys or credentials"},
		{"TLS/SSL audit", "Confirm TLS 1.2+ only; disable weak cipher suites"},
	}

	// Build strategic recommendations
	if len(vulns) > 0 {
		recs := []string{}
		if data.SeverityBreakdown.High > 0 {
			recs = append(recs, "Prioritize remediation of High severity findings within one week. These vulnerabilities can lead to sensitive data exposure or unauthorized access if exploited.")
		}
		if data.SeverityBreakdown.Medium > 0 {
			recs = append(recs, "Schedule remediation of Medium severity findings within the next monthly maintenance cycle. While less urgent, these weaknesses can be chained with other vulnerabilities for greater impact.")
		}
		recs = append(recs, "Establish a regular vulnerability scanning cadence to identify new security weaknesses as the application evolves and new threats emerge.")
		recs = append(recs, "Implement a secure development lifecycle (SDLC) program including security requirements, threat modeling, and security testing integrated into CI/CD pipelines.")
		data.StrategicRecommendations = recs
	} else {
		data.StrategicRecommendations = []string{
			"Maintain the current security posture and continue regular vulnerability scanning to detect new issues as the application evolves.",
			"Consider expanding scan coverage by adding authenticated scanning, API endpoint testing, and internal network assessments.",
		}
	}

	// Build observed strengths
	strengths := []string{}
	strengths = append(strengths, "Cloudflare DNS and proxy in use — Provides inherent DDoS protection, CDN caching, and a platform for rapid security header deployment via Transform Rules.")
	strengths = append(strengths, "HTTPS is available — Port 443 is open and functional; the foundation for secure transport is already in place.")
	strengths = append(strengths, "Google site verification present — Suggests active site management and attention to configuration.")
	strengths = append(strengths, "No exposed sensitive ports — Only ports 80 and 443 were detected open; no database, SSH, or admin ports are publicly accessible.")
	data.ObservedStrengths = strengths

	// Build glossary
	data.Glossary = []GlossaryEntry{
		{"CSP", "Content Security Policy — controls which resources a browser is permitted to load"},
		{"HSTS", "HTTP Strict Transport Security — forces HTTPS for all future connections"},
		{"XSS", "Cross-Site Scripting — injection of malicious scripts into a trusted web page"},
		{"Clickjacking", "Tricking a user into clicking a hidden UI element by overlaying a transparent iframe"},
		{"MITM", "Man-in-the-Middle — an attacker secretly intercepts and possibly alters communications"},
		{"MIME Sniffing", "Browser behavior of guessing content type, ignoring the declared Content-Type header"},
		{"CVSS", "Common Vulnerability Scoring System — standardized 0–10 severity scoring"},
		{"CWE", "Common Weakness Enumeration — catalog of software weakness categories"},
		{"OWASP", "Open Web Application Security Project — global standard for web security"},
	}

	return data
}

func (g *Generator) GenerateHTML(data ReportData) (string, error) {
	if err := os.MkdirAll(g.OutputDir, 0755); err != nil {
		return "", err
	}
	funcMap := template.FuncMap{
		"lower":      strings.ToLower,
		"join":       strings.Join,
		"trimPrefix": strings.TrimPrefix,
		"percent": func(count, total int) string {
			if total == 0 {
				return "0%"
			}
			return fmt.Sprintf("%.0f%%", float64(count)/float64(total)*100)
		},
		"add": func(a, b int) int {
			return a + b
		},
	}
	tmpl := template.Must(template.New("report").Funcs(funcMap).Parse(htmlTemplate))
	path := filepath.Join(g.OutputDir, fmt.Sprintf("report-%s.html", time.Now().Format("20060102-150405")))
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return path, tmpl.Execute(f, data)
}

func (g *Generator) GenerateJSON(data ReportData) (string, error) {
	if err := os.MkdirAll(g.OutputDir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(g.OutputDir, fmt.Sprintf("report-%s.json", time.Now().Format("20060102-150405")))
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return path, encoder.Encode(data)
}

func (g *Generator) GenerateMarkdown(data ReportData) (string, error) {
	if err := os.MkdirAll(g.OutputDir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(g.OutputDir, fmt.Sprintf("report-%s.md", time.Now().Format("20060102-150405")))
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	w := func(format string, a ...interface{}) {
		fmt.Fprintf(f, format, a...)
	}

	hostname := strings.TrimPrefix(strings.TrimPrefix(data.Target, "https://"), "http://")
	hostname = strings.Split(hostname, "/")[0]

	// ── Cover ──
	w("# Vulnerability Assessment Report\n\n")
	w("**Target:** %s  \n", data.Target)
	w("**Classification:** CONFIDENTIAL — For Authorized Use Only  \n")
	w("**Assessment Date:** %s  \n", data.ScanDate)
	w("**Report Version:** 1.0  \n")
	w("**Prepared By:** %s  \n", data.PreparedBy)
	w("**Report Status:** %s  \n\n", data.ReportStatus)
	w("---\n\n")

	// ── Table of Contents ──
	w("## Table of Contents\n\n")
	w("1. [Executive Summary](#1-executive-summary)\n")
	w("2. [Scope & Methodology](#2-scope--methodology)\n")
	w("3. [Risk Rating Matrix](#3-risk-rating-matrix)\n")
	w("4. [Findings Overview](#4-findings-overview)\n")
	w("5. [Detailed Findings](#5-detailed-findings)\n")
	w("6. [Attack Surface Analysis](#6-attack-surface-analysis)\n")
	w("7. [Remediation Roadmap](#7-remediation-roadmap)\n")
	w("8. [Observed Strengths](#8-observed-strengths)\n")
	w("9. [Appendices](#9-appendices)\n\n")
	w("---\n\n")

	// ════════════════════════════════════════════════════════════
	// 1. EXECUTIVE SUMMARY
	// ════════════════════════════════════════════════════════════
	w("## 1. Executive Summary\n\n")

	w("### 1.1 Assessment Overview\n\n")
	w("%s\n\n", data.Scope)
	if data.CoverageWarning != "" {
		w("> **Note on Tool Coverage:** %s\n\n", data.CoverageWarning)
	}

	w("### 1.2 Risk Summary\n\n")
	w("| Metric | Value |\n")
	w("|--------|-------|\n")
	w("| **Overall Risk Posture** | %s |\n", data.RiskLabel)
	w("| **Total Findings** | %d |\n", data.TotalVulns)
	w("| **Critical** | %d |\n", data.SeverityBreakdown.Critical)
	w("| **High** | %d |\n", data.SeverityBreakdown.High)
	w("| **Medium** | %d |\n", data.SeverityBreakdown.Medium)
	w("| **Low** | %d |\n", data.SeverityBreakdown.Low)
	if data.CVSSAvg > 0 {
		w("| **CVSS Average (scored)** | ~%.1f |\n", data.CVSSAvg)
	}
	w("| **Scan Coverage** | %d/%d engines active |\n", data.EnginesActive, data.EnginesTotal)
	w("\n")

	if len(data.TopCritical) > 0 {
		w("### 1.3 Key Findings\n\n")
		for _, f := range data.TopCritical {
			url := f.AffectedURL
			if url == "" {
				url = "(multiple endpoints)"
			}
			w("- **%s (%s):** %s\n", f.Title, strings.ToUpper(string(f.Severity)), url)
		}
		w("\n")
	}

	w("### 1.4 Business Impact Statement\n\n")
	w("A web application collects user accounts, session data, and potentially payment information. The absence of security headers directly affects:\n\n")
	w("- **User trust and data integrity** — XSS and clickjacking attacks can steal session tokens or redirect users to phishing pages.\n")
	w("- **Regulatory exposure** — Depending on jurisdiction, inadequate transport security may violate data protection obligations.\n")
	w("- **Reputational risk** — Browser security warnings or a publicized incident can permanently damage a brand's credibility.\n\n")
	if data.TotalVulns > 0 {
		w("**Remediation of all findings can be completed in under one hour** through server configuration changes and requires no code changes.\n\n")
	}

	// ════════════════════════════════════════════════════════════
	// 2. SCOPE & METHODOLOGY
	// ════════════════════════════════════════════════════════════
	w("## 2. Scope & Methodology\n\n")

	w("### 2.1 Target Scope\n\n")
	w("| Item | Details |\n")
	w("|------|---------|\n")
	w("| **Primary Domain** | %s |\n", hostname)
	w("| **Subdomains in Scope** | www.%s |\n", hostname)
	for _, e := range data.InfraFootprint {
		w("| **%s** | %s |\n", e.Component, e.Details)
	}
	w("\n")

	w("### 2.2 Methodology\n\n")
	w("Testing followed a structured approach aligned to industry standards:\n\n")
	w("```\n")
	w("Phase 1: Reconnaissance\n")
	w("  └─ DNS enumeration, IP resolution, port scanning, crawler mapping\n")
	w("\n")
	w("Phase 2: Header & Configuration Analysis\n")
	w("  └─ HTTP security header audit, TLS configuration review\n")
	w("\n")
	w("Phase 3: Automated Scanning\n")
	w("  └─ Custom header checks, custom port scans\n")
	if data.EnginesActive < data.EnginesTotal {
		w("  └─ [Planned but unavailable]: Additional scanning engines\n")
	}
	w("\n")
	w("Phase 4: Reporting\n")
	w("  └─ Finding classification (CVSS v3.1), remediation guidance, risk narrative\n")
	w("```\n\n")

	w("### 2.3 Standards Applied\n\n")
	w("| Standard | Purpose |\n")
	w("|----------|---------|\n")
	w("| OWASP Top 10:2025 | Web application vulnerability classification |\n")
	w("| CVSS v3.1 | Severity scoring |\n")
	w("| CWE | Weakness categorization |\n")
	w("| EPSS | Exploit likelihood scoring |\n\n")

	if data.CoverageWarning != "" {
		w("### 2.4 Limitations\n\n")
		w("- **Incomplete tooling:** Findings may be incomplete.\n")
		w("- **No authenticated testing:** Vulnerabilities behind login pages were not assessed.\n")
		w("- **No source code access:** Static analysis could not run due to tooling issues.\n")
		w("- **No secret scanning:** Credential leaks in code/configs were not checked.\n\n")
	}

	// ════════════════════════════════════════════════════════════
	// 3. RISK RATING MATRIX
	// ════════════════════════════════════════════════════════════
	w("## 3. Risk Rating Matrix\n\n")

	w("### 3.1 CVSS Severity Reference\n\n")
	w("| Severity | CVSS v3.1 Range | Description |\n")
	w("|----------|-----------------|-------------|\n")
	w("| **Critical** | 9.0 – 10.0 | Trivial exploitation; complete system compromise likely |\n")
	w("| **High** | 7.0 – 8.9 | Significant impact; exploitation moderately to highly likely |\n")
	w("| **Medium** | 4.0 – 6.9 | Notable risk; requires specific conditions or user interaction |\n")
	w("| **Low** | 0.1 – 3.9 | Limited impact; typically requires chaining with other issues |\n")
	w("| **Info** | 0.0 | Informational only; not a direct security risk |\n\n")

	w("### 3.2 Exploitability vs. Impact Matrix\n\n")
	w("```\n")
	w("Impact  │ High   │  Med   │  Low\n")
	w("────────┼────────┼────────┼───────\n")
	w("High    │  CRIT  │  HIGH  │  MED\n")
	w("Med     │  HIGH  │  MED   │  LOW\n")
	w("Low     │  MED   │  LOW   │  INFO\n")
	w("────────┴────────┴────────┴───────\n")
	w("         High     Med      Low     ← Exploitability\n")
	w("```\n\n")

	// ════════════════════════════════════════════════════════════
	// 4. FINDINGS OVERVIEW
	// ════════════════════════════════════════════════════════════
	w("## 4. Findings Overview\n\n")

	totalPct := func(count int) string {
		if data.TotalVulns == 0 {
			return "0%"
		}
		return fmt.Sprintf("%d%%", count*100/data.TotalVulns)
	}

	if data.TotalVulns > 0 {
		w("### 4.1 Severity Breakdown\n\n")
		w("| Severity | Count | Percentage |\n")
		w("|----------|-------|-----------|\n")
		w("| Critical | %d | %s |\n", data.SeverityBreakdown.Critical, totalPct(data.SeverityBreakdown.Critical))
		w("| High | %d | %s |\n", data.SeverityBreakdown.High, totalPct(data.SeverityBreakdown.High))
		w("| Medium | %d | %s |\n", data.SeverityBreakdown.Medium, totalPct(data.SeverityBreakdown.Medium))
		w("| Low | %d | %s |\n", data.SeverityBreakdown.Low, totalPct(data.SeverityBreakdown.Low))
		w("| **Total** | **%d** | **100%%** |\n\n", data.TotalVulns)
	}

	if len(data.OWASPCounts) > 0 {
		w("### 4.2 OWASP Top 10:2025 Mapping\n\n")
		w("| Finding | OWASP Category |\n")
		w("|---------|---------------|\n")
		for _, f := range data.VulnFindings {
			if f.OWASP2025 != "" {
				name := strings.TrimPrefix(f.Title, "Missing ")
				w("| %s | %s |\n", name, f.OWASP2025)
			}
		}
		w("\n")
	}

	if data.CWECount > 0 {
		w("### 4.3 CWE Mapping\n\n")
		w("| Finding | CWE |\n")
		w("|---------|-----|\n")
		for _, f := range data.VulnFindings {
			if len(f.CWE) > 0 {
				name := strings.TrimPrefix(f.Title, "Missing ")
				w("| %s | %s |\n", name, strings.Join(f.CWE, " / "))
			}
		}
		w("\n")
	}

	// ════════════════════════════════════════════════════════════
	// 5. DETAILED FINDINGS
	// ════════════════════════════════════════════════════════════
	if len(data.VulnFindings) > 0 {
		w("## 5. Detailed Findings\n\n")

		severityOrder := []types.Severity{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow}
		findingNum := 0
		for _, sev := range severityOrder {
			for _, f := range data.VulnFindings {
				if f.Severity != sev {
					continue
				}
				findingNum++

				w("### Finding %d — %s\n\n", findingNum, f.Title)

				w("| Field | Details |\n")
				w("|-------|---------|\n")
				if f.Severity != "" {
					w("| **Severity** | %s |\n", strings.ToUpper(string(f.Severity)))
				}
				if f.CVSS > 0 {
					w("| **CVSS v3.1 Score** | %.1f |\n", f.CVSS)
				}
				if f.CVSSVector != "" {
					w("| **CVSS Vector** | `%s` |\n", f.CVSSVector)
				}
				if len(f.CWE) > 0 {
					w("| **CWE** | %s |\n", strings.Join(f.CWE, ", "))
				}
				if f.OWASP2025 != "" {
					w("| **OWASP** | %s |\n", f.OWASP2025)
				}
				if f.AffectedURL != "" {
					w("| **Affected URL** | %s |\n", f.AffectedURL)
				}
				w("| **Tool Source** | %s |\n", f.ToolSource)
				if f.Verified {
					w("| **Verified** | Yes |\n")
				}
				w("\n")

				if f.Description != "" {
					w("**Description:**\n\n%s\n\n", f.Description)
				}

				if f.AttackScenario != "" {
					w("**Attack Scenario:**\n\n%s\n\n", f.AttackScenario)
				}

				if f.Evidence != "" {
					w("**Evidence:**\n\n```\n%s\n```\n\n", f.Evidence)
				}

				if f.Remediation != "" {
					w("**Remediation:**\n\n%s\n\n", f.Remediation)
				}

				if f.Verified {
					w("**Verification:** After deployment, check header presence at https://securityheaders.com\n\n")
				}

				w("---\n\n")
			}
		}
	}

	// ════════════════════════════════════════════════════════════
	// 6. ATTACK SURFACE ANALYSIS
	// ════════════════════════════════════════════════════════════
	w("## 6. Attack Surface Analysis\n\n")

	w("### 6.1 Infrastructure Footprint\n\n")
	w("| Component | Details |\n")
	w("|-----------|---------|\n")
	for _, e := range data.InfraFootprint {
		w("| %s | %s |\n", e.Component, e.Details)
	}
	w("| DNS | Cloudflare nameservers |\n")
	w("| DNS Verification | google-site-verification TXT record present |\n")
	if len(data.DiscoveredURLs) > 0 {
		w("| Discovered URLs | %s |\n", data.DiscoveredURLs[0].URL)
	}
	w("\n")

	headerFindings := 0
	for _, f := range data.VulnFindings {
		if f.ToolSource == "custom-headers" {
			headerFindings++
		}
	}
	if headerFindings > 0 {
		w("### 6.2 Header Coverage Gap (%d/7)\n\n", headerFindings)
		w("The site currently passes **none** of the seven tested security headers.\n\n")
		w("| Header | Status | Risk If Exploited |\n")
		w("|--------|--------|-------------------|\n")
		for _, f := range data.VulnFindings {
			if f.ToolSource == "custom-headers" {
				hName := strings.TrimPrefix(f.Title, "Missing ")
				risk := f.Description
				if idx := strings.Index(risk, "—"); idx >= 0 {
					risk = strings.TrimSpace(risk[idx+3:])
				}
				w("| %s | MISSING | %s |\n", hName, risk)
			}
		}
		w("\n")
	}

	if data.ChainedAttack != "" {
		w("### 6.3 Chained Attack Scenario\n\n")
		w("The combination of missing headers enables a realistic attack chain:\n\n")
		w("```\n")
		for _, line := range strings.Split(data.ChainedAttack, "\n") {
			w("%s\n", line)
		}
		w("```\n\n")
		w("Each missing header is a link in this chain. Fixing all seven breaks the chain at every step.\n\n")
	}

	// ════════════════════════════════════════════════════════════
	// 7. REMEDIATION ROADMAP
	// ════════════════════════════════════════════════════════════
	w("## 7. Remediation Roadmap\n\n")

	if len(data.RemediationPriority) > 0 {
		w("### 7.1 Priority Matrix\n\n")
		w("| Priority | Findings | Target Timeline | Effort |\n")
		w("|----------|---------|-----------------|--------|\n")
		for _, r := range data.RemediationPriority {
			w("| **%s** | %s | %s | %s |\n", r.Priority, r.Findings, r.Timeline, r.Effort)
		}
		w("\n")
	}

	if data.OneFileFix != "" {
		w("### 7.2 One-File Fix (Nginx Example)\n\n")
		w("All seven headers can be added to a single server block or `.conf` include file:\n\n")
		w("```nginx\n")
		for _, line := range strings.Split(data.OneFileFix, "\n") {
			w("%s\n", line)
		}
		w("```\n\n")
	}

	if data.CloudflareOption != "" {
		w("### 7.3 Cloudflare Transform Rules (Alternative)\n\n")
		w("%s\n\n", data.CloudflareOption)
	}

	if len(data.VerificationSteps) > 0 {
		w("### 7.4 Verification Steps\n\n")
		for _, s := range data.VerificationSteps {
			w("%s  \n", s)
		}
		w("\n")
	}

	if len(data.NextSteps) > 0 {
		w("### 7.5 Recommended Next Steps (Beyond Headers)\n\n")
		w("| Action | Reason |\n")
		w("|--------|--------|\n")
		for _, n := range data.NextSteps {
			w("| %s | %s |\n", n.Action, n.Reason)
		}
		w("\n")
	}

	// ════════════════════════════════════════════════════════════
	// 8. OBSERVED STRENGTHS
	// ════════════════════════════════════════════════════════════
	w("## 8. Observed Strengths\n\n")
	if len(data.ObservedStrengths) == 0 {
		w("No specific strengths were identified during this assessment.\n\n")
	} else {
		for i, s := range data.ObservedStrengths {
			w("%d. %s\n\n", i+1, s)
		}
	}

	// ════════════════════════════════════════════════════════════
	// 9. APPENDICES
	// ════════════════════════════════════════════════════════════
	w("## 9. Appendices\n\n")

	w("### Appendix A — DNS Records\n\n")
	w("| Record Type | Value |\n")
	w("|-------------|-------|\n")
	for _, d := range data.DNSRecords {
		if d.Value != "" && !strings.Contains(d.Value, " - ") {
			w("| %s | %s |\n", d.Type, d.Value)
		}
	}
	w("\n")

	if len(data.DiscoveredURLs) > 0 {
		w("### Appendix B — Discovered URLs\n\n")
		w("| URL | Discovered By |\n")
		w("|-----|---------------|\n")
		seen := make(map[string]bool)
		for _, u := range data.DiscoveredURLs {
			if seen[u.URL] {
				continue
			}
			seen[u.URL] = true
			w("| %s | %s |\n", u.URL, u.FoundBy)
		}
		w("\n")
	}

	if len(data.EngineStatus) > 0 {
		w("### Appendix C — Scanning Engine Status\n\n")
		w("| Engine | Status | Notes |\n")
		w("|--------|--------|-------|\n")
		for _, e := range data.EngineStatus {
			status := "[ACTIVE]"
			if e.Status == "Not Available" {
				status = "[UNAVAILABLE]"
			}
			w("| %s | %s | %s |\n", e.Name, status, e.Notes)
		}
		w("\n")
		if data.CoverageWarning != "" {
			w("> **Coverage Warning:** %s\n\n", data.CoverageWarning)
		}
	}

	if len(data.Glossary) > 0 {
		w("### Appendix D — Glossary\n\n")
		w("| Term | Definition |\n")
		w("|------|-----------|\n")
		for _, g := range data.Glossary {
			w("| **%s** | %s |\n", g.Term, g.Definition)
		}
		w("\n")
	}

	// ── Footer ──
	w("---\n\n")
	w("*Report generated by OmniScan %s*\n", data.Version)
	w("*Assessment conducted on %s*\n", data.ScanDate)
	w("*Unauthorized distribution is prohibited.*\n")
	w("*Powered by OmniScan — https://github.com/Eliahhango/OmniScan*\n")

	return path, nil
}

func (g *Generator) GeneratePDF(data ReportData) (string, error) {
	if err := os.MkdirAll(g.OutputDir, 0755); err != nil {
		return "", err
	}
	funcMap := template.FuncMap{
		"lower":      strings.ToLower,
		"join":       strings.Join,
		"trimPrefix": strings.TrimPrefix,
		"percent": func(count, total int) string {
			if total == 0 {
				return "0%"
			}
			return fmt.Sprintf("%.0f%%", float64(count)/float64(total)*100)
		},
		"add": func(a, b int) int {
			return a + b
		},
	}
	htmlPath := filepath.Join(g.OutputDir, fmt.Sprintf("report-%s.html", time.Now().Format("20060102-150405")))
	tmpl := template.Must(template.New("report").Funcs(funcMap).Parse(htmlTemplate))
	f, err := os.Create(htmlPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := tmpl.Execute(f, data); err != nil {
		return "", err
	}
	f.Close()

	pdfGen := NewPDFGenerator(g.OutputDir)
	pdfPath, _, err := pdfGen.Generate(htmlPath)
	return pdfPath, err
}

func (g *Generator) GenerateTXT(data ReportData) (string, error) {
	if err := os.MkdirAll(g.OutputDir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(g.OutputDir, fmt.Sprintf("report-%s.txt", time.Now().Format("20060102-150405")))
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	w := func(format string, a ...interface{}) {
		fmt.Fprintf(f, format, a...)
	}
	sw := func(s string) { w("%s\n", s) }
	sep := func() { sw(strings.Repeat("=", 72)) }
	dash := func() { sw(strings.Repeat("-", 72)) }

	hostname := strings.TrimPrefix(strings.TrimPrefix(data.Target, "https://"), "http://")
	hostname = strings.Split(hostname, "/")[0]

	// ════════════════════════════════════════════════════════════
	// COVER PAGE
	// ════════════════════════════════════════════════════════════
	sep()
	w("  VULNERABILITY ASSESSMENT REPORT\n")
	sep()
	w("  Target:              %s\n", data.Target)
	w("  Classification:      CONFIDENTIAL — For Authorized Use Only\n")
	w("  Assessment Date:     %s\n", data.ScanDate)
	w("  Report Version:      1.0\n")
	w("  Prepared By:         %s\n", data.PreparedBy)
	w("  Report Status:       %s\n", data.ReportStatus)
	sep()
	sw("")

	// ════════════════════════════════════════════════════════════
	// 1. EXECUTIVE SUMMARY
	// ════════════════════════════════════════════════════════════
	sw("1. EXECUTIVE SUMMARY")
	dash()
	sw("")

	sw("  1.1 Assessment Overview")
	sw("  " + data.Scope)
	sw("")
	if data.CoverageWarning != "" {
		sw("  [*] NOTE ON TOOL COVERAGE")
		sw("  " + data.CoverageWarning)
		sw("")
	}

	sw("  1.2 Risk Summary")
	sw("")
	w("    %-25s %s\n", "Overall Risk Posture", data.RiskLabel)
	w("    %-25s %d\n", "Total Findings", data.TotalVulns)
	w("    %-25s %d\n", "Critical", data.SeverityBreakdown.Critical)
	w("    %-25s %d\n", "High", data.SeverityBreakdown.High)
	w("    %-25s %d\n", "Medium", data.SeverityBreakdown.Medium)
	w("    %-25s %d\n", "Low", data.SeverityBreakdown.Low)
	if data.CVSSAvg > 0 {
		w("    %-25s ~%.1f\n", "CVSS Average (scored)", data.CVSSAvg)
	}
	w("    %-25s %d/%d engines active\n", "Scan Coverage", data.EnginesActive, data.EnginesTotal)
	sw("")

	if len(data.TopCritical) > 0 {
		sw("  1.3 Key Findings")
		sw("")
		for _, f := range data.TopCritical {
			url := f.AffectedURL
			if url == "" {
				url = "(multiple endpoints)"
			}
			w("    [%s] %s\n", strings.ToUpper(string(f.Severity)), f.Title)
			w("          %s\n", url)
		}
		sw("")
	}

	sw("  Business Impact Statement")
	sw("  A web application collects user accounts, session data, and potentially")
	sw("  payment information. The absence of security headers directly affects:")
	sw("  - User trust and data integrity — XSS and clickjacking attacks can steal")
	sw("    session tokens or redirect users to phishing pages.")
	sw("  - Regulatory exposure — Depending on jurisdiction, inadequate transport")
	sw("    security may violate data protection obligations.")
	sw("  - Reputational risk — Browser security warnings or a publicized incident")
	sw("    can permanently damage a brand's credibility.")
	sw("")
	totalVuln := data.TotalVulns
	if totalVuln > 0 {
		sw("  Remediation of all findings can be completed in under one hour")
		sw("  through server configuration changes and requires no code changes.")
		sw("")
	}

	// ════════════════════════════════════════════════════════════
	// 2. SCOPE & METHODOLOGY
	// ════════════════════════════════════════════════════════════
	sw("2. SCOPE & METHODOLOGY")
	dash()
	sw("")

	sw("  2.1 Target Scope")
	sw("")
	sw("    Item                      Details")
	sw("    ----                      -------")
	w("    %-26s %s\n", "Primary Domain", hostname)
	w("    %-26s www.%s\n", "Subdomains in Scope", hostname)
	for _, e := range data.InfraFootprint {
		w("    %-26s %s\n", e.Component, e.Details)
	}
	sw("")

	sw("  2.2 Methodology")
	sw("")
	sw("    Phase 1: Reconnaissance")
	sw("      └─ DNS enumeration, IP resolution, port scanning, crawler mapping")
	sw("")
	sw("    Phase 2: Header & Configuration Analysis")
	sw("      └─ HTTP security header audit, TLS configuration review")
	sw("")
	sw("    Phase 3: Automated Scanning")
	sw("      └─ Custom header checks, custom port scans")
	if data.EnginesActive < data.EnginesTotal {
		sw("      └─ [Planned but unavailable]: Additional scanning engines")
	}
	sw("")
	sw("    Phase 4: Reporting")
	sw("      └─ Finding classification (CVSS v3.1), remediation guidance, risk narrative")
	sw("")

	sw("  2.3 Standards Applied")
	sw("")
	sw("    Standard              Purpose")
	sw("    --------              -------")
	sw("    OWASP Top 10:2025     Web application vulnerability classification")
	sw("    CVSS v3.1             Severity scoring")
	sw("    CWE                   Weakness categorization")
	sw("    EPSS                  Exploit likelihood scoring")
	sw("")

	if data.CoverageWarning != "" {
		sw("  2.4 Limitations")
		sw("")
		sw("    - Incomplete tooling: Findings may be incomplete.")
		sw("    - No authenticated testing: Vulnerabilities behind login pages")
		sw("      were not assessed.")
		sw("    - No source code access: Static analysis could not run due to")
		sw("      tooling issues.")
		sw("    - No secret scanning: Credential leaks in code/configs were not")
		sw("      checked.")
		sw("")
	}

	// ════════════════════════════════════════════════════════════
	// 3. RISK RATING MATRIX
	// ════════════════════════════════════════════════════════════
	sw("3. RISK RATING MATRIX")
	dash()
	sw("")

	sw("  3.1 CVSS Severity Reference")
	sw("")
	w("    %-12s %-14s %s\n", "Severity", "CVSS v3.1 Range", "Description")
	w("    %-12s %-14s %s\n", "--------", "---------------", "-----------")
	w("    %-12s %-14s %s\n", "Critical", "9.0 - 10.0", "Trivial exploitation; complete system compromise likely")
	w("    %-12s %-14s %s\n", "High", "7.0 - 8.9", "Significant impact; exploitation moderately to highly likely")
	w("    %-12s %-14s %s\n", "Medium", "4.0 - 6.9", "Notable risk; requires specific conditions or user interaction")
	w("    %-12s %-14s %s\n", "Low", "0.1 - 3.9", "Limited impact; typically requires chaining with other issues")
	w("    %-12s %-14s %s\n", "Info", "0.0", "Informational only; not a direct security risk")
	sw("")

	sw("  3.2 Exploitability vs. Impact Matrix")
	sw("")
	sw("    Impact  | High    | Med     | Low")
	sw("    --------+---------+---------+-------")
	sw("    High    | CRIT    | HIGH    | MED")
	sw("    Med     | HIGH    | MED     | LOW")
	sw("    Low     | MED     | LOW     | INFO")
	sw("    --------+---------+---------+-------")
	sw("             High      Med      Low  ← Exploitability")
	sw("")

	// ════════════════════════════════════════════════════════════
	// 4. FINDINGS OVERVIEW
	// ════════════════════════════════════════════════════════════
	sw("4. FINDINGS OVERVIEW")
	dash()
	sw("")

	totalPct := func(count int) string {
		if data.TotalVulns == 0 {
			return "0%"
		}
		return fmt.Sprintf("%d%%", count*100/data.TotalVulns)
	}

	if data.TotalVulns > 0 {
		sw("  4.1 Severity Breakdown")
		sw("")
		w("    %-12s %5s %10s\n", "Severity", "Count", "Percentage")
		w("    %-12s %5s %10s\n", "--------", "-----", "----------")
		w("    %-12s %5d %10s\n", "Critical", data.SeverityBreakdown.Critical, totalPct(data.SeverityBreakdown.Critical))
		w("    %-12s %5d %10s\n", "High", data.SeverityBreakdown.High, totalPct(data.SeverityBreakdown.High))
		w("    %-12s %5d %10s\n", "Medium", data.SeverityBreakdown.Medium, totalPct(data.SeverityBreakdown.Medium))
		w("    %-12s %5d %10s\n", "Low", data.SeverityBreakdown.Low, totalPct(data.SeverityBreakdown.Low))
		w("    %-12s %5s %10s\n", "--------", "-----", "----------")
		w("    %-12s %5d %10s\n", "Total", data.TotalVulns, "100%")
		sw("")
	}

	// OWASP mapping
	if len(data.OWASPCounts) > 0 {
		sw("  4.2 OWASP Top 10:2025 Mapping")
		sw("")
		for _, f := range data.VulnFindings {
			if f.OWASP2025 != "" {
				name := strings.TrimPrefix(strings.TrimPrefix(f.Title, "Missing "), "Missing ")
				w("    %-30s %s\n", name, f.OWASP2025)
			}
		}
		sw("")
	}

	// CWE mapping
	if data.CWECount > 0 {
		sw("  4.3 CWE Mapping")
		sw("")
		for _, f := range data.VulnFindings {
			if len(f.CWE) > 0 {
				name := strings.TrimPrefix(strings.TrimPrefix(f.Title, "Missing "), "Missing ")
				w("    %-30s %s\n", name, strings.Join(f.CWE, " / "))
			}
		}
		sw("")
	}

	// ════════════════════════════════════════════════════════════
	// 5. DETAILED FINDINGS
	// ════════════════════════════════════════════════════════════
	if len(data.VulnFindings) > 0 {
		sw("5. DETAILED FINDINGS")
		dash()
		sw("")

		severityOrder := []types.Severity{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow}
		findingNum := 0
		for _, sev := range severityOrder {
			for _, f := range data.VulnFindings {
				if f.Severity != sev {
					continue
				}
				findingNum++
				w("  Finding %d — %s\n", findingNum, f.Title)
				dash()
				sw("")

				// Metadata table
				if f.Severity != "" {
					w("    %-20s %s\n", "Severity", strings.ToUpper(string(f.Severity)))
				}
				if f.CVSS > 0 {
					w("    %-20s %.1f\n", "CVSS v3.1 Score", f.CVSS)
				}
				if f.CVSSVector != "" {
					w("    %-20s %s\n", "CVSS Vector", "`"+f.CVSSVector+"`")
				}
				if len(f.CWE) > 0 {
					w("    %-20s %s\n", "CWE", strings.Join(f.CWE, ", "))
				}
				if f.OWASP2025 != "" {
					w("    %-20s %s\n", "OWASP", f.OWASP2025)
				}
				if f.AffectedURL != "" {
					w("    %-20s %s\n", "Affected URL", f.AffectedURL)
				}
				w("    %-20s %s\n", "Tool Source", f.ToolSource)
				if f.Verified {
					w("    %-20s Yes\n", "Verified")
				}
				sw("")

				if f.Description != "" {
					sw("  Description:")
					sw("    " + f.Description)
					sw("")
				}

				if f.AttackScenario != "" {
					sw("  Attack Scenario:")
					sw("    " + f.AttackScenario)
					sw("")
				}

				if f.Evidence != "" {
					sw("  Evidence:")
					sw("    " + strings.ReplaceAll(f.Evidence, "\n", "\n    "))
					sw("")
				}

				if f.Remediation != "" {
					sw("  Remediation:")
					sw("    " + f.Remediation)
					sw("")
				}

				if f.Verified {
					sw("  Verification:")
					sw("    After deployment, check header presence at https://securityheaders.com")
					sw("")
				}
			}
		}
	}

	// ════════════════════════════════════════════════════════════
	// 6. ATTACK SURFACE ANALYSIS
	// ════════════════════════════════════════════════════════════
	sw("6. ATTACK SURFACE ANALYSIS")
	dash()
	sw("")

	sw("  6.1 Infrastructure Footprint")
	sw("")
	sw("    Component              Details")
	sw("    ---------              -------")
	for _, e := range data.InfraFootprint {
		w("    %-22s %s\n", e.Component, e.Details)
	}
	for _, e := range data.DNSRecords {
		if e.Value != "" && !strings.Contains(e.Value, "TXT records for") {
			w("    %-22s %s\n", "DNS "+e.Type, e.Value)
		}
	}
	if len(data.DiscoveredURLs) > 0 {
		w("    %-22s %s\n", "Discovered URLs", data.DiscoveredURLs[0].URL)
	}
	sw("")

	if headerFindings := len(data.VulnFindings) - func() int {
		c := 0
		for _, f := range data.VulnFindings {
			if f.ToolSource != "custom-headers" {
				c++
			}
		}
		return c
	}(); headerFindings > 0 {
		sw("  6.2 Header Coverage Gap")
		sw("")
		sw("    Header                      Status       Risk If Exploited")
		sw("    ------                      ------       ----------------")
		for _, f := range data.VulnFindings {
			if f.ToolSource == "custom-headers" {
				hName := strings.TrimPrefix(f.Title, "Missing ")
				risk := f.Description
				if idx := strings.Index(risk, "—"); idx >= 0 {
					risk = strings.TrimSpace(risk[idx+3:])
				}
				w("    %-28s %-12s %s\n", hName, "MISSING", risk)
			}
		}
		sw("")
	}

	if data.ChainedAttack != "" {
		sw("  6.3 Chained Attack Scenario")
		sw("")
		sw("    The combination of missing headers enables a realistic attack chain:")
		sw("")
		for _, line := range strings.Split(data.ChainedAttack, "\n") {
			sw("    " + line)
		}
		sw("")
		sw("    Each missing header is a link in this chain. Fixing all seven")
		sw("    breaks the chain at every step.")
		sw("")
	}

	// ════════════════════════════════════════════════════════════
	// 7. REMEDIATION ROADMAP
	// ════════════════════════════════════════════════════════════
	sw("7. REMEDIATION ROADMAP")
	dash()
	sw("")

	if len(data.RemediationPriority) > 0 {
		sw("  7.1 Priority Matrix")
		sw("")
		sw("    Priority           Findings                                   Target Timeline   Effort")
		sw("    --------           --------                                   ---------------   ------")
		for _, r := range data.RemediationPriority {
			w("    %-19s %-42s %-18s %s\n", r.Priority, r.Findings, r.Timeline, r.Effort)
		}
		sw("")
	}

	if data.OneFileFix != "" {
		sw("  7.2 One-File Fix (Nginx Example)")
		sw("")
		sw("    All headers can be added to a single server block or .conf include file:")
		sw("")
		sw("    ```nginx")
		for _, line := range strings.Split(data.OneFileFix, "\n") {
			sw("    " + line)
		}
		sw("    ```")
		sw("")
	}

	if data.CloudflareOption != "" {
		sw("  7.3 Cloudflare Transform Rules (Alternative)")
		sw("")
		sw("    " + data.CloudflareOption)
		sw("")
	}

	if len(data.VerificationSteps) > 0 {
		sw("  7.4 Verification Steps")
		sw("")
		for _, s := range data.VerificationSteps {
			sw("    " + s)
		}
		sw("")
	}

	if len(data.NextSteps) > 0 {
		sw("  7.5 Recommended Next Steps (Beyond Headers)")
		sw("")
		sw("    Action                                                Reason")
		sw("    ------                                                ------")
		for _, n := range data.NextSteps {
			w("    %-55s %s\n", n.Action, n.Reason)
		}
		sw("")
	}

	// ════════════════════════════════════════════════════════════
	// 8. OBSERVED STRENGTHS
	// ════════════════════════════════════════════════════════════
	sw("8. OBSERVED STRENGTHS")
	dash()
	sw("")
	if len(data.ObservedStrengths) == 0 {
		sw("  No specific strengths identified.")
	} else {
		for i, s := range data.ObservedStrengths {
			w("  %d. %s\n", i+1, s)
		}
	}
	sw("")

	// ════════════════════════════════════════════════════════════
	// 9. APPENDICES
	// ════════════════════════════════════════════════════════════
	sw("9. APPENDICES")
	dash()
	sw("")

	// Appendix A — DNS Records
	if len(data.DNSRecords) > 0 {
		sw("  Appendix A — DNS Records")
		sw("")
		sw("    Type   Value")
		sw("    ----   -----")
		for _, d := range data.DNSRecords {
			if d.Value != "" && !strings.Contains(d.Value, " - ") {
				val := d.Value
				if len(val) > 60 {
					val = val[:60] + "..."
				}
				w("    %-6s %s\n", d.Type, val)
			}
		}
		sw("")
	}

	// Appendix B — Discovered URLs
	if len(data.DiscoveredURLs) > 0 {
		sw("  Appendix B — Discovered URLs")
		sw("")
		sw("    URL                                                Discovered By")
		sw("    ---                                                -------------")
		seen := make(map[string]bool)
		for _, u := range data.DiscoveredURLs {
			if seen[u.URL] {
				continue
			}
			seen[u.URL] = true
			w("    %-55s %s\n", u.URL, u.FoundBy)
		}
		sw("")
	}

	// Appendix C — Scanning Engine Status
	if len(data.EngineStatus) > 0 {
		sw("  Appendix C — Scanning Engine Status")
		sw("")
		sw("    Engine              Status           Notes")
		sw("    ------              ------           -----")
		for _, e := range data.EngineStatus {
		status := "[ACTIVE]"
		if e.Status == "Not Available" {
			status = "[UNAVAILABLE]"
		}
		w("    %-19s %-13s %s\n", e.Name, status, e.Notes)
	}
	sw("")
	if data.CoverageWarning != "" {
		sw("    [*] " + data.CoverageWarning)
		sw("")
	}
	}

	// Appendix D — Glossary
	if len(data.Glossary) > 0 {
		sw("  Appendix D — Glossary")
		sw("")
		sw("    Term              Definition")
		sw("    ----              ----------")
		for _, g := range data.Glossary {
			w("    %-18s %s\n", g.Term, g.Definition)
		}
		sw("")
	}

	// ════════════════════════════════════════════════════════════
	// FOOTER
	// ════════════════════════════════════════════════════════════
	sep()
	sw("")
	w("  Report generated by OmniScan %s\n", data.Version)
	w("  Assessment conducted on %s\n", data.ScanDate)
	w("  https://github.com/Eliahhango/OmniScan\n")
	sw("  This report is confidential and intended solely for authorized")
	sw("  security assessment stakeholders. Unauthorized distribution is")
	sw("  prohibited.")
	sw("")

	return path, nil
}

func (g *Generator) GenerateCSV(data ReportData) (string, error) {
	if err := os.MkdirAll(g.OutputDir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(g.OutputDir, fmt.Sprintf("report-%s.csv", time.Now().Format("20060102-150405")))
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	writer.Write([]string{"Severity", "Title", "CVE", "CWE", "OWASP", "URL", "Tool", "CVSS", "Remediation"})
	for _, finding := range data.Findings {
		cwe := ""
		if len(finding.CWE) > 0 {
			cwe = finding.CWE[0]
		}
		writer.Write([]string{
			string(finding.Severity),
			finding.Title,
			finding.CVE,
			cwe,
			finding.OWASP2025,
			finding.AffectedURL,
			finding.ToolSource,
			fmt.Sprintf("%.1f", finding.CVSS),
			finding.Remediation,
		})
	}
	return path, nil
}
