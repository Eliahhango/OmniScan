package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Eliahhango/OmniScan/internal/version"
	"github.com/Eliahhango/OmniScan/pkg/types"
)

type Generator struct {
	OutputDir string
}

type ReportData struct {
	Target      string
	ScanDate    string
	Duration    string
	ToolsUsed   []string
	TotalVulns  int
	Findings    []types.Finding
	SeverityBreakdown struct {
		Critical int
		High     int
		Medium   int
		Low      int
		Info     int
	}
	TopCritical   []types.Finding
	CVSSAvg       float64
	CWECount      int
	OWASPCoverage int
	OWASPCounts   map[string]int
	GeneratedAt   string
	RiskScore     float64
	RiskLabel     string

	// Professional report fields
	Scope                  string
	Methodology            string
	ExecutiveSummary       string
	StrategicRecommendations []string
	ObservedStrengths      []string
	Version                string
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
	data := ReportData{
		Target:      target,
		ScanDate:    time.Now().Format("2006-01-02 15:04:05"),
		Duration:    duration.Round(time.Second).String(),
		ToolsUsed:   tools,
		TotalVulns:  len(findings),
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Findings:    findings,
		Scope: fmt.Sprintf("Security assessment of %s. Testing methodology follows OWASP Top 10:2025, CWE classification, and CVSS v3.1 scoring standards. All scans performed from an external perspective against publicly accessible endpoints.", target),
		Methodology: fmt.Sprintf("The assessment was conducted using %d industry-standard scanning engines covering network reconnaissance, web application scanning, directory fuzzing, CVE template matching, static analysis, secret detection, and dependency auditing. Findings are enriched with EPSS (Exploit Prediction Scoring System) scores, mapped to CWE categories and OWASP Top 10:2025 classifications.", len(tools)),
		Version:     version.Version,
	}

	data.OWASPCounts = make(map[string]int)

	var totalCVSS float64
	cweSet := make(map[string]bool)
	owaspSet := make(map[string]bool)

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

		totalCVSS += f.CVSS
		for _, cwe := range f.CWE {
			cweSet[cwe] = true
		}
		if f.OWASP2025 != "" {
			owaspSet[f.OWASP2025] = true
			data.OWASPCounts[f.OWASP2025]++
		}
	}

	if len(findings) > 0 {
		data.CVSSAvg = totalCVSS / float64(len(findings))
	}
	data.CWECount = len(cweSet)
	data.OWASPCoverage = len(owaspSet)

	data.RiskScore = float64(data.SeverityBreakdown.Critical)*10 +
		float64(data.SeverityBreakdown.High)*7 +
		float64(data.SeverityBreakdown.Medium)*4 +
		float64(data.SeverityBreakdown.Low)*1
	switch {
	case data.RiskScore >= 20:
		data.RiskLabel = "Critical"
	case data.RiskScore >= 10:
		data.RiskLabel = "High"
	case data.RiskScore >= 5:
		data.RiskLabel = "Medium"
	case data.RiskScore > 0:
		data.RiskLabel = "Low"
	default:
		data.RiskLabel = "None"
	}

	var critical []types.Finding
	for _, f := range findings {
		if f.Severity == types.SeverityCritical || f.Severity == types.SeverityHigh {
			critical = append(critical, f)
		}
	}
	if len(critical) > 5 {
		critical = critical[:5]
	}
	data.TopCritical = critical

	// Build executive summary
	summaryParts := []string{
		fmt.Sprintf("A security assessment was conducted on %s utilizing %d scanning engines over a period of %s.", target, len(tools), data.Duration),
	}
	if data.TotalVulns > 0 {
		summaryParts = append(summaryParts,
			fmt.Sprintf("The assessment identified %d vulnerabilities in total, comprising %d critical, %d high, %d medium, and %d low severity findings.",
				data.TotalVulns,
				data.SeverityBreakdown.Critical,
				data.SeverityBreakdown.High,
				data.SeverityBreakdown.Medium,
				data.SeverityBreakdown.Low))
		summaryParts = append(summaryParts,
			"The overall risk posture of the target is rated as "+data.RiskLabel+" based on the severity distribution and exploitability of identified vulnerabilities.")
		if data.CVSSAvg > 0 {
			summaryParts = append(summaryParts,
				fmt.Sprintf("The average CVSS v3.1 score across all findings is %.1f, indicating the overall severity level of identified security weaknesses.", data.CVSSAvg))
		}
		if data.CWECount > 0 {
			summaryParts = append(summaryParts,
				fmt.Sprintf("Vulnerabilities span %d distinct CWE categories, with coverage across %d of 10 OWASP Top 10:2025 categories.", data.CWECount, data.OWASPCoverage))
		}
		if data.SeverityBreakdown.Critical+data.SeverityBreakdown.High > 0 {
			richParts := []string{
				"The most critical issues include:",
			}
			for i, f := range data.TopCritical {
				if i >= 3 {
					break
				}
				richParts = append(richParts, fmt.Sprintf("- %s [%s] affecting %s", f.Title, f.CVE, f.AffectedURL))
			}
			summaryParts = append(summaryParts, strings.Join(richParts, "\n"))
		}
		data.ExecutiveSummary = strings.Join(summaryParts, " ")
	} else {
		data.ExecutiveSummary = fmt.Sprintf("A security assessment was conducted on %s utilizing %d scanning engines over a period of %s. No vulnerabilities were identified during the assessment. The target demonstrates a strong security posture against the tested attack vectors.", target, len(tools), data.Duration)
	}

	// Build strategic recommendations
	if data.TotalVulns > 0 {
		recs := []string{}
		if data.SeverityBreakdown.Critical > 0 {
			recs = append(recs, "Immediately address all Critical severity findings. These vulnerabilities present an active and significant risk to the confidentiality, integrity, and availability of affected systems.")
		}
		if data.SeverityBreakdown.High > 0 {
			recs = append(recs, "Prioritize remediation of High severity findings within one week. These vulnerabilities can lead to sensitive data exposure or unauthorized access if exploited.")
		}
		if data.SeverityBreakdown.Medium > 0 {
			recs = append(recs, "Schedule remediation of Medium severity findings within the next monthly maintenance cycle. While less urgent, these weaknesses can be chained with other vulnerabilities for greater impact.")
		}
		recs = append(recs, "Establish a regular vulnerability scanning cadence to identify new security weaknesses as the application evolves and new threats emerge.")
		recs = append(recs, "Implement a secure development lifecycle (SDLC) program including security requirements, threat modeling, and security testing integrated into CI/CD pipelines.")
		recs = append(recs, "Conduct regular security awareness training for development teams focusing on the OWASP Top 10:2025 vulnerability categories identified in this assessment.")
		data.StrategicRecommendations = recs
	} else {
		data.StrategicRecommendations = []string{
			"Maintain the current security posture and continue regular vulnerability scanning to detect new issues as the application evolves.",
			"Consider expanding scan coverage by adding authenticated scanning, API endpoint testing, and internal network assessments.",
			"Implement continuous security monitoring and integrate security testing into the CI/CD pipeline for early vulnerability detection.",
		}
	}

	// Build observed strengths
	strengths := []string{}
	if data.SeverityBreakdown.Info > 0 {
		strengths = append(strengths, fmt.Sprintf("%d informational findings suggest comprehensive tool coverage and thorough scanning methodology.", data.SeverityBreakdown.Info))
	}
	if data.OWASPCoverage > 0 {
		strengths = append(strengths, fmt.Sprintf("Vulnerability mapping covers %d of 10 OWASP Top 10:2025 categories, indicating broad attack surface coverage in the assessment.", data.OWASPCoverage))
	}
	if data.CWECount > 0 {
		strengths = append(strengths, fmt.Sprintf("Findings are mapped across %d distinct CWE categories, providing granular classification for targeted remediation.", data.CWECount))
	}
	if len(tools) > 0 {
		strengths = append(strengths, fmt.Sprintf("Assessment leveraged %d distinct security scanning tools for comprehensive multi-vector coverage.", len(tools)))
	}
	if data.TotalVulns == 0 || (data.SeverityBreakdown.Critical == 0 && data.SeverityBreakdown.High == 0 && data.SeverityBreakdown.Medium == 0) {
		strengths = append(strengths, "No serious vulnerabilities were identified, suggesting effective existing security controls and development practices.")
	}
	if len(strengths) == 0 {
		strengths = append(strengths, "Assessment completed successfully with full tool chain coverage.")
	}
	data.ObservedStrengths = strengths

	return data
}

func (g *Generator) GenerateHTML(data ReportData) (string, error) {
	if err := os.MkdirAll(g.OutputDir, 0755); err != nil {
		return "", err
	}
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"percent": func(count, total int) string {
			if total == 0 {
				return "0%"
			}
			return fmt.Sprintf("%.0f%%", float64(count)/float64(total)*100)
		},
		"add": func(a, b int) int {
			return a + b
		},
		"owaspCategories": func() []string {
			return []string{
				"Broken Access Control",
				"Cryptographic Failures",
				"Injection",
				"Insecure Design",
				"Security Misconfiguration",
				"Vulnerable and Outdated Components",
				"Identification and Authentication Failures",
				"Software and Data Integrity Failures",
				"Security Logging and Monitoring Failures",
				"SSRF",
			}
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

	// ── Cover ──
	w("# Vulnerability Assessment Report\n\n")
	w("**Target:** %s  \n", data.Target)
	w("**Scan Date:** %s  \n", data.ScanDate)
	w("**Duration:** %s  \n", data.Duration)
	w("**Tools Deployed:** %d  \n", len(data.ToolsUsed))
	w("**Engine Version:** OmniScan %s  \n\n", data.Version)
	w("---\n\n")

	// ── 1. Executive Summary ──
	w("## 1. Executive Summary\n\n")
	w("%s\n\n", data.ExecutiveSummary)
	if data.TotalVulns > 0 {
		w("**Risk Posture:** %s  \n", data.RiskLabel)
		w("**Total Findings:** %d  \n", data.TotalVulns)
		w("**Average CVSS Score:** %.1f  \n", data.CVSSAvg)
		w("**CWE Categories Identified:** %d  \n", data.CWECount)
		w("**OWASP Top 10:2025 Coverage:** %d/10  \n\n", data.OWASPCoverage)
	}

	// ── 2. Scope & Methodology ──
	w("## 2. Scope & Methodology\n\n")
	w("### 2.1 Scope\n\n%s\n\n", data.Scope)
	w("### 2.2 Methodology\n\n%s\n\n", data.Methodology)
	w("**Standards & Frameworks:**  \n")
	w("- CVSS v3.1 — Common Vulnerability Scoring System  \n")
	w("- CWE — Common Weakness Enumeration  \n")
	w("- OWASP Top 10:2025 — Web Application Security Risks  \n")
	w("- EPSS — Exploit Prediction Scoring System  \n")
	w("- NVD — National Vulnerability Database  \n\n")
	w("**Tools Used:** %s  \n\n", strings.Join(data.ToolsUsed, ", "))

	// ── 3. Findings Summary ──
	w("## 3. Findings Summary\n\n")
	w("### 3.1 Severity Distribution\n\n")
	w("| Severity | Count |\n")
	w("|----------|-------|\n")
	w("| Critical | %d |\n", data.SeverityBreakdown.Critical)
	w("| High     | %d |\n", data.SeverityBreakdown.High)
	w("| Medium   | %d |\n", data.SeverityBreakdown.Medium)
	w("| Low      | %d |\n", data.SeverityBreakdown.Low)
	w("| Info     | %d |\n", data.SeverityBreakdown.Info)
	w("| **Total**| **%d** |\n\n", data.TotalVulns)

	if len(data.TopCritical) > 0 {
		w("### 3.2 Top Critical & High Severity Findings\n\n")
		w("| # | Severity | Title | CVE | URL |\n")
		w("|---|----------|-------|-----|-----|\n")
		for i, f := range data.TopCritical {
			cve := f.CVE
			if cve == "" {
				cve = "-"
			}
			w("| %d | %s | %s | %s | %s |\n", i+1, f.Severity, f.Title, cve, f.AffectedURL)
		}
		w("\n")
	}

	if len(data.OWASPCounts) > 0 {
		w("### 3.3 OWASP Top 10:2025 Coverage\n\n")
		w("| Category | Count |\n")
		w("|----------|-------|\n")
		for _, cat := range []string{
			"Broken Access Control", "Cryptographic Failures", "Injection",
			"Insecure Design", "Security Misconfiguration", "Vulnerable and Outdated Components",
			"Identification and Authentication Failures", "Software and Data Integrity Failures",
			"Security Logging and Monitoring Failures", "SSRF",
		} {
			count := data.OWASPCounts[cat]
			w("| %s | %d |\n", cat, count)
		}
		w("\n")
	}

	// ── 4. Observed Security Strengths ──
	w("## 4. Observed Security Strengths\n\n")
	if len(data.ObservedStrengths) == 0 {
		w("No specific strengths were identified during this assessment.\n\n")
	} else {
		for i, s := range data.ObservedStrengths {
			w("%d. %s\n", i+1, s)
		}
		w("\n")
	}

	// ── 5. Detailed Findings ──
	w("## 5. Detailed Findings\n\n")
	if len(data.Findings) == 0 {
		w("No vulnerabilities were identified during the assessment.\n\n")
	} else {
		w("| # | Severity | Title | CVE | CWE | CVSS | EPSS | URL | Tool |\n")
		w("|---|----------|-------|-----|-----|------|------|-----|------|\n")
		for i, f := range data.Findings {
			cve := f.CVE
			if cve == "" {
				cve = "-"
			}
			cwe := ""
			if len(f.CWE) > 0 {
				cwe = f.CWE[0]
			}
			cvss := fmt.Sprintf("%.1f", f.CVSS)
			if f.CVSS == 0 {
				cvss = "-"
			}
			epss := ""
			if f.EPSS > 0 {
				epss = fmt.Sprintf("%.4f", f.EPSS)
			} else {
				epss = "-"
			}
			w("| %d | %s | %s | %s | %s | %s | %s | %s | %s |\n",
				i+1, f.Severity, f.Title, cve, cwe, cvss, epss, f.AffectedURL, f.ToolSource)
		}
		w("\n")

		// Per-finding details
		w("### 5.1 Finding Details\n\n")
		for i, f := range data.Findings {
			w("#### Finding %d: [%s] %s\n\n", i+1, f.Severity, f.Title)
			if f.Description != "" {
				w("**Description:** %s\n\n", f.Description)
			}
			w("- **Severity:** %s  \n", f.Severity)
			w("- **Tool:** %s  \n", f.ToolSource)
			if f.AffectedURL != "" {
				w("- **Affected URL:** `%s`  \n", f.AffectedURL)
			}
			if f.CVE != "" {
				w("- **CVE:** %s  \n", f.CVE)
			}
			if len(f.CWE) > 0 {
				w("- **CWE:** %s  \n", strings.Join(f.CWE, ", "))
			}
			if f.OWASP2025 != "" {
				w("- **OWASP:** %s  \n", f.OWASP2025)
			}
			if f.CVSS > 0 {
				w("- **CVSS Score:** %.1f  \n", f.CVSS)
				if f.CVSSVector != "" {
					w("- **CVSS Vector:** `%s`  \n", f.CVSSVector)
				}
			}
			if f.EPSS > 0 {
				w("- **EPSS Score:** %.4f  \n", f.EPSS)
			}
			if f.Proof != "" {
				w("- **Proof:** `%s`  \n", f.Proof)
			}
			if f.Remediation != "" {
				w("\n**Remediation:** %s  \n", f.Remediation)
			}
			w("\n---\n\n")
		}
	}

	// ── 6. Strategic Recommendations ──
	w("## 6. Strategic Recommendations\n\n")
	if len(data.StrategicRecommendations) == 0 {
		w("No specific recommendations at this time.\n\n")
	} else {
		for i, r := range data.StrategicRecommendations {
			w("%d. %s\n\n", i+1, r)
		}
	}

	// ── Appendix ──
	w("## Appendix A: Severity Reference\n\n")
	w("| Severity | CVSS Range | Description |\n")
	w("|----------|------------|-------------|\n")
	w("| Critical | 9.0–10.0   | Exploitation is trivial and can lead to complete system compromise |\n")
	w("| High     | 7.0–8.9    | Significant impact; exploitation likely with moderate skill |\n")
	w("| Medium   | 4.0–6.9    | Notable risk; exploitation possible under specific conditions |\n")
	w("| Low      | 0.1–3.9    | Limited impact; requires chaining or special circumstances |\n")
	w("| Info     | 0.0        | Informational; does not represent a security risk |\n\n")

	w("---\n\n")
	w("*Report generated by OmniScan %s — EliTechWiz/github.com/Eliahhango*\n", data.Version)
	w("*Assessment conducted on %s*\n", data.ScanDate)

	return path, nil
}

func (g *Generator) GeneratePDF(data ReportData) (string, error) {
	if err := os.MkdirAll(g.OutputDir, 0755); err != nil {
		return "", err
	}
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"percent": func(count, total int) string {
			if total == 0 {
				return "0%"
			}
			return fmt.Sprintf("%.0f%%", float64(count)/float64(total)*100)
		},
		"add": func(a, b int) int {
			return a + b
		},
		"owaspCategories": func() []string {
			return []string{
				"Broken Access Control",
				"Cryptographic Failures",
				"Injection",
				"Insecure Design",
				"Security Misconfiguration",
				"Vulnerable and Outdated Components",
				"Identification and Authentication Failures",
				"Software and Data Integrity Failures",
				"Security Logging and Monitoring Failures",
				"SSRF",
			}
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

	sw := func(s string) {
		w("%s\n", s)
	}
	sep := func() { sw(strings.Repeat("=", 72)) }
	dash := func() { sw(strings.Repeat("-", 72)) }

	sep()
	w("  VULNERABILITY ASSESSMENT REPORT\n")
	sep()
	w("  Target:    %s\n", data.Target)
	w("  Date:      %s\n", data.ScanDate)
	w("  Duration:  %s\n", data.Duration)
	w("  Tools:     %d engines\n", len(data.ToolsUsed))
	w("  Version:   OmniScan %s\n", data.Version)
	sep()
	sw("")

	// Executive Summary
	sw("1. EXECUTIVE SUMMARY")
	dash()
	sw(data.ExecutiveSummary)
	sw("")
	if data.TotalVulns > 0 {
		w("  Risk Posture:           %s\n", data.RiskLabel)
		w("  Total Findings:         %d\n", data.TotalVulns)
		w("  Average CVSS Score:     %.1f\n", data.CVSSAvg)
		w("  CWE Categories:         %d\n", data.CWECount)
		w("  OWASP Top 10 Coverage:  %d/10\n", data.OWASPCoverage)
		sw("")
	}

	// Scope & Methodology
	sw("2. SCOPE & METHODOLOGY")
	dash()
	sw("  Scope:")
	sw("  " + data.Scope)
	sw("")
	sw("  Methodology:")
	sw("  " + data.Methodology)
	sw("")
	w("  Tools Used: %s\n", strings.Join(data.ToolsUsed, ", "))
	sw("")

	// Severity Distribution
	sw("3. FINDINGS SUMMARY")
	dash()
	sw("  3.1 Severity Distribution")
	sw("")
	w("  %-12s %s\n", "Severity", "Count")
	w("  %-12s %s\n", "--------", "-----")
	w("  %-12s %3d\n", "Critical", data.SeverityBreakdown.Critical)
	w("  %-12s %3d\n", "High", data.SeverityBreakdown.High)
	w("  %-12s %3d\n", "Medium", data.SeverityBreakdown.Medium)
	w("  %-12s %3d\n", "Low", data.SeverityBreakdown.Low)
	w("  %-12s %3d\n", "Info", data.SeverityBreakdown.Info)
	w("  %-12s %3d\n", "Total", data.TotalVulns)
	sw("")

	if len(data.TopCritical) > 0 {
		sw("  3.2 Top Critical & High Findings")
		sw("")
		for i, f := range data.TopCritical {
			cve := f.CVE
			if cve == "" {
				cve = "-"
			}
			w("  %d. [%s] %s (CVE: %s)\n", i+1, f.Severity, f.Title, cve)
			w("      URL: %s\n", f.AffectedURL)
		}
		sw("")
	}

	// Strengths
	sw("4. OBSERVED STRENGTHS")
	dash()
	if len(data.ObservedStrengths) == 0 {
		sw("  No specific strengths identified.")
	} else {
		for i, s := range data.ObservedStrengths {
			w("  %d. %s\n", i+1, s)
		}
	}
	sw("")

	// Detailed Findings
	sw("5. DETAILED FINDINGS")
	dash()
	if len(data.Findings) == 0 {
		sw("  No vulnerabilities were identified.")
		sw("")
	} else {
		for i, f := range data.Findings {
			w("  5.%d Finding: [%s] %s\n", i+1, f.Severity, f.Title)
			dash()
			if f.Description != "" {
				sw("  " + f.Description)
				sw("")
			}
			w("    Severity:     %s\n", f.Severity)
			w("    Tool:         %s\n", f.ToolSource)
			if f.AffectedURL != "" {
				w("    URL:          %s\n", f.AffectedURL)
			}
			if f.AffectedParam != "" {
				w("    Parameter:    %s\n", f.AffectedParam)
			}
			if f.CVE != "" {
				w("    CVE:          %s\n", f.CVE)
			}
			if len(f.CWE) > 0 {
				w("    CWE:          %s\n", strings.Join(f.CWE, ", "))
			}
			if f.OWASP2025 != "" {
				w("    OWASP:        %s\n", f.OWASP2025)
			}
			if f.CVSS > 0 {
				w("    CVSS:         %.1f\n", f.CVSS)
			}
			if f.EPSS > 0 {
				w("    EPSS:         %.4f\n", f.EPSS)
			}
			if f.Proof != "" {
				w("    Proof:        %s\n", f.Proof)
			}
			if f.Remediation != "" {
				w("    Remediation:  %s\n", f.Remediation)
			}
			sw("")
		}
	}

	// Recommendations
	sw("6. STRATEGIC RECOMMENDATIONS")
	dash()
	if len(data.StrategicRecommendations) == 0 {
		sw("  No specific recommendations at this time.")
	} else {
		for i, r := range data.StrategicRecommendations {
			w("  %d. %s\n", i+1, r)
		}
	}
	sw("")

	// Severity Reference
	sw("APPENDIX A: SEVERITY REFERENCE")
	dash()
	sw("  Critical  9.0-10.0  Exploitation is trivial; complete compromise")
	sw("  High      7.0-8.9   Significant impact; exploitation likely")
	sw("  Medium    4.0-6.9   Notable risk; specific conditions needed")
	sw("  Low       0.1-3.9   Limited impact; special circumstances")
	sw("  Info      0.0       Informational only")
	sw("")
	sep()

	sw("")
	w("Report generated by OmniScan %s\n", data.Version)
	w("Assessment conducted on %s\n", data.ScanDate)
	w("https://github.com/Eliahhango/OmniScan\n")

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
