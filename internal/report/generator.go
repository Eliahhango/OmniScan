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

	fmt.Fprintf(f, "# Security Report: %s\n\n", data.Target)
	fmt.Fprintf(f, "**Scan Date:** %s\n", data.ScanDate)
	fmt.Fprintf(f, "**Duration:** %s\n", data.Duration)
	fmt.Fprintf(f, "**Total Vulnerabilities:** %d\n\n", data.TotalVulns)

	fmt.Fprintf(f, "## Severity Breakdown\n")
	fmt.Fprintf(f, "- Critical: %d\n", data.SeverityBreakdown.Critical)
	fmt.Fprintf(f, "- High: %d\n", data.SeverityBreakdown.High)
	fmt.Fprintf(f, "- Medium: %d\n", data.SeverityBreakdown.Medium)
	fmt.Fprintf(f, "- Low: %d\n", data.SeverityBreakdown.Low)
	fmt.Fprintf(f, "- Info: %d\n\n", data.SeverityBreakdown.Info)

	fmt.Fprintf(f, "## Findings\n\n")
	for _, finding := range data.Findings {
		fmt.Fprintf(f, "### [%s] %s\n", finding.Severity, finding.Title)
		if finding.CVE != "" {
			fmt.Fprintf(f, "- CVE: %s\n", finding.CVE)
		}
		if len(finding.CWE) > 0 {
			fmt.Fprintf(f, "- CWE: %s\n", finding.CWE)
		}
		if finding.AffectedURL != "" {
			fmt.Fprintf(f, "- URL: %s\n", finding.AffectedURL)
		}
		fmt.Fprintf(f, "\n")
	}

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
