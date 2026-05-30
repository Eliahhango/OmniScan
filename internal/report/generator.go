package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
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

	return data
}

func (g *Generator) GenerateHTML(data ReportData) (string, error) {
	if err := os.MkdirAll(g.OutputDir, 0755); err != nil {
		return "", err
	}
	funcMap := template.FuncMap{
		"percent": func(count, total int) string {
			if total == 0 {
				return "0%"
			}
			return fmt.Sprintf("%.0f%%", float64(count)/float64(total)*100)
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
		"percent": func(count, total int) string {
			if total == 0 {
				return "0%"
			}
			return fmt.Sprintf("%.0f%%", float64(count)/float64(total)*100)
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
