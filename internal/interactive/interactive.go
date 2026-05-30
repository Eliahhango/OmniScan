package interactive

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Eliahhango/OmniScan/internal/config"
	"github.com/Eliahhango/OmniScan/internal/db"
	"github.com/Eliahhango/OmniScan/internal/report"
	"github.com/Eliahhango/OmniScan/internal/scanner"
	"github.com/Eliahhango/OmniScan/pkg/types"
)

type ScanCategory struct {
	Number  string
	Name    string
	Desc    string
	Scanners []string // names of CustomChecks + external tools
}

var scanCategories = []ScanCategory{
	{
		Number: "0", Name: "Basic Recon",
		Desc:    "DNS records, WHOIS, Geo-IP, security headers, CMS detection, social links",
		Scanners: []string{"dns-records", "whois-lookup", "geo-ip-lookup", "security-headers", "cms-detection", "error-disclosure", "social-links"},
	},
	{
		Number: "1", Name: "Subdomain Enumeration",
		Desc:    "DNS brute-force, subdomain takeover, S3 bucket enum, CORS",
		Scanners: []string{"subdomain-enum", "subdomain-takeover", "s3-bucket-enum", "cors-misconfig"},
	},
	{
		Number: "2", Name: "Web Crawler & Discovery",
		Desc:    "URL extraction, admin panels, git exposure, exposed endpoints",
		Scanners: []string{"url-crawler", "git-exposure", "exposed-endpoints", "websocket-vulns"},
	},
	{
		Number: "3", Name: "Web Vulnerability Scan",
		Desc:    "SQLi, XSS, SSRF, Path Traversal, Open Redirect, Command Injection",
		Scanners: []string{"sqli-detection", "xss-stored-dom", "ssrf-detection", "path-traversal", "open-redirect", "command-injection"},
	},
	{
		Number: "4", Name: "Advanced Attacks",
		Desc:    "XXE, Deserialization, SSTI, HTTP Smuggling, Prototype Pollution",
		Scanners: []string{"xxe-detection", "deserialization", "ssti-detection", "http-smuggling", "prototype-pollution"},
	},
	{
		Number: "5", Name: "Web Security Audit",
		Desc:    "CSRF, CORS, JWT, Rate Limiting, Cache Poisoning, Host Header, CRLF, 2FA",
		Scanners: []string{"csrf-detection", "cors-misconfig", "jwt-attacks", "rate-limiting", "cache-poisoning", "host-header-injection", "crlf-injection", "2fa-bypass"},
	},
	{
		Number: "6", Name: "Port Scanning",
		Desc:    "Quick TCP port scan on common ports",
		Scanners: []string{"port-scan"},
	},
	{
		Number: "7", Name: "Secrets & SAST",
		Desc:    "JS secrets, error disclosure, IDOR detection, race condition",
		Scanners: []string{"js-secrets", "error-disclosure", "idor-detection", "race-condition"},
	},
	{
		Number: "8", Name: "Fuzzing & Bruteforce",
		Desc:    "Rate limiting tests, parameter discovery",
		Scanners: []string{"rate-limiting"},
	},
	{
		Number: "9", Name: "External Scanners (full scan only)",
		Desc:    "Nuclei, ZAP, Nikto, OpenVAS — run via [A] Scan Everything",
		Scanners: []string{},
	},
	{
		Number: "10", Name: "CMS & Technology Detection",
		Desc:    "CMS fingerprint, tech fingerprint, GraphQL, Account Takeover, S3",
		Scanners: []string{"tech-fingerprint", "cms-detection", "graphql-introspection", "account-takeover", "s3-bucket-enum"},
	},
	{
		Number: "11", Name: "Threat Intelligence",
		Desc:    "CISA KEV, EPSS scoring, tech fingerprint",
		Scanners: []string{"cisa-kev", "epss-score", "tech-fingerprint"},
	},
}

func Run() {
	reader := bufio.NewReader(os.Stdin)
	protocol := "https://"
	cfg, err := config.Load("omniscan.yaml")
	if err != nil {
		cfg, _ = config.Defaults()
	}

	printBanner()

thephuckinstart:
	fmt.Println()
	fmt.Print("  Enter the website you want to scan (e.g., example.com): ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)

	if target == "" || strings.Contains(target, "://") || !strings.Contains(target, ".") {
		fmt.Println("  Invalid target. Enter a domain without http://")
		goto thephuckinstart
	}

	fmt.Println()
	fmt.Print("  Enter 1 for HTTP or 2 for HTTPS [2]: ")
	proto, _ := reader.ReadString('\n')
	proto = strings.TrimSpace(proto)
	if strings.TrimSpace(proto) == "1" {
		protocol = "http://"
	} else {
		protocol = "https://"
	}

scanlist:
	fmt.Println()
	printScanList(target, protocol)

askscan:
	fmt.Println()
	fmt.Print("  Choose scan or action from the list above: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(strings.ToUpper(choice))

	switch {
	case choice == "Q":
		fmt.Print("\n  Goodbye!\n")
		return

	case choice == "B":
		goto thephuckinstart

	case choice == "A":
		runAllScans(cfg, target, protocol, reader)

	case choice >= "0" && choice <= "9", choice == "10", choice == "11":
		cat := findCategory(choice)
		if cat != nil {
			runCategory(cfg, target, protocol, cat, reader)
		} else {
			fmt.Println("  Invalid option!")
			goto askscan
		}
	case choice == "12":
		runCustomPicker(cfg, target, protocol, reader)

	default:
		fmt.Println("  Invalid option!")
		goto askscan
	}

	fmt.Println()
	fmt.Print("  Press Enter to continue...")
	reader.ReadString('\n')
	goto scanlist
}

func printBanner() {
	fmt.Println(`
   ___                        _   ____
  / _ \   _ __ ___    _ __   (_) / ___|    ___    __ _   _ __
 | | | | | '_ ` + "`" + ` _ \  | '_ \  | | \___ \   / __|  / _` + "`" + ` | | '_ \
 | |_| | | | | | | | | | | | | |  ___) | | (__  | (_| | | | | |
  \___/  |_| |_| |_| |_| |_| |_| |____/   \___|  \__,_| |_| |_|`)

	fmt.Println("  Unified Vulnerability Hunting Platform — 13 tools, one interface.")
	fmt.Println("  ─────────────────────────────────────────────────────────────")
	fmt.Println("  Developer: EliTechWiz (Eliah Hango)")
	fmt.Println("  GitHub:    https://github.com/Eliahhango")
	fmt.Println("  Website:   https://elitechwiz.com")
	fmt.Println("  Telegram:  @techarmyy")
	fmt.Println("  ─────────────────────────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Interactive Mode — Select scans by number, A for all, B for back, Q to quit")
	fmt.Println("  ────────────────────────────────────────────────────────────────────────────")
}

func printScanList(target, protocol string) {
	fmt.Printf("  Scanning site: %s%s\n\n", protocol, target)
	fmt.Println("  Available scan categories:")
	fmt.Println("  ───────────────────────────")

	for _, cat := range scanCategories {
		fmt.Printf("  [%s] %s\n", cat.Number, cat.Name)
		fmt.Printf("       %s\n", cat.Desc)
	}

	fmt.Println("  [12] Custom — Pick individual scanners by number")
	fmt.Println("  [A]  Scan Everything — Full comprehensive scan (includes external tools)")
	fmt.Println("  [B]  Back — Enter a new target")
	fmt.Println("  [Q]  Quit")
	fmt.Println("  ────────────────────────────────────────────────────────────────────────────")
	fmt.Println("  Note: External tools (Nuclei, Nmap, ZAP, Nikto, etc.) only run via [A].")
}

func findCategory(num string) *ScanCategory {
	for _, cat := range scanCategories {
		if cat.Number == num {
			return &cat
		}
	}
	return nil
}

func runAllScans(cfg *config.Config, target, protocol string, reader *bufio.Reader) {
	fmt.Printf("\n  Running full comprehensive scan on %s%s\n", protocol, target)
	fmt.Println("  This will run ALL scanners, including external tools if available")
	fmt.Println()

	store, err := db.New(cfg.DBPath, cfg.Passphrase)
	if err != nil {
		fmt.Printf("  Database unavailable: %v\n", err)
		return
	}
	defer store.Close()

	allFindings := runOrchestrator(cfg, store, target, reader)
	if len(allFindings) > 0 {
		generateReport(allFindings, target, cfg.OutputDir, reader)
	}
}

func runCategory(cfg *config.Config, target, protocol string, cat *ScanCategory, reader *bufio.Reader) {
	fmt.Printf("\n  Running %s on %s%s\n", cat.Name, protocol, target)
	fmt.Println()

	selected := make(map[string]bool)
	for _, name := range cat.Scanners {
		selected[name] = true
	}

	findings := runCustomScanners(target, selected)
	if len(findings) > 0 {
		generateReport(findings, target, cfg.OutputDir, reader)
	} else {
		fmt.Println("  No findings from selected scanners.")
	}
}

type scanConfig struct {
	name   string
	runFn  func(context.Context, *scanner.Orchestrator, string, int64) error
}

func runOrchestrator(cfg *config.Config, store *db.Store, target string, reader *bufio.Reader) []types.Finding {
	orchCfg := &scanner.OrchestratorConfig{
		Target:      target,
		Concurrency: cfg.Concurrency,
		RateLimit:   cfg.RateLimit,
		OutputDir:   cfg.OutputDir,
		ToolsDir:    cfg.ToolsDir,
		DBPath:      cfg.DBPath,
	}
	orch := scanner.NewOrchestrator(orchCfg, store)

	numStages := 0
	orch.OnStage = func(stage types.ScanStage, tool string, progress float64) {
		name := types.StageNames[stage]
		if tool != "" {
			fmt.Printf("  [%s] %s\n", name, tool)
		} else {
			numStages++
			fmt.Printf("  Phase %d: %s...\n", numStages, name)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	var allFindings []types.Finding
	var mu sync.Mutex

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for finding := range orch.Results() {
			mu.Lock()
			allFindings = append(allFindings, finding)
			mu.Unlock()
			fmt.Printf("  [%s] %s - %s (%s)\n", finding.Severity, finding.Title, finding.AffectedURL, finding.ToolSource)
		}
	}()

	if err := orch.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "  Scan error: %v\n", err)
	}
	wg.Wait()

	fmt.Printf("\n  Scan complete. Total findings: %d\n\n", len(allFindings))
	return allFindings
}

func generateReport(findings []types.Finding, target, outputDir string, reader *bufio.Reader) {
	reporter := report.NewGenerator(outputDir)
	toolSet := make(map[string]bool)
	for _, f := range findings {
		toolSet[f.ToolSource] = true
	}
	tools := make([]string, 0, len(toolSet))
	for t := range toolSet {
		tools = append(tools, t)
	}

	data := reporter.BuildReportData(target, findings, time.Minute, tools)

	fmt.Println("  Available formats: html, pdf, markdown, json, csv, txt, all, skip")
	fmt.Print("  Report format [html]: ")
	format, _ := reader.ReadString('\n')
	format = strings.TrimSpace(format)
	if format == "" {
		format = "html"
	}

	var filePath string
	var genErr error

	switch strings.ToLower(format) {
	case "html":
		filePath, genErr = reporter.GenerateHTML(data)
	case "pdf":
		filePath, genErr = reporter.GeneratePDF(data)
	case "markdown", "md":
		filePath, genErr = reporter.GenerateMarkdown(data)
	case "json":
		filePath, genErr = reporter.GenerateJSON(data)
	case "csv":
		filePath, genErr = reporter.GenerateCSV(data)
	case "txt":
		filePath, genErr = reporter.GenerateTXT(data)
	case "all":
		formats := []struct {
			name string
			fn   func(report.ReportData) (string, error)
		}{
			{"html", reporter.GenerateHTML},
			{"markdown", reporter.GenerateMarkdown},
			{"json", reporter.GenerateJSON},
			{"csv", reporter.GenerateCSV},
			{"pdf", reporter.GeneratePDF},
			{"txt", reporter.GenerateTXT},
		}
		for _, f := range formats {
			if p, err := f.fn(data); err == nil {
				fmt.Printf("  Report saved: %s\n", p)
			}
		}
		return
	case "skip":
		return
	default:
		filePath, genErr = reporter.GenerateHTML(data)
	}

	if genErr != nil {
		fmt.Printf("  Report error: %v\n", genErr)
		return
	}
	fmt.Printf("  Report saved: %s\n", filePath)
}

func runCustomPicker(cfg *config.Config, target, protocol string, reader *bufio.Reader) {
	fmt.Println("\n  Custom scanner selection — pick individual scanners by number")
	fmt.Println("  ─────────────────────────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  [C] Cancel")
	fmt.Println()
	for i, c := range scanner.CustomChecks {
		fmt.Printf("  [%d] %s — %s\n", i, c.Name, c.Description)
	}
	fmt.Println()

	fmt.Print("  Enter scanner numbers (comma-separated, e.g. 0,1,5): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if strings.ToUpper(input) == "C" || input == "" {
		return
	}

	parts := strings.Split(input, ",")
	selected := make(map[string]bool)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		idx := 0
		if _, err := fmt.Sscanf(p, "%d", &idx); err == nil && idx >= 0 && idx < len(scanner.CustomChecks) {
			selected[scanner.CustomChecks[idx].Name] = true
		}
	}

	if len(selected) == 0 {
		fmt.Println("  No valid scanners selected.")
		return
	}

	fmt.Printf("  Running %d selected scanners...\n", len(selected))

	findings := runCustomScanners(target, selected)
	if len(findings) > 0 {
		generateReport(findings, target, cfg.OutputDir, reader)
	} else {
		fmt.Println("  No findings from selected scanners.")
	}
}

func runCustomScanners(target string, selected map[string]bool) []types.Finding {
	var findings []types.Finding
	for _, c := range scanner.CustomChecks {
		if !selected[c.Name] {
			continue
		}
		fmt.Printf("  Running: %s\n", c.Name)
		f, err := c.Check(target)
		if err != nil {
			fmt.Printf("  Error in %s: %v\n", c.Name, err)
			continue
		}
		findings = append(findings, f...)
		for _, fv := range f {
			fmt.Printf("  [%s] %s - %s\n", fv.Severity, fv.Title, fv.AffectedURL)
		}
	}
	return findings
}
