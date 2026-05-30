package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/Eliahhango/OmniScan/internal/config"
	"github.com/Eliahhango/OmniScan/internal/daemon"
	"github.com/Eliahhango/OmniScan/internal/db"
	"github.com/Eliahhango/OmniScan/internal/report"
	"github.com/Eliahhango/OmniScan/internal/scanner"
	"github.com/Eliahhango/OmniScan/internal/tui"
	"github.com/Eliahhango/OmniScan/pkg/types"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("OmniScan - Unified Vulnerability Hunting Platform")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  omniscan tui                      Launch interactive TUI")
		fmt.Println("  omniscan scan [flags] <target>    Run scan")
		fmt.Println("  omniscan diff <id1> <id2>         Compare two scans")
		fmt.Println("  omniscan daemon [--listen :8080]  Start daemon server")
		fmt.Println("  omniscan setup                    Install all 13 tools")
		fmt.Println("  omniscan bounty <target>          Bug bounty mode")
		fmt.Println()
		fmt.Println("Flags:")
		fmt.Println("  -t <target>         Scan target (domain or IP)")
		fmt.Println("  -program            Bug bounty program name")
		fmt.Println("  -resume             Resume from last checkpoint")
		fmt.Println("  -config <path>      Config file path")
		fmt.Println("  -json               Output findings as JSON lines")
		fmt.Println("  -exit-on-severity   Exit non-zero if any finding >= severity (critical|high|medium|low)")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  omniscan tui")
		fmt.Println("  omniscan scan -t example.com")
		fmt.Println("  omniscan scan --json --exit-on-severity=high -t example.com")
		fmt.Println("  omniscan diff 1 2")
		fmt.Println("  omniscan daemon --listen :9090")
		fmt.Println("  omniscan bounty -t example.com -program hackerone")
		fmt.Println("  omniscan setup")
		return
	}

	cmd := os.Args[1]
	configPath := "omniscan.yaml"

	switch cmd {
	case "tui":
		runTUI(configPath)
	case "scan":
		runScan(configPath)
	case "diff":
		runDiff()
	case "daemon":
		runDaemon(configPath)
	case "setup":
		runSetup()
	case "bounty":
		runBounty(configPath)
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

func runTUI(configPath string) {
	app := tui.NewApp()

	target := ""
	for i, arg := range os.Args {
		if arg == "-t" && i+1 < len(os.Args) {
			target = os.Args[i+1]
			break
		}
	}
	if target == "" {
		target = "target.com"
	}
	app.SetTarget(target)

	cfg, err := config.Load(configPath)
	if err != nil {
		cfg = config.Defaults()
	}

	store, err := db.New(cfg.DBPath, cfg.Passphrase)
	if err == nil {
		defer store.Close()
		orchCfg := &scanner.OrchestratorConfig{
			Target:      target,
			Concurrency: cfg.Concurrency,
			RateLimit:   cfg.RateLimit,
			OutputDir:   cfg.OutputDir,
			ToolsDir:    cfg.ToolsDir,
			DBPath:      cfg.DBPath,
		}
		orch := scanner.NewOrchestrator(orchCfg, store)
		app.SetOrchestrator(orch)
	}

	prog := tea.NewProgram(app, tea.WithAltScreen())
	app.SetProgram(prog)

	if _, err := prog.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runScan(configPath string) {
	target := ""
	resume := false
	jsonOutput := false
	exitOnSeverity := types.Severity("")

	for i, arg := range os.Args {
		switch arg {
		case "-t":
			if i+1 < len(os.Args) {
				target = os.Args[i+1]
			}
		case "-resume":
			resume = true
		case "-json":
			jsonOutput = true
		case "-exit-on-severity":
			if i+1 < len(os.Args) {
				exitOnSeverity = types.Severity(os.Args[i+1])
			}
		}
	}
	if target == "" && len(os.Args) > 2 {
		for _, a := range os.Args[2:] {
			if !isFlag(a) {
				target = a
				break
			}
		}
	}
	if target == "" {
		fmt.Println("Error: target required. Usage: omniscan scan -t <target>")
		os.Exit(1)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Printf("Warning: could not load config: %v\n", err)
		cfg = config.Defaults()
	}

	store, err := db.New(cfg.DBPath, cfg.Passphrase)
	if err != nil {
		fmt.Printf("Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	orchCfg := &scanner.OrchestratorConfig{
		Target:      target,
		Concurrency: cfg.Concurrency,
		RateLimit:   cfg.RateLimit,
		OutputDir:   cfg.OutputDir,
		ToolsDir:    cfg.ToolsDir,
		Resume:      resume,
		DBPath:      cfg.DBPath,
	}

	orch := scanner.NewOrchestrator(orchCfg, store)

	// Print progress in CLI mode (emitProgress is a no-op without this)
	if !jsonOutput {
		stageNum := 0
		orch.OnStage = func(stage types.ScanStage, tool string, progress float64) {
			if tool != "" {
				stageName := types.StageNames[stage]
				fmt.Printf("  [%d/7] %s: %s\n", stageNum+1, stageName, tool)
			} else {
				stageNum = int(stage)
				fmt.Printf("  [%d/7] %s...\n", stageNum+1, types.StageNames[stage])
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()

	if !jsonOutput {
		fmt.Printf("Starting scan on %s...\n", target)
	}
	start := time.Now()

	var allFindings []types.Finding
	var mu sync.Mutex
	toolSet := make(map[string]bool)
	var highestSeverity types.Severity
	var readWg sync.WaitGroup

	readWg.Add(1)
	go func() {
		defer readWg.Done()
		for finding := range orch.Results() {
			mu.Lock()
			allFindings = append(allFindings, finding)
			if severityRank[finding.Severity] > severityRank[highestSeverity] {
				highestSeverity = finding.Severity
			}
			toolSet[finding.ToolSource] = true
			mu.Unlock()

			if jsonOutput {
				line, _ := json.Marshal(finding)
				fmt.Println(string(line))
			} else {
				fmt.Printf("[%s] %s - %s (%s)\n", finding.Severity, finding.Title, finding.AffectedURL, finding.ToolSource)
			}
		}
	}()

	readWg.Add(1)
	go func() {
		defer readWg.Done()
		for err := range orch.Errors() {
			if jsonOutput {
				line, _ := json.Marshal(map[string]string{"error": err.Error()})
				fmt.Fprintln(os.Stderr, string(line))
			} else {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			}
		}
	}()

	if err := orch.Run(ctx); err != nil {
		if jsonOutput {
			line, _ := json.Marshal(map[string]string{"error": err.Error()})
			fmt.Fprintln(os.Stderr, string(line))
		} else {
			fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		}
		os.Exit(1)
	}

	readWg.Wait()

	duration := time.Since(start)
	if !jsonOutput {
		fmt.Printf("\nScan completed in %s\n", duration)
		fmt.Printf("Total findings: %d\n", len(allFindings))
	}

	if exitOnSeverity != "" && severityRank[highestSeverity] >= severityRank[exitOnSeverity] {
		os.Exit(1)
	}

	// Generate report
	if jsonOutput {
		return
	}
	generateScanReport(target, allFindings, duration, toolSet, cfg.OutputDir)
}

func generateScanReport(target string, findings []types.Finding, duration time.Duration, toolSet map[string]bool, outputDir string) {
	fmt.Println()
	fmt.Println("================================================")
	fmt.Println("  SCAN COMPLETE — Generate Report")
	fmt.Println("================================================")
	fmt.Println("  Available formats: html, pdf, markdown, json, csv, all")
	fmt.Println("  Enter nothing to skip.")
	fmt.Print("  Report format [html]: ")

	reader := bufio.NewReader(os.Stdin)
	format, _ := reader.ReadString('\n')
	format = strings.TrimSpace(format)
	if format == "" {
		format = "html"
	}

	if format == "all" || format == "skip" {
		if format == "skip" {
			fmt.Println("  Skipping report generation.")
			return
		}
	}

	reporter := report.NewGenerator(outputDir)
	tools := make([]string, 0, len(toolSet))
	for t := range toolSet {
		tools = append(tools, t)
	}
	data := reporter.BuildReportData(target, findings, duration, tools)

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
	case "all":
		paths := make([]string, 0, 5)
		formats := []struct {
			name string
			fn   func(report.ReportData) (string, error)
		}{
			{"html", reporter.GenerateHTML},
			{"markdown", reporter.GenerateMarkdown},
			{"json", reporter.GenerateJSON},
			{"csv", reporter.GenerateCSV},
			{"pdf", reporter.GeneratePDF},
		}
		for _, f := range formats {
			if p, err := f.fn(data); err == nil {
				paths = append(paths, p)
			} else {
				fmt.Printf("  [!] %s: %v\n", f.name, err)
			}
		}
		fmt.Println("\n  Reports generated:")
		for _, p := range paths {
			fmt.Printf("    • %s\n", p)
		}
		return
	default:
		fmt.Printf("  Unknown format: %s. Generating HTML instead.\n", format)
		filePath, genErr = reporter.GenerateHTML(data)
	}

	if genErr != nil {
		fmt.Printf("  [!] Error generating %s report: %v\n", format, genErr)
		return
	}
	fmt.Printf("\n  Report saved to: %s\n", filePath)
}

var severityRank = map[types.Severity]int{
	types.SeverityCritical: 4,
	types.SeverityHigh:     3,
	types.SeverityMedium:   2,
	types.SeverityLow:      1,
	types.SeverityInfo:     0,
	"":                     0,
}

func isFlag(s string) bool {
	return len(s) > 0 && s[0] == '-'
}

func runDiff() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: omniscan diff <scan_id_1> <scan_id_2>")
		os.Exit(1)
	}
	var id1, id2 int64
	fmt.Sscanf(os.Args[2], "%d", &id1)
	fmt.Sscanf(os.Args[3], "%d", &id2)
	if id1 == 0 || id2 == 0 {
		fmt.Println("Invalid scan IDs")
		os.Exit(1)
	}

	cfg, err := config.Load("omniscan.yaml")
	if err != nil {
		cfg = config.Defaults()
	}
	store, err := db.New(cfg.DBPath, cfg.Passphrase)
	if err != nil {
		fmt.Printf("Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	s1, _ := store.GetScan(id1)
	s2, _ := store.GetScan(id2)

	f1, _ := store.GetFindings(id1)
	f2, _ := store.GetFindings(id2)

	f1set := make(map[string]bool, len(f1))
	for _, f := range f1 {
		f1set[f.ID] = true
	}
	f2set := make(map[string]bool, len(f2))
	for _, f := range f2 {
		f2set[f.ID] = true
	}

	var added, fixed []types.Finding
	for _, f := range f2 {
		if !f1set[f.ID] {
			added = append(added, f)
		}
	}
	for _, f := range f1 {
		if !f2set[f.ID] {
			fixed = append(fixed, f)
		}
	}

	fmt.Printf("Scan %d vs Scan %d\n", id1, id2)
	if s1 != nil {
		fmt.Printf("  Scan %d: %s (%s, %d findings)\n", id1, s1.Target, s1.Status, len(f1))
	}
	if s2 != nil {
		fmt.Printf("  Scan %d: %s (%s, %d findings)\n", id2, s2.Target, s2.Status, len(f2))
	}

	fmt.Printf("\nNew findings: %d\n", len(added))
	for _, f := range added {
		fmt.Printf("  [+] [%s] %s - %s (%s)\n", f.Severity, f.Title, f.AffectedURL, f.ToolSource)
	}

	fmt.Printf("\nFixed findings: %d\n", len(fixed))
	for _, f := range fixed {
		fmt.Printf("  [-] [%s] %s - %s (%s)\n", f.Severity, f.Title, f.AffectedURL, f.ToolSource)
	}

	if len(added) == 0 && len(fixed) == 0 {
		fmt.Println("\nNo changes between scans.")
	}
}

func runDaemon(configPath string) {
	listen := ":9090"
	for i, arg := range os.Args {
		if arg == "--listen" && i+1 < len(os.Args) {
			listen = os.Args[i+1]
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		cfg = config.Defaults()
	}
	if cfg.Daemon.Listen != "" {
		listen = cfg.Daemon.Listen
	}

	store, err := db.New(cfg.DBPath, cfg.Passphrase)
	if err != nil {
		fmt.Printf("Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	srv := daemon.New(nil, store, listen)
	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Daemon error: %v\n", err)
		os.Exit(1)
	}
}

func runSetup() {
	fmt.Println("OmniScan - Installing tools...")

	progress := make(chan scanner.InstallResult, 13)
	installer := scanner.NewInstaller("tools")
	installer.Progress = progress

	go func() {
		for r := range progress {
			if r.Status == "installed" {
				fmt.Printf("  [+] %s - installed\n", r.Name)
			} else {
				fmt.Printf("  [-] %s - %s\n", r.Name, r.Error)
			}
		}
	}()

	results := installer.InstallAll()
	close(progress)

	success, failed := 0, 0
	for _, r := range results {
		if r.Status == "installed" {
			success++
		} else {
			failed++
		}
	}
	fmt.Printf("\nInstalled: %d, Failed: %d (manual install required)\n", success, failed)
}

func runBounty(configPath string) {
	target := ""
	program := ""
	for i, arg := range os.Args {
		switch arg {
		case "-t":
			if i+1 < len(os.Args) {
				target = os.Args[i+1]
			}
		case "-program":
			if i+1 < len(os.Args) {
				program = os.Args[i+1]
			}
		}
	}
	if target == "" {
		fmt.Println("Error: target required")
		os.Exit(1)
	}

	fmt.Printf("OmniScan Bounty Mode - Target: %s", target)
	if program != "" {
		fmt.Printf(", Program: %s", program)
	}
	fmt.Println()

	cfg, err := config.Load(configPath)
	if err != nil {
		cfg = config.Defaults()
	}

	store, err := db.New(cfg.DBPath, cfg.Passphrase)
	if err != nil {
		fmt.Printf("Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	orchCfg := &scanner.OrchestratorConfig{
		Target:      target,
		Concurrency: cfg.Concurrency,
		RateLimit:   cfg.RateLimit,
		OutputDir:   cfg.OutputDir,
		ToolsDir:    cfg.ToolsDir,
		DBPath:      cfg.DBPath,
	}

	orch := scanner.NewOrchestrator(orchCfg, store)
	scanCfg := &types.ScanConfig{
		Target: target,
	}
	_ = scanCfg

	ctx := context.Background()
	if err := orch.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		os.Exit(1)
	}
}
