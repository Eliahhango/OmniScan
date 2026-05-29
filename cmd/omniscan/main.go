package main

import (
	"context"
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/Eliahhango/OmniScan/internal/config"
	"github.com/Eliahhango/OmniScan/internal/db"
	"github.com/Eliahhango/OmniScan/internal/scanner"
	"github.com/Eliahhango/OmniScan/internal/tui"
	"github.com/Eliahhango/OmniScan/pkg/types"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("OmniScan - Unified Vulnerability Hunting Platform")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  omniscan tui                    Launch interactive TUI")
		fmt.Println("  omniscan scan <target>          Run scan")
		fmt.Println("  omniscan setup                  Install all 13 tools")
		fmt.Println("  omniscan bounty <target>        Bug bounty mode")
		fmt.Println()
		fmt.Println("Flags:")
		fmt.Println("  -t <target>     Scan target (domain or IP)")
		fmt.Println("  -program        Bug bounty program name")
		fmt.Println("  -resume         Resume from last checkpoint")
		fmt.Println("  -config <path>  Config file path")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  omniscan tui")
		fmt.Println("  omniscan scan -t example.com")
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

	store, err := db.New(cfg.DBPath)
	if err == nil {
		defer store.Close()
		orchCfg := &scanner.OrchestratorConfig{
			Target:      target,
			Concurrency: cfg.Concurrency,
			RateLimit:   cfg.RateLimit,
			OutputDir:   cfg.OutputDir,
			ToolsDir:    cfg.ToolsDir,
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
	for i, arg := range os.Args {
		switch arg {
		case "-t":
			if i+1 < len(os.Args) {
				target = os.Args[i+1]
			}
		case "-resume":
			resume = true
		}
	}
	if target == "" && len(os.Args) > 2 {
		target = os.Args[2]
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

	store, err := db.New(cfg.DBPath)
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
	}

	orch := scanner.NewOrchestrator(orchCfg, store)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()

	fmt.Printf("Starting scan on %s...\n", target)
	start := time.Now()

	go func() {
		for finding := range orch.Results() {
			fmt.Printf("[%s] %s - %s (%s)\n", finding.Severity, finding.Title, finding.AffectedURL, finding.ToolSource)
		}
	}()

	go func() {
		for err := range orch.Errors() {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
	}()

	if err := orch.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		os.Exit(1)
	}

	duration := time.Since(start)
	fmt.Printf("\nScan completed in %s\n", duration)
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

	store, err := db.New(cfg.DBPath)
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
