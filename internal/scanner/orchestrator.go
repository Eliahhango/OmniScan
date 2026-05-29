package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Eliahhango/OmniScan/internal/db"
	"github.com/Eliahhango/OmniScan/internal/normalizer"
	"github.com/Eliahhango/OmniScan/internal/recon"
	"github.com/Eliahhango/OmniScan/pkg/types"
)

type Orchestrator struct {
	cfg      *OrchestratorConfig
	db       *db.Store
	results  chan types.Finding
	errors   chan error
	pipeline *types.ScanPipeline
	targets  []string
	OnStage  func(stage types.ScanStage, tool string, progress float64)
}

type OrchestratorConfig struct {
	Target      string
	Scope       []string
	Concurrency int
	RateLimit   int
	OutputDir   string
	ToolsDir    string
	Resume      bool
}

func NewOrchestrator(cfg *OrchestratorConfig, db *db.Store) *Orchestrator {
	return &Orchestrator{
		cfg:     cfg,
		db:      db,
		results: make(chan types.Finding, 1000),
		errors:  make(chan error, 100),
		pipeline: &types.ScanPipeline{
			Target:    cfg.Target,
			Scope:     cfg.Scope,
			Stage:     types.StageRecon,
			StartTime: time.Now(),
		},
	}
}

func (o *Orchestrator) Results() <-chan types.Finding {
	return o.results
}

func (o *Orchestrator) Errors() <-chan error {
	return o.errors
}

func (o *Orchestrator) Run(ctx context.Context) error {
	scanID, err := o.db.CreateScan(o.cfg.Target, o.cfg.Scope)
	if err != nil {
		return fmt.Errorf("create scan: %w", err)
	}

	var resumeStage types.ScanStage
	if o.cfg.Resume {
		stage, _, err := o.db.GetCheckpoint(scanID)
		if err == nil {
			resumeStage = types.ScanStage(stage)
		}
	}

	stages := []struct {
		stage types.ScanStage
		fn    func(context.Context, int64) error
	}{
		{types.StageRecon, o.runRecon},
		{types.StageCrawling, o.runCrawling},
		{types.StageFuzzing, o.runFuzzing},
		{types.StageVulnScan, o.runVulnScan},
		{types.StageDeepScan, o.runDeepScan},
		{types.StageSAST, o.runSAST},
		{types.StageSecrets, o.runSecrets},
	}

	for _, s := range stages {
		if s.stage < resumeStage {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		o.pipeline.Stage = s.stage
		o.pipeline.Progress = float64(s.stage) / float64(len(stages)) * 100
		o.emitProgress(s.stage, "", o.pipeline.Progress)

		if err := s.fn(ctx, scanID); err != nil {
			o.errors <- fmt.Errorf("stage %d: %w", s.stage, err)
		}
		o.db.SaveCheckpoint(scanID, int(s.stage), "", "")
	}

	o.pipeline.Stage = types.StageReporting
	o.pipeline.Progress = 100

	o.db.UpdateScanStatus(scanID, "completed")
	close(o.results)
	close(o.errors)
	return nil
}

func (o *Orchestrator) runRecon(ctx context.Context, scanID int64) error {
	o.emitProgress(types.StageRecon, "Subfinder", 0.2)
	subfinder := recon.NewSubfinder(o.cfg.Target)
	subdomains, err := subfinder.Run(ctx)
	if err != nil {
		return err
	}

	o.emitProgress(types.StageRecon, "Httpx", 0.5)
	httpx := recon.NewHttpx(subdomains)

	alive, err := httpx.Run(ctx)
	if err != nil {
		return err
	}

	o.targets = alive

	for _, u := range alive {
		o.sendResult(types.Finding{
			ID:          fmt.Sprintf("recon-%s", u),
			Title:       "Live Host Discovered",
			Description: fmt.Sprintf("Host %s is alive", u),
			Severity:    types.SeverityInfo,
			AffectedURL: u,
			ToolSource:  "httpx",
			Timestamp:   time.Now(),
		})
	}

	probes, err := httpx.RunWithTech(ctx)
	if err == nil {
		for _, p := range probes {
			if len(p.Tech) > 0 {
				o.sendResult(types.Finding{
					ID:          fmt.Sprintf("tech-%s", p.URL),
					Title:       "Technology Detected",
					Description: fmt.Sprintf("Technologies on %s: %s", p.URL, strings.Join(p.Tech, ", ")),
					Severity:    types.SeverityInfo,
					AffectedURL: p.URL,
					ToolSource:  "httpx",
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return nil
}

func (o *Orchestrator) runCrawling(ctx context.Context, scanID int64) error {
	var urls []string

	o.emitProgress(types.StageCrawling, "Katana", 0.3)
	katana := recon.NewKatana(o.activeTargets())
	katanaURLs, err := katana.Run(ctx)
	if err == nil {
		urls = append(urls, katanaURLs...)
	}

	o.emitProgress(types.StageCrawling, "GAU", 0.7)
	gau := recon.NewGAU(o.cfg.Target)
	gauURLs, err := gau.Run(ctx)
	if err == nil {
		urls = append(urls, gauURLs...)
	}

	urls = uniqueStrings(urls)

	for _, u := range urls {
		o.sendResult(types.Finding{
			ID:          fmt.Sprintf("crawl-%s", u),
			Title:       "Discovered URL",
			Description: fmt.Sprintf("URL discovered during crawling: %s", u),
			Severity:    types.SeverityInfo,
			AffectedURL: u,
			ToolSource:  "crawler",
			Timestamp:   time.Now(),
		})
	}
	return nil
}

func (o *Orchestrator) runFuzzing(ctx context.Context, scanID int64) error {
	o.emitProgress(types.StageFuzzing, "FFUF", 0)
	for _, target := range o.activeTargets() {
		ffuf := NewFFUF(target, o.cfg.ToolsDir)
		ffuf.Results = o.enrichResults()
		if err := ffuf.Run(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (o *Orchestrator) runVulnScan(ctx context.Context, scanID int64) error {
	o.emitProgress(types.StageVulnScan, "Nuclei", 0)
	for _, target := range o.activeTargets() {
		nuclei := NewNuclei(target, o.cfg.RateLimit, o.cfg.ToolsDir)
		nuclei.Results = o.enrichResults()
		if err := nuclei.Run(ctx); err != nil {
			return err
		}

		o.emitProgress(types.StageVulnScan, "Nikto", 33)
		nikto := NewNikto(target, o.cfg.ToolsDir)
		nikto.Results = o.enrichResults()
		if err := nikto.Run(ctx); err != nil {
			return err
		}

		o.emitProgress(types.StageVulnScan, "OpenVAS", 66)
		openvas := NewOpenVAS(target, o.cfg.ToolsDir)
		openvas.Results = o.enrichResults()
		if err := openvas.Run(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (o *Orchestrator) runDeepScan(ctx context.Context, scanID int64) error {
	o.emitProgress(types.StageDeepScan, "ZAP", 0)
	for _, target := range o.activeTargets() {
		zap := NewZAP(target, o.cfg.ToolsDir)
		zap.Results = o.enrichResults()
		if err := zap.Run(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (o *Orchestrator) runSAST(ctx context.Context, scanID int64) error {
	o.emitProgress(types.StageSAST, "Semgrep", 0.5)
	semgrep := NewSemgrep(o.cfg.Target, o.cfg.ToolsDir)
	semgrep.Results = o.enrichResults()
	if err := semgrep.Run(ctx); err != nil {
		return err
	}

	o.emitProgress(types.StageSAST, "Bearer", 1.0)
	bearer := NewBearer(o.cfg.Target, o.cfg.ToolsDir)
	bearer.Results = o.enrichResults()
	return bearer.Run(ctx)
}

func (o *Orchestrator) runSecrets(ctx context.Context, scanID int64) error {
	o.emitProgress(types.StageSecrets, "TruffleHog", 0)
	trufflehog := NewTruffleHog(o.cfg.Target, o.cfg.ToolsDir)
	trufflehog.Results = o.enrichResults()
	return trufflehog.Run(ctx)
}

func (o *Orchestrator) emitProgress(stage types.ScanStage, tool string, progress float64) {
	if o.OnStage != nil {
		o.OnStage(stage, tool, progress)
	}
}

func (o *Orchestrator) activeTargets() []string {
	if len(o.targets) > 0 {
		return o.targets
	}
	return []string{o.cfg.Target}
}

func (o *Orchestrator) sendResult(finding types.Finding) {
	normalizer.EnrichWithOWASP2025(&finding)
	if finding.CVE != "" {
		if score, _ := GetEPSS(finding.CVE); score > 0 {
			finding.EPSS = score
		}
	}
	o.results <- finding
}

func (o *Orchestrator) enrichResults() chan<- types.Finding {
	ch := make(chan types.Finding, 1000)
	go func() {
		for f := range ch {
			o.sendResult(f)
		}
	}()
	return ch
}

func uniqueStrings(s []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(s))
	for _, v := range s {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}

func runCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s: %w\n%s", name, err, string(output))
	}
	return output, nil
}

func findTool(name string, extraPaths ...string) string {
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	for _, dir := range extraPaths {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return name
}

func writeTargetsFile(targets []string, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "targets.txt")
	return path, os.WriteFile(path, []byte(strings.Join(targets, "\n")), 0644)
}

type InstallResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type InstallFunc func() error

type Installer struct {
	ToolsDir string
	Results  map[string]InstallResult
	mu       sync.Mutex
}

func NewInstaller(toolsDir string) *Installer {
	return &Installer{
		ToolsDir: toolsDir,
		Results:  make(map[string]InstallResult),
	}
}

func (i *Installer) InstallAll() map[string]InstallResult {
	tools := map[string]InstallFunc{
		"nuclei":     i.installNuclei,
		"subfinder":  i.installSubfinder,
		"httpx":      i.installHttpx,
		"katana":     i.installKatana,
		"ffuf":       i.installFfuf,
		"nmap":       i.installNmap,
		"nikto":      i.installNikto,
		"openvas":    i.installOpenVAS,
		"zap":        i.installZap,
		"semgrep":    i.installSemgrep,
		"trufflehog": i.installTrufflehog,
		"gau":        i.installGau,
		"gospider":   i.installGospider,
	}

	var wg sync.WaitGroup
	for name, fn := range tools {
		wg.Add(1)
		go func(name string, fn InstallFunc) {
			defer wg.Done()
			result := InstallResult{Name: name}
			if err := fn(); err != nil {
				result.Status = "failed"
				result.Error = err.Error()
			} else {
				result.Status = "installed"
			}
			i.mu.Lock()
			i.Results[name] = result
			i.mu.Unlock()
		}(name, fn)
	}
	wg.Wait()
	return i.Results
}

func (i *Installer) installNuclei() error {
	_, err := runCmd(context.Background(), "go", "install", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
	return err
}

func (i *Installer) installSubfinder() error {
	_, err := runCmd(context.Background(), "go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
	return err
}

func (i *Installer) installHttpx() error {
	_, err := runCmd(context.Background(), "go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest")
	return err
}

func (i *Installer) installKatana() error {
	_, err := runCmd(context.Background(), "go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest")
	return err
}

func (i *Installer) installFfuf() error {
	_, err := runCmd(context.Background(), "go", "install", "github.com/ffuf/ffuf/v2@latest")
	return err
}

func (i *Installer) installNmap() error {
	return fmt.Errorf("nmap must be installed via package manager")
}

func (i *Installer) installNikto() error {
	return fmt.Errorf("nikto must be installed via package manager")
}

func (i *Installer) installOpenVAS() error {
	return fmt.Errorf("openvas must be installed via package manager")
}

func (i *Installer) installZap() error {
	return fmt.Errorf("zap must be installed via package manager or docker")
}

func (i *Installer) installSemgrep() error {
	return fmt.Errorf("semgrep must be installed via pip: pip install semgrep")
}

func (i *Installer) installTrufflehog() error {
	_, err := runCmd(context.Background(), "go", "install", "github.com/trufflesecurity/trufflehog/v3@latest")
	return err
}

func (i *Installer) installGau() error {
	_, err := runCmd(context.Background(), "go", "install", "github.com/lc/gau/v2/cmd/gau@latest")
	return err
}

func (i *Installer) installGospider() error {
	_, err := runCmd(context.Background(), "go", "install", "github.com/jaeles-project/gospider@latest")
	return err
}
