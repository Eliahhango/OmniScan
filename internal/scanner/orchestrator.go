package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Eliahhango/OmniScan/internal/db"
	"github.com/Eliahhango/OmniScan/internal/normalizer"
	"github.com/Eliahhango/OmniScan/internal/recon"
	"github.com/Eliahhango/OmniScan/internal/version"
	"github.com/Eliahhango/OmniScan/internal/webhook"
	"github.com/Eliahhango/OmniScan/pkg/types"
)

// Version is the current OmniScan version. Aliased from the canonical version package
// so that all existing references to scanner.Version continue to work.
var Version = version.Version

type Orchestrator struct {
	cfg        *OrchestratorConfig
	db         *db.Store
	results    chan types.Finding
	errors     chan error
	pipeline   *types.ScanPipeline
	targets    []string
	OnStage    func(stage types.ScanStage, tool string, progress float64)
	epssClient *EPSSClient
	reconCache *recon.ResultCache
	webhook    *webhook.Client
	wg         sync.WaitGroup
}

type OrchestratorConfig struct {
	Target      string
	Scope       []string
	Concurrency int
	RateLimit   int
	OutputDir   string
	ToolsDir    string
	Resume      bool
	DBPath      string
}

func NewOrchestrator(cfg *OrchestratorConfig, db *db.Store) *Orchestrator {
	return NewOrchestratorWithWebhook(cfg, db, nil)
}

func NewOrchestratorWithWebhook(cfg *OrchestratorConfig, db *db.Store, wh *webhook.Client) *Orchestrator {
	return &Orchestrator{
		cfg:        cfg,
		db:         db,
		results:    make(chan types.Finding, 1000),
		errors:     make(chan error, 100),
		epssClient: NewEPSSClient(),
		webhook:    wh,
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

	var resumeStage int
	if o.cfg.Resume {
		stage, _, err := o.db.GetCheckpoint(scanID)
		if err == nil {
			resumeStage = stage
		}
	}

	stages := []struct {
		stage types.ScanStage
		name  string
		fn    func(context.Context, int64) error
	}{
		{types.StageRecon, "Recon", o.runRecon},
		{types.StageCrawling, "Crawling", o.runCrawling},
		{types.StageFuzzing, "Fuzzing", o.runFuzzing},
		{types.StageVulnScan, "VulnScan", o.runVulnScan},
		{types.StageDeepScan, "DeepScan", o.runDeepScan},
		{types.StageSAST, "SAST", o.runSAST},
		{types.StageSecrets, "Secrets", o.runSecrets},
	}

	for i, s := range stages {
		if int(s.stage) <= resumeStage {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		o.pipeline.Stage = s.stage
		o.pipeline.Progress = float64(i+1) / float64(len(stages)) * 100
		o.emitProgress(s.stage, "", o.pipeline.Progress)

		if err := s.fn(ctx, scanID); err != nil {
			select {
			case o.errors <- fmt.Errorf("stage %d: %w", s.stage, err):
			default:
			}
		}
		o.db.SaveCheckpoint(scanID, int(s.stage), "", "")
	}

	o.pipeline.Stage = types.StageReporting
	o.pipeline.Progress = 100

	o.db.UpdateScanStatus(scanID, "completed")

	o.wg.Wait()
	close(o.results)
	close(o.errors)
	return nil
}

func (o *Orchestrator) runRecon(ctx context.Context, scanID int64) error {
	if o.reconCache == nil {
		c, err := recon.NewResultCache(o.cfg.DBPath)
		if err == nil {
			o.reconCache = c
		}
	}

	o.emitProgress(types.StageRecon, "Subfinder", 0.2)
	subfinder := recon.NewSubfinder(o.cfg.Target)
	subfinder.RateLimit = o.cfg.RateLimit
	subfinder.Cache = o.reconCache
	subdomains, err := subfinder.Run(ctx)
	if err != nil || len(subdomains) == 0 {
		subdomains = []string{o.cfg.Target}
	}

	o.emitProgress(types.StageRecon, "Httpx", 0.5)
	httpx := recon.NewHttpx(subdomains)

	alive, err := httpx.Run(ctx)
	if err != nil || len(alive) == 0 {
		alive = subdomains
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
	katana.RateLimit = o.cfg.RateLimit
	katana.Cache = o.reconCache
	katanaURLs, err := katana.Run(ctx)
	if err == nil {
		urls = append(urls, katanaURLs...)
	}

	o.emitProgress(types.StageCrawling, "GAU", 0.7)
	gau := recon.NewGAU(o.cfg.Target)
	gau.Cache = o.reconCache
	gauURLs, err := gau.Run(ctx)
	if err == nil {
		urls = append(urls, gauURLs...)
	}

	urls = uniqueStrings(urls)

	for _, u := range urls {
		if parsed, err := url.ParseRequestURI(u); err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			continue
		}
		if isStaticAsset(u) {
			continue
		}
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
		ffuf.Results = o.enrichResults(ctx)
		if err := ffuf.Run(ctx); err != nil {
			continue
		}
	}

	o.emitProgress(types.StageFuzzing, "Gobuster", 50)
	for _, target := range o.activeTargets() {
		gobuster := NewGobuster(target, o.cfg.ToolsDir)
		gobuster.Results = o.enrichResults(ctx)
		if err := gobuster.Run(ctx); err != nil {
			continue
		}
	}
	return nil
}

func (o *Orchestrator) runVulnScan(ctx context.Context, scanID int64) error {
	o.emitProgress(types.StageVulnScan, "Nuclei", 0)
	for _, target := range o.activeTargets() {
		nuclei := NewNuclei(target, o.cfg.RateLimit, o.cfg.ToolsDir)
		nuclei.Results = o.enrichResults(ctx)
		if err := nuclei.Run(ctx); err != nil {
			continue
		}

		o.emitProgress(types.StageVulnScan, "Nikto", 33)
		nikto := NewNikto(target, o.cfg.ToolsDir)
		nikto.Results = o.enrichResults(ctx)
		if err := nikto.Run(ctx); err != nil {
			continue
		}

		o.emitProgress(types.StageVulnScan, "OpenVAS", 66)
		openvas := NewOpenVAS(target, o.cfg.ToolsDir)
		openvas.Results = o.enrichResults(ctx)
		if err := openvas.Run(ctx); err != nil {
			continue
		}
	}
	return nil
}

func (o *Orchestrator) runDeepScan(ctx context.Context, scanID int64) error {
	o.emitProgress(types.StageDeepScan, "ZAP", 0)
	for _, target := range o.activeTargets() {
		zap := NewZAP(target, o.cfg.ToolsDir)
		zap.Results = o.enrichResults(ctx)
		if err := zap.Run(ctx); err != nil {
			continue
		}
	}
	return nil
}

func (o *Orchestrator) runSAST(ctx context.Context, scanID int64) error {
	o.emitProgress(types.StageSAST, "Semgrep", 0.5)
	semgrep := NewSemgrep(o.cfg.Target, o.cfg.ToolsDir)
	semgrep.Results = o.enrichResults(ctx)
	if err := semgrep.Run(ctx); err != nil {
		return err
	}

	o.emitProgress(types.StageSAST, "Bearer", 1.0)
	bearer := NewBearer(o.cfg.Target, o.cfg.ToolsDir)
	bearer.Results = o.enrichResults(ctx)
	return bearer.Run(ctx)
}

func (o *Orchestrator) runSecrets(ctx context.Context, scanID int64) error {
	o.emitProgress(types.StageSecrets, "TruffleHog", 0)
	trufflehog := NewTruffleHog(o.cfg.Target, o.cfg.ToolsDir)
	trufflehog.Results = o.enrichResults(ctx)
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

var staticExtensions = []string{
	".css", ".js", ".json", ".map",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
	".woff", ".woff2", ".ttf", ".eot", ".otf",
	".mp4", ".mp3", ".avi", ".mov",
	".pdf", ".doc", ".docx", ".zip", ".tar", ".gz",
}

func isStaticAsset(u string) bool {
	lower := strings.ToLower(u)
	for _, ext := range staticExtensions {
		if strings.HasSuffix(lower, ext) || strings.Contains(lower, ext+"?") {
			return true
		}
	}
	return false
}

func (o *Orchestrator) sendResult(finding types.Finding) {
	if strings.HasSuffix(finding.ID, "-skip") {
		return
	}
	normalizer.EnrichWithOWASP2025(&finding)
	if finding.CVE != "" {
		if score := o.epssClient.GetCachedEPSS(finding.CVE); score > 0 {
			finding.EPSS = score
		} else {
			go o.epssClient.GetEPSS(finding.CVE)
		}
	}
	if o.webhook != nil && o.webhook.ShouldSend(finding) {
		go o.webhook.Send(finding)
	}
	select {
	case o.results <- finding:
	default:
	}
}

func (o *Orchestrator) enrichResults(ctx context.Context) chan types.Finding {
	ch := make(chan types.Finding, 1000)
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case f, ok := <-ch:
				if !ok {
					return
				}
				o.sendResult(f)
			}
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
	return findToolMulti([]string{name}, extraPaths...)
}

func findToolMulti(names []string, extraPaths ...string) string {
	safe := make([]string, len(names))
	for i, n := range names {
		safe[i] = filepath.Base(n)
	}
	for _, name := range safe {
		if runtime.GOOS == "windows" && !strings.Contains(name, ".") {
			for _, ext := range []string{".exe", ".bat", ".cmd"} {
				if path, err := exec.LookPath(name + ext); err == nil {
					return path
				}
			}
		}
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	for _, name := range safe {
		for _, dir := range extraPaths {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
			if runtime.GOOS == "windows" && !strings.Contains(name, ".") {
				for _, ext := range []string{".exe", ".bat", ".cmd"} {
					path := filepath.Join(dir, name+ext)
					if _, err := os.Stat(path); err == nil {
						return path
					}
				}
			}
		}
	}
	// Search common Go binary directories
	homeDir, _ := os.UserHomeDir()
	goDirs := []string{
		filepath.Join(homeDir, "go", "bin"),
		"/root/go/bin",
	}
	if gh := os.Getenv("GOPATH"); gh != "" {
		goDirs = append(goDirs, filepath.Join(gh, "bin"))
	}
	if gh := os.Getenv("GOROOT"); gh != "" {
		goDirs = append(goDirs, filepath.Join(gh, "bin"))
	}
	for _, name := range safe {
		for _, dir := range goDirs {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}
	return safe[0]
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
	Progress chan<- InstallResult
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
		"gobuster":   i.installGobuster,
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
			if i.Progress != nil {
				i.Progress <- result
			}
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
	// Pre-built binary from GitHub releases: go install fails due to replace directives in trufflehog's go.mod
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	osName := runtime.GOOS

	// Fetch latest release info from GitHub API
	resp, err := http.Get("https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest")
	if err != nil {
		return fmt.Errorf("fetch trufflehog release: %w", err)
	}
	defer resp.Body.Close()

	var release struct {
		Assets []struct {
			BrowserDownloadURL string `json:"browser_download_url"`
			Name               string `json:"name"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("decode trufflehog release: %w", err)
	}

	// Find asset matching OS/ARCH, e.g. trufflehog_3.95.3_linux_amd64.tar.gz
	suffix := fmt.Sprintf("%s_%s.tar.gz", osName, arch)
	var downloadURL string
	for _, a := range release.Assets {
		if strings.Contains(a.Name, suffix) {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		return fmt.Errorf("no trufflehog binary found for %s/%s", osName, arch)
	}

	// Download the archive
	binResp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("download trufflehog: %w", err)
	}
	defer binResp.Body.Close()

	tmpDir, err := os.MkdirTemp("", "trufflehog")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	tmpTar := filepath.Join(tmpDir, "th.tar.gz")
	f, err := os.Create(tmpTar)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, binResp.Body); err != nil {
		f.Close()
		return err
	}
	f.Close()

	// Extract
	if _, err := runCmd(context.Background(), "tar", "xzf", tmpTar, "-C", tmpDir); err != nil {
		return fmt.Errorf("extract trufflehog: %w", err)
	}

	// Install binary
	binaryPath := filepath.Join(tmpDir, "trufflehog")
	installPath := filepath.Join(i.ToolsDir, "trufflehog")
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
		installPath += ".exe"
	}
	if err := os.MkdirAll(i.ToolsDir, 0755); err != nil {
		return err
	}
	input, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("read extracted trufflehog: %w", err)
	}
	if err := os.WriteFile(installPath, input, 0755); err != nil {
		return fmt.Errorf("write trufflehog: %w", err)
	}

	return nil
}

// UpdateSelf rebuilds OmniScan from source via go install
func UpdateSelf() error {
	_, err := runCmd(context.Background(), "go", "install", "github.com/Eliahhango/OmniScan/cmd/omniscan@latest")
	return err
}

// UpdateAll updates the binary and all integrated tools
func (i *Installer) UpdateAll() map[string]InstallResult {
	// Update self first
	if err := UpdateSelf(); err != nil {
		// If self-update fails, still try to update tools
		if i.Progress != nil {
			i.Progress <- InstallResult{Name: "omniscan", Status: "failed", Error: err.Error()}
		}
	} else {
		if i.Progress != nil {
			i.Progress <- InstallResult{Name: "omniscan", Status: "updated"}
		}
	}
	return i.InstallAll()
}

func (i *Installer) installGobuster() error {
	_, err := runCmd(context.Background(), "go", "install", "github.com/OJ/gobuster/v3@latest")
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
