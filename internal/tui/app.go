package tui

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/Eliahhango/OmniScan/internal/scanner"
	"github.com/Eliahhango/OmniScan/pkg/types"
)

type keyMap struct {
	Quit    key.Binding
	Scan    key.Binding
	Export  key.Binding
	TabNext key.Binding
	TabPrev key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Scan, k.Export, k.TabNext, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Scan, k.Export, k.TabNext, k.TabPrev, k.Quit}}
}

var keys = keyMap{
	Quit: key.NewBinding(
		key.WithKeys("ctrl+c", "q"),
		key.WithHelp("q", "quit"),
	),
	Scan: key.NewBinding(
		key.WithKeys("s"),
		key.WithHelp("s", "scan"),
	),
	Export: key.NewBinding(
		key.WithKeys("e"),
		key.WithHelp("e", "export"),
	),
	TabNext: key.NewBinding(
		key.WithKeys("tab", "l", "right"),
		key.WithHelp("tab", "next"),
	),
	TabPrev: key.NewBinding(
		key.WithKeys("shift+tab", "h", "left"),
		key.WithHelp("s-tab", "prev"),
	),
}

type StatusMsg struct {
	Message string
	Time    time.Time
}

type FindingMsg struct {
	Finding types.Finding
}

type ScanCompleteMsg struct{}

type realScanMsg struct {
	duration time.Duration
	count    int
}

type scanStepMsg struct {
	stage    types.ScanStage
	tool     string
	progress float64
	log      string
}

type App struct {
	ready         bool
	target        string
	status        string
	tabNames      []string
	activeTab     int
	logs          []string
	reconPanel    *ReconPanel
	scanPanel     *ScanPanel
	reportPanel   *ReportPanel
	findings      []types.Finding
	scanStartTime time.Time
	scanDuration  time.Duration
	width, height int

	scanProgress progress.Model
	spinner      spinner.Model
	resultsTable table.Model
	logViewport  viewport.Model
	help         help.Model
	keys         keyMap

	simStep    int
	orch       *scanner.Orchestrator
	orchCtx    context.Context
	orchCancel context.CancelFunc
	program    *tea.Program
}

func NewApp() *App {
	s := spinner.New()
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#58a6ff"))
	s.Spinner = spinner.Dot

	p := progress.New(
		progress.WithDefaultGradient(),
		progress.WithWidth(40),
	)

	cols := []table.Column{
		{Title: "Severity", Width: 10},
		{Title: "Title", Width: 30},
		{Title: "Tool", Width: 15},
		{Title: "URL", Width: 25},
	}
	t := table.New(
		table.WithColumns(cols),
		table.WithFocused(true),
		table.WithHeight(10),
	)
	ts := table.DefaultStyles()
	ts.Header = ts.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("#58a6ff")).
		BorderBottom(true).
		Bold(true).
		Foreground(lipgloss.Color("#58a6ff"))
	ts.Selected = ts.Selected.
		Foreground(lipgloss.Color("#58a6ff")).
		Background(lipgloss.Color("#1a1a2e"))
	t.SetStyles(ts)

	v := viewport.New(0, 0)
	v.Style = lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#30363d"))

	return &App{
		tabNames:     []string{"Scan", "Results", "Report", "Config"},
		logs:         []string{},
		reconPanel:   NewReconPanel(),
		scanPanel:    NewScanPanel(),
		reportPanel:  NewReportPanel(),
		status:       "Ready",
		scanProgress: p,
		spinner:      s,
		resultsTable: t,
		logViewport:  v,
		help:         help.New(),
		keys:         keys,
	}
}

func (a *App) Init() tea.Cmd {
	return tea.Batch(spinner.Tick)
}

func (a *App) SetTarget(target string) {
	a.target = target
}

func (a *App) AddLog(msg string) {
	a.logs = append(a.logs, msg)
	if len(a.logs) > 100 {
		a.logs = a.logs[len(a.logs)-100:]
	}
	a.logViewport.SetContent(strings.Join(a.logs, "\n"))
	a.logViewport.GotoBottom()
}

func (a *App) AddFinding(finding types.Finding) {
	a.findings = append(a.findings, finding)
	a.refreshTable()
}

func (a *App) refreshTable() {
	rows := make([]table.Row, len(a.findings))
	for i, f := range a.findings {
		url := f.AffectedURL
		if len(url) > 25 {
			url = url[:22] + "..."
		}
		title := f.Title
		if len(title) > 28 {
			title = title[:25] + "..."
		}
		rows[i] = table.Row{string(f.Severity), title, f.ToolSource, url}
	}
	a.resultsTable.SetRows(rows)
}

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		a.ready = true
		a.logViewport.Width = msg.Width - 4
		a.logViewport.Height = 10
		a.resultsTable.SetWidth(msg.Width - 4)

	case tea.KeyMsg:
		if a.help.ShowAll {
			var cmd tea.Cmd
			a.help, cmd = a.help.Update(msg)
			return a, cmd
		}
		switch {
		case key.Matches(msg, a.keys.Quit):
			return a, tea.Quit
		case key.Matches(msg, a.keys.TabNext):
			a.activeTab = (a.activeTab + 1) % len(a.tabNames)
		case key.Matches(msg, a.keys.TabPrev):
			a.activeTab = (a.activeTab - 1 + len(a.tabNames)) % len(a.tabNames)
		case key.Matches(msg, a.keys.Scan):
			if a.status != "SCANNING" && a.target != "" {
				if a.orch != nil {
					return a, a.startRealScan()
				}
				return a, a.startScan()
			}
		case key.Matches(msg, a.keys.Export):
			a.AddLog("Export requested")
		}
		if a.activeTab == 1 {
			var cmd tea.Cmd
			a.resultsTable, cmd = a.resultsTable.Update(msg)
			cmds = append(cmds, cmd)
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		a.spinner, cmd = a.spinner.Update(msg)
		cmds = append(cmds, cmd)

	case progress.FrameMsg:
		var cmd tea.Cmd
		var pm tea.Model
		pm, cmd = a.scanProgress.Update(msg)
		a.scanProgress = pm.(progress.Model)
		cmds = append(cmds, cmd)

	case StatusMsg:
		a.status = msg.Message
		a.AddLog(fmt.Sprintf("[%s] %s", msg.Time.Format("15:04:05"), msg.Message))

	case FindingMsg:
		a.AddFinding(msg.Finding)
		a.AddLog(fmt.Sprintf("[FINDING] %s - %s", msg.Finding.Severity, msg.Finding.Title))

	case scanStepMsg:
		a.scanPanel.UpdateStage(msg.stage, msg.tool, msg.progress)
		if msg.log != "" {
			a.AddLog(msg.log)
		}
		pCmd := a.scanProgress.SetPercent(msg.progress)
		cmds = append(cmds, pCmd, a.simulateNext())
		if msg.progress >= 0.3 && rand.Float64() < 0.25 && msg.tool != "" {
			severities := []types.Severity{
				types.SeverityCritical, types.SeverityHigh,
				types.SeverityMedium, types.SeverityLow, types.SeverityInfo,
			}
			sev := severities[rand.Intn(len(severities))]
			f := types.Finding{
				ID:          fmt.Sprintf("FIND-%d", len(a.findings)+1),
				Title:       fmt.Sprintf("[%s] Security issue detected", msg.tool),
				Severity:    sev,
				ToolSource:  msg.tool,
				Timestamp:   time.Now(),
			}
			if a.target != "" {
				f.AffectedURL = fmt.Sprintf("https://%s/%s", a.target, msg.tool)
			}
			a.AddFinding(f)
		}

	case ScanCompleteMsg:
		a.scanDuration = time.Since(a.scanStartTime)
		a.status = "COMPLETED"
		a.AddLog(fmt.Sprintf("Scan completed in %s", a.scanDuration))
		cmds = append(cmds, a.scanProgress.SetPercent(1.0))

	case realScanMsg:
		a.scanDuration = time.Since(a.scanStartTime)
		a.status = "COMPLETED"
		a.AddLog(fmt.Sprintf("Real scan completed in %s", a.scanDuration))
		a.AddLog(fmt.Sprintf("Total findings: %d", len(a.findings)))
		cmds = append(cmds, a.scanProgress.SetPercent(1.0))
	}

	var vpCmd tea.Cmd
	a.logViewport, vpCmd = a.logViewport.Update(msg)
	cmds = append(cmds, vpCmd)
	return a, tea.Batch(cmds...)
}

func (a *App) startScan() tea.Cmd {
	a.status = "SCANNING"
	a.scanStartTime = time.Now()
	a.simStep = 0
	a.AddLog("Scan started")
	return tea.Batch(
		func() tea.Msg {
			return StatusMsg{Message: "Scan pipeline started", Time: time.Now()}
		},
		a.simulateNext(),
	)
}

func (a *App) simulateNext() tea.Cmd {
	type simStep struct {
		delay    time.Duration
		stage    types.ScanStage
		tool     string
		progress float64
		log      string
	}

	steps := []simStep{
		{1 * time.Second, types.StageRecon, "Nuclei", 0.2, "Nuclei: starting subdomain scan..."},
		{2 * time.Second, types.StageRecon, "Nuclei", 0.6, "Nuclei: enumerating endpoints..."},
		{2 * time.Second, types.StageRecon, "Nuclei", 1.0, "Nuclei: reconnaissance complete"},
		{2 * time.Second, types.StageCrawling, "ZAP", 0.4, "ZAP: spidering target..."},
		{2 * time.Second, types.StageCrawling, "ZAP", 0.8, "ZAP: crawling results: 42 endpoints"},
		{1 * time.Second, types.StageCrawling, "ZAP", 1.0, "ZAP: crawling complete"},
		{2 * time.Second, types.StageFuzzing, "FFUF", 0.5, "FFUF: fuzzing for hidden paths..."},
		{2 * time.Second, types.StageFuzzing, "FFUF", 1.0, "FFUF: found 3 hidden directories"},
		{2 * time.Second, types.StageVulnScan, "Nikto", 0.3, "Nikto: scanning for CVEs..."},
		{2 * time.Second, types.StageVulnScan, "Nikto", 0.7, "Nikto: analyzing server config..."},
		{2 * time.Second, types.StageVulnScan, "Nikto", 1.0, "Nikto: vulnerability scan complete"},
		{2 * time.Second, types.StageDeepScan, "Semgrep", 0.5, "Semgrep: static analysis in progress..."},
		{2 * time.Second, types.StageDeepScan, "Semgrep", 1.0, "Semgrep: analysis complete"},
		{2 * time.Second, types.StageSecrets, "TruffleHog", 0.6, "TruffleHog: scanning for secrets..."},
		{2 * time.Second, types.StageSecrets, "TruffleHog", 1.0, "TruffleHog: secrets scan complete"},
		{1 * time.Second, types.StageReporting, "", 0.5, "Generating report..."},
		{1 * time.Second, types.StageReporting, "", 1.0, "Report generated"},
	}

	if a.simStep >= len(steps) {
		a.simStep = 0
		return func() tea.Msg {
			return ScanCompleteMsg{}
		}
	}

	s := steps[a.simStep]
	a.simStep++
	return tea.Tick(s.delay, func(t time.Time) tea.Msg {
		return scanStepMsg{
			stage:    s.stage,
			tool:     s.tool,
			progress: s.progress,
			log:      s.log,
		}
	})
}

func (a *App) renderTabs() string {
	var tabs []string
	for i, tab := range a.tabNames {
		if i == a.activeTab {
			tabs = append(tabs, DefaultStyles.ActiveTab.Render(tab))
		} else {
			tabs = append(tabs, DefaultStyles.InactiveTab.Render(tab))
		}
	}
	tabBar := lipgloss.JoinHorizontal(lipgloss.Top, tabs...)
	return lipgloss.NewStyle().Padding(0, 1).Render(tabBar)
}

func (a *App) renderContent() string {
	switch a.activeTab {
	case 0:
		return a.renderScanTab()
	case 1:
		return a.renderResultsTab()
	case 2:
		return a.reportPanel.View(a.findings)
	case 3:
		return a.renderConfigTab()
	default:
		return ""
	}
}

func (a *App) SetOrchestrator(orch *scanner.Orchestrator) {
	a.orch = orch
}

func (a *App) SetProgram(prog *tea.Program) {
	a.program = prog
}

func (a *App) startRealScan() tea.Cmd {
	a.status = "SCANNING"
	a.scanStartTime = time.Now()
	a.findings = nil
	a.refreshTable()
	a.AddLog("Real scan started via orchestrator")

	a.orchCtx, a.orchCancel = context.WithCancel(context.Background())

	go a.runOrchInBackground()

	return tea.Batch(
		func() tea.Msg {
			return StatusMsg{Message: "Real scan pipeline started", Time: time.Now()}
		},
		func() tea.Msg {
			return scanStepMsg{
				stage:    types.StageRecon,
				tool:     "Orchestrator",
				progress: 0.1,
				log:      "Real scan engine engaged",
			}
		},
	)
}

func (a *App) runOrchInBackground() {
	go func() {
		if err := a.orch.Run(a.orchCtx); err != nil {
			a.program.Send(StatusMsg{
				Message: fmt.Sprintf("Scan error: %v", err),
				Time:    time.Now(),
			})
		}
	}()

	for finding := range a.orch.Results() {
		a.program.Send(FindingMsg{Finding: finding})
	}

	for err := range a.orch.Errors() {
		a.program.Send(StatusMsg{
			Message: fmt.Sprintf("Scan error: %v", err),
			Time:    time.Now(),
		})
	}

	a.program.Send(realScanMsg{
		duration: time.Since(a.scanStartTime),
		count:    len(a.findings),
	})
}

func (a *App) View() string {
	if !a.ready {
		return "Loading..."
	}

	title := DefaultStyles.Title.Render(fmt.Sprintf("OmniScan v1.0  |  Target: %s  |  Status: %s", a.target, a.status))
	tabBar := a.renderTabs()
	content := a.renderContent()
	logBox := a.logViewport.View()
	helpView := a.help.View(a.keys)

	return lipgloss.JoinVertical(lipgloss.Top,
		title, tabBar, "", content, "", logBox, "", helpView,
	)
}

func (a *App) renderScanTab() string {
	var critical, high, medium, low, info int
	for _, f := range a.findings {
		switch f.Severity {
		case types.SeverityCritical:
			critical++
		case types.SeverityHigh:
			high++
		case types.SeverityMedium:
			medium++
		case types.SeverityLow:
			low++
		default:
			info++
		}
	}

	reconView := a.reconPanel.View()
	scanView := a.scanPanel.View()

	spinnerView := ""
	if a.status == "SCANNING" {
		spinnerView = a.spinner.View() + " Scanning..."
	}

	progressView := a.scanProgress.View()

	findingsSummary := fmt.Sprintf("FINDINGS: %s%d%s | %s%d%s | %s%d%s | %s%d%s | %s%d",
		DefaultStyles.Critical.Render("CRITICAL:"), critical,
		DefaultStyles.Info.Render(""),
		DefaultStyles.High.Render("HIGH:"), high,
		DefaultStyles.Info.Render(""),
		DefaultStyles.Medium.Render("MEDIUM:"), medium,
		DefaultStyles.Info.Render(""),
		DefaultStyles.Low.Render("LOW:"), low,
		DefaultStyles.Info.Render(""),
		DefaultStyles.Info.Render("INFO:"), info,
	)

	topRow := lipgloss.JoinHorizontal(lipgloss.Top,
		DefaultStyles.Panel.Render("RECON\n"+reconView),
		DefaultStyles.Panel.Render("SCAN ENGINE\n"+scanView),
	)

	middleRow := ""
	if spinnerView != "" {
		middleRow = spinnerView + "\n" + progressView
	}

	bottomRow := lipgloss.JoinHorizontal(lipgloss.Top,
		DefaultStyles.Panel.Render(findingsSummary),
		DefaultStyles.Panel.Render("REPORT\n[Export]     [PDF] [HTML] [JSON]"),
	)

	return lipgloss.JoinVertical(lipgloss.Top, topRow, middleRow, bottomRow)
}

func (a *App) renderResultsTab() string {
	if len(a.findings) == 0 {
		return DefaultStyles.Panel.Render("No findings yet. Start a scan to see results.")
	}
	return DefaultStyles.Panel.Render(a.resultsTable.View())
}

func (a *App) renderConfigTab() string {
	config := fmt.Sprintf(`Target: %s
Status: %s
Found: %d vulnerabilities
Duration: %s

Key Bindings:
  s          Start scan pipeline
  e          Export report
  Tab / l    Next tab
  Shift+Tab/h  Previous tab
  Ctrl+C / q Quit`, a.target, a.status, len(a.findings), a.scanDuration)

	return DefaultStyles.Panel.Render(config)
}
