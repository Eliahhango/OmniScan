package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/Eliahhango/OmniScan/pkg/types"
)

type ToolProgress struct {
	Name       string
	Progress   float64
	Status     string
}

type ScanPanel struct {
	currentStage types.ScanStage
	tools        []ToolProgress
}

func NewScanPanel() *ScanPanel {
	return &ScanPanel{
		tools: []ToolProgress{
			{Name: "Nuclei"},
			{Name: "ZAP"},
			{Name: "Nmap"},
			{Name: "FFUF"},
			{Name: "Nikto"},
			{Name: "Semgrep"},
			{Name: "TruffleHog"},
		},
	}
}

func (s *ScanPanel) UpdateStage(stage types.ScanStage, tool string, progress float64) {
	s.currentStage = stage
	for i, t := range s.tools {
		if t.Name == tool {
			s.tools[i].Progress = progress
			if progress >= 1.0 {
				s.tools[i].Status = "DONE"
			} else if progress > 0 {
				s.tools[i].Status = "RUNNING"
			}
			break
		}
	}
}

func (s *ScanPanel) View() string {
	var lines []string
	stageName := "Unknown"
	if name, ok := types.StageNames[s.currentStage]; ok {
		stageName = name
	}
	lines = append(lines, fmt.Sprintf("Stage: %s\n", stageName))

	for _, t := range s.tools {
		bar := renderProgressBar(t.Progress, 20)
		status := t.Status
		if status == "" {
			status = "PENDING"
		}
		statusColor := lipgloss.Color("#8b949e")
		switch status {
		case "RUNNING":
			statusColor = lipgloss.Color("#58a6ff")
		case "DONE":
			statusColor = lipgloss.Color("#3fb950")
		}
		coloredStatus := lipgloss.NewStyle().Foreground(statusColor).Render(status)
		lines = append(lines, fmt.Sprintf("> %s %s [%s]", t.Name, bar, coloredStatus))
	}

	return strings.Join(lines, "\n")
}

func renderProgressBar(pct float64, width int) string {
	if pct > 1 {
		pct = 1
	}
	filled := int(pct * float64(width))
	empty := width - filled

	bar := lipgloss.NewStyle().Foreground(lipgloss.Color("#58a6ff")).Render(strings.Repeat("█", filled)) +
		lipgloss.NewStyle().Foreground(lipgloss.Color("#30363d")).Render(strings.Repeat("░", empty))
	return fmt.Sprintf("[%s]", bar)
}

type ScanUpdate struct {
	Stage    types.ScanStage
	Tool     string
	Progress float64
}
