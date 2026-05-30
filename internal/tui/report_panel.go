package tui

import (
	"fmt"
	"strings"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

type ReportPanel struct{}

func NewReportPanel() *ReportPanel {
	return &ReportPanel{}
}

func (r *ReportPanel) View(findings []types.Finding) string {
	if len(findings) == 0 {
		return "No findings yet. Start a scan first."
	}

	var lines []string
	lines = append(lines, "OmniScan Report — EliTechWiz/github.com/Eliahhango")
	lines = append(lines, strings.Repeat("=", 60))
	lines = append(lines, fmt.Sprintf("Total Findings: %d\n", len(findings)))

	var critical, high, medium, low, info int
	for _, f := range findings {
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

	lines = append(lines, "Severity Breakdown:")
	lines = append(lines, fmt.Sprintf("  Critical: %d", critical))
	lines = append(lines, fmt.Sprintf("  High:     %d", high))
	lines = append(lines, fmt.Sprintf("  Medium:   %d", medium))
	lines = append(lines, fmt.Sprintf("  Low:      %d", low))
	lines = append(lines, fmt.Sprintf("  Info:     %d\n", info))

	lines = append(lines, "Export Options:")
	lines = append(lines, "  [HTML] [PDF] [Markdown] [JSON] [CSV]")

	return strings.Join(lines, "\n")
}
