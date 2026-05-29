package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

type BearerScanner struct {
	Target   string
	ToolsDir string
	Results  chan<- types.Finding
}

func NewBearer(target string, toolsDir string) *BearerScanner {
	return &BearerScanner{Target: target, ToolsDir: toolsDir}
}

func (b *BearerScanner) Run(ctx context.Context) error {
	bearerPath := findTool("bearer", filepath.Join(b.ToolsDir, "bearer"))

	cmd := exec.CommandContext(ctx, bearerPath, "scan", b.Target, "--json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if b.Results != nil {
			b.Results <- types.Finding{
				ID:          "bearer-skip",
				Title:       "Bearer not available",
				Description: "Bearer SAST scanner encountered an error and was skipped",
				Severity:    types.SeverityInfo,
				ToolSource:  "bearer",
				Timestamp:   time.Now(),
			}
		}
		return nil
	}

	if b.Results != nil {
		parseBearerOutput(output, b.Results)
	}
	return nil
}

type bearerReport struct {
	Findings []bearerFinding `json:"findings"`
}

type bearerFinding struct {
	ID          string           `json:"id"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Severity    string           `json:"severity"`
	Line        int              `json:"line"`
	File        string           `json:"filename"`
	Category    string           `json:"category"`
	CWEs        []string         `json:"cwe_ids"`
	Remediation *bearerRemediation `json:"remediation,omitempty"`
}

type bearerRemediation struct {
	Text string `json:"text,omitempty"`
}

func parseBearerOutput(data []byte, results chan<- types.Finding) {
	var report bearerReport
	if err := json.Unmarshal(data, &report); err != nil {
		return
	}

	for _, f := range report.Findings {
		var severity types.Severity
		switch f.Severity {
		case "critical":
			severity = types.SeverityCritical
		case "high":
			severity = types.SeverityHigh
		case "medium":
			severity = types.SeverityMedium
		case "low":
			severity = types.SeverityLow
		default:
			severity = types.SeverityInfo
		}

		remediation := ""
		if f.Remediation != nil {
			remediation = f.Remediation.Text
		}

		results <- types.Finding{
			ID:          fmt.Sprintf("bearer-%s-%s:%d", f.ID, f.File, f.Line),
			Title:       f.Title,
			Description: f.Description,
			Severity:    severity,
			CWE:         f.CWEs,
			AffectedURL: fmt.Sprintf("%s:%d", f.File, f.Line),
			ToolSource:  "bearer",
			Timestamp:   time.Now(),
			Remediation: remediation,
		}
	}
}
