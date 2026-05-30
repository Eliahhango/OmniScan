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

type Semgrep struct {
	Target   string
	ToolsDir string
	Results  chan types.Finding
}

func NewSemgrep(target string, toolsDir string) *Semgrep {
	return &Semgrep{Target: target, ToolsDir: toolsDir}
}

func (s *Semgrep) Run(ctx context.Context) error {
	defer func() {
		if s.Results != nil {
			close(s.Results)
		}
	}()
	semgrepPath := findTool("semgrep", filepath.Join(s.ToolsDir, "semgrep"))
	args := []string{"--json", "-c", "p/owasp-top-ten", s.Target}

	cmd := exec.CommandContext(ctx, semgrepPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if s.Results != nil {
			s.Results <- types.Finding{
				ID:          "semgrep-unavailable",
				Title:       "Semgrep Not Available",
				Description: fmt.Sprintf("Semgrep scanner could not be executed. Install with: pip install semgrep"),
				Severity:    types.SeverityInfo,
				ToolSource:  "semgrep",
				Timestamp:   time.Now(),
			}
		}
		return nil
	}

	if s.Results != nil {
		parseSemgrepOutput(output, s.Results)
	}
	return nil
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Metadata struct {
			CWE []string `json:"cwe"`
		} `json:"metadata"`
	} `json:"extra"`
}

type semgrepReport struct {
	Results []semgrepResult `json:"results"`
}

func parseSemgrepOutput(data []byte, results chan<- types.Finding) {
	var report semgrepReport
	if err := json.Unmarshal(data, &report); err != nil {
		return
	}

	for _, r := range report.Results {
		var severity types.Severity
		switch r.Extra.Severity {
		case "ERROR":
			severity = types.SeverityHigh
		case "WARNING":
			severity = types.SeverityMedium
		default:
			severity = types.SeverityLow
		}

		results <- types.Finding{
			ID:          fmt.Sprintf("semgrep-%s-%s:%d", r.CheckID, r.Path, r.Start.Line),
			Title:       r.CheckID,
			Description: r.Extra.Message,
			Severity:    severity,
			CWE:         r.Extra.Metadata.CWE,
			AffectedURL: r.Path,
			ToolSource:  "semgrep",
			Timestamp:   time.Now(),
		}
	}
}
