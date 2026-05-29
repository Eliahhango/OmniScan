package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

type Nuclei struct {
	Target     string
	RateLimit  int
	ToolsDir   string
	Results    chan<- types.Finding
	TemplateDir string
}

func NewNuclei(target string, rateLimit int, toolsDir string) *Nuclei {
	return &Nuclei{
		Target:      target,
		RateLimit:   rateLimit,
		ToolsDir:    toolsDir,
		TemplateDir: "templates/",
	}
}

func (n *Nuclei) Run(ctx context.Context) error {
	outputFile := filepath.Join(os.TempDir(), fmt.Sprintf("nuclei-%d.json", time.Now().UnixMilli()))
	defer os.Remove(outputFile)

	targetsFile, err := writeTargetsFile([]string{n.Target}, os.TempDir())
	if err != nil {
		return fmt.Errorf("write targets file: %w", err)
	}
	defer os.Remove(targetsFile)

	args := []string{
		"-l", targetsFile,
		"-t", n.TemplateDir,
		"-severity", "critical,high,medium,low",
		"-rate-limit", fmt.Sprintf("%d", n.RateLimit),
		"-bulk-size", "25",
		"-json",
		"-o", outputFile,
		"-stats",
		"-hm",
	}

	nucleiPath := findTool("nuclei", filepath.Join(n.ToolsDir, "nuclei"))
	cmd := exec.CommandContext(ctx, nucleiPath, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("nuclei stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		if n.Results != nil {
			n.Results <- types.Finding{
				ID:          "nuclei-skip",
				Title:       "Nuclei not available",
				Description: fmt.Sprintf("Nuclei binary not found: %v", err),
				Severity:    types.SeverityInfo,
				ToolSource:  "nuclei",
				Timestamp:   time.Now(),
			}
		}
		return nil
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		if n.Results != nil {
			finding, err := parseNucleiLine(line)
			if err == nil {
				n.Results <- *finding
			}
		}
	}

	cmd.Wait()

	if _, err := os.Stat(outputFile); err == nil {
		data, err := os.ReadFile(outputFile)
		if err == nil {
			lines := bufio.NewScanner(bytes.NewReader(data))
			for lines.Scan() {
				if n.Results != nil {
					finding, err := parseNucleiLine(lines.Bytes())
					if err == nil && finding != nil {
						finding.ToolSource = "nuclei"
						n.Results <- *finding
					}
				}
			}
		}
	}

	return nil
}

type nucleiResult struct {
	TemplateID    string    `json:"template-id"`
	Info          nucleiInfo `json:"info"`
	Host          string    `json:"host"`
	MatchedAt     string    `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	Type          string    `json:"type"`
	Timestamp     string    `json:"timestamp"`
}

type nucleiInfo struct {
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Remediation string   `json:"remediation"`
}

func parseNucleiLine(data []byte) (*types.Finding, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	templateID, _ := raw["template-id"].(string)

	var severity types.Severity
	if info, ok := raw["info"].(map[string]interface{}); ok {
		if s, ok := info["severity"].(string); ok {
			severity = types.Severity(s)
		}
	}

	host, _ := raw["host"].(string)
	matchedAt, _ := raw["matched-at"].(string)
	if matchedAt == "" {
		matchedAt = host
	}

	title := templateID
	if info, ok := raw["info"].(map[string]interface{}); ok {
		if name, ok := info["name"].(string); ok {
			title = name
		}
	}

	return &types.Finding{
		ID:          fmt.Sprintf("nuclei-%s-%s", templateID, matchedAt),
		Title:       title,
		Severity:    severity,
		AffectedURL: matchedAt,
		CVE:         templateID,
		ToolSource:  "nuclei",
		Timestamp:   time.Now(),
	}, nil
}
