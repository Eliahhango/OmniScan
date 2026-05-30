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
	"strings"
	"time"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

type Nuclei struct {
	Target    string
	RateLimit int
	ToolsDir  string
	Results   chan types.Finding
}

func NewNuclei(target string, rateLimit int, toolsDir string) *Nuclei {
	return &Nuclei{
		Target:    target,
		RateLimit: rateLimit,
		ToolsDir:  toolsDir,
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
		"-severity", "critical,high,medium,low",
		"-rate-limit", fmt.Sprintf("%d", n.RateLimit),
		"-bulk-size", "25",
		"-json",
		"-o", outputFile,
		"-stats",
		"-hm",
	}

	defer func() {
		if n.Results != nil {
			close(n.Results)
		}
	}()
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
				ID:          "nuclei-unavailable",
				Title:       "Nuclei Not Available",
				Description: fmt.Sprintf("Nuclei scanner could not be executed: %v. Install with: omniscan setup or go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", err),
				Severity:    types.SeverityInfo,
				AffectedURL: n.Target,
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

func parseNucleiLine(data []byte) (*types.Finding, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	templateID, _ := raw["template-id"].(string)
	host, _ := raw["host"].(string)
	matchedAt, _ := raw["matched-at"].(string)
	if matchedAt == "" {
		matchedAt = host
	}

	var severity types.Severity
	var title, description, remediation string
	var cve string
	var cwes []string
	var cvssScore float64
	var classification string

	if info, ok := raw["info"].(map[string]interface{}); ok {
		if s, ok := info["severity"].(string); ok {
			severity = types.Severity(s)
		}
		if n, ok := info["name"].(string); ok {
			title = n
		}
		if d, ok := info["description"].(string); ok {
			description = d
		}
		if r, ok := info["remediation"].(string); ok {
			remediation = r
		}

		var tags []string
		if t, ok := info["tags"].(string); ok {
			for _, tag := range strings.Split(t, ",") {
				tag = strings.TrimSpace(tag)
				tags = append(tags, tag)
			}
		} else if t, ok := info["tags"].([]interface{}); ok {
			for _, tag := range t {
				tags = append(tags, fmt.Sprintf("%v", tag))
			}
		}

		for _, tag := range tags {
			upper := strings.ToUpper(tag)
			if strings.HasPrefix(upper, "CVE-") {
				cve = upper
			}
			if strings.HasPrefix(upper, "CWE-") {
				cwes = append(cwes, upper)
			}
		}

		if class, ok := info["classification"].(map[string]interface{}); ok {
			if cvss, ok := class["cvss-score"].(float64); ok {
				cvssScore = cvss
			}
			if c, ok := class["cve-id"].(string); ok && cve == "" {
				cve = c
			}
			if c, ok := class["cwe-id"].(string); ok && len(cwes) == 0 {
				cwes = strings.Split(c, ",")
			}
			if c, ok := class["cvss-metrics"].(string); ok {
				classification = c
			}
		}
	}

	extracted, _ := raw["extracted-results"].([]interface{})
	var proof string
	if len(extracted) > 0 {
		proof = fmt.Sprintf("%v", extracted[0])
	}

	if title == "" {
		title = templateID
	}

	id := fmt.Sprintf("nuclei-%s-%s", templateID, matchedAt)
	if len(id) > 128 {
		id = id[:128]
	}

	return &types.Finding{
		ID:           id,
		Title:        title,
		Description:  description,
		Severity:     severity,
		CVSS:         cvssScore,
		CVSSVector:   classification,
		CVE:          cve,
		CWE:          cwes,
		AffectedURL:  matchedAt,
		Proof:        proof,
		Remediation:  remediation,
		ToolSource:   "nuclei",
		Timestamp:    time.Now(),
	}, nil
}
