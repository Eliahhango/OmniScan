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

type Gobuster struct {
	Target    string
	ToolsDir  string
	Results   chan types.Finding
	Wordlist  string
	Extension string
}

func NewGobuster(target string, toolsDir string) *Gobuster {
	return &Gobuster{
		Target:   target,
		ToolsDir: toolsDir,
	}
}

func (g *Gobuster) wordlistPath() string {
	if g.Wordlist != "" {
		if _, err := os.Stat(g.Wordlist); err == nil {
			return g.Wordlist
		}
	}
	candidates := []string{
		filepath.Join(g.ToolsDir, "wordlists", "common.txt"),
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
		"/usr/local/share/wordlists/dirb/common.txt",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "common.txt"
}

func (g *Gobuster) Run(ctx context.Context) error {
	defer func() {
		if g.Results != nil {
			close(g.Results)
		}
	}()
	gobusterPath := findTool("gobuster", filepath.Join(g.ToolsDir, "gobuster"))

	args := []string{"dir", "-u", g.Target, "-w", g.wordlistPath(), "-q", "-json"}
	if g.Extension != "" {
		args = append(args, "-x", g.Extension)
	}

	cmd := exec.CommandContext(ctx, gobusterPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if g.Results != nil {
			g.Results <- types.Finding{
				ID:          "gobuster-skip",
				Title:       "Gobuster not available",
				Description: "Gobuster scanner encountered an error and was skipped",
				Severity:    types.SeverityInfo,
				ToolSource:  "gobuster",
				Timestamp:   time.Now(),
			}
		}
		return nil
	}

	if g.Results != nil {
		parseGobusterOutput(g.Target, output, g.Results)
	}
	return nil
}

type gobusterResult struct {
	Path        string `json:"path"`
	StatusCode  int    `json:"status"`
	ContentSize int64  `json:"size"`
}

func parseGobusterOutput(target string, data []byte, results chan<- types.Finding) {
	base := strings.TrimRight(target, "/")
	if !strings.HasPrefix(base, "http") {
		base = "https://" + base
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}

		var r gobusterResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}

		if r.StatusCode == 0 || r.Path == "" {
			continue
		}

		var severity types.Severity
		switch {
		case r.StatusCode == 200 || r.StatusCode == 201 || r.StatusCode == 204:
			severity = types.SeverityMedium
		case r.StatusCode == 301 || r.StatusCode == 302 || r.StatusCode == 307 || r.StatusCode == 308:
			severity = types.SeverityLow
		case r.StatusCode == 401 || r.StatusCode == 403:
			severity = types.SeverityLow
		case r.StatusCode == 500:
			severity = types.SeverityMedium
		default:
			severity = types.SeverityInfo
		}

		results <- types.Finding{
			ID:          fmt.Sprintf("gobuster-%s-%d", r.Path, r.StatusCode),
			Title:       fmt.Sprintf("Discovered Path [%d] %s", r.StatusCode, r.Path),
			Description: fmt.Sprintf("Gobuster discovered %s with status %d (size: %d)", r.Path, r.StatusCode, r.ContentSize),
			Severity:    severity,
			AffectedURL: base + r.Path,
			ToolSource:  "gobuster",
			Timestamp:   time.Now(),
		}
	}
}
