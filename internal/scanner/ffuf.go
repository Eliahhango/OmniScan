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

type FFUF struct {
	Target    string
	ToolsDir  string
	Results   chan types.Finding
	Wordlist  string
	Extension string
}

func NewFFUF(target string, toolsDir string) *FFUF {
	return &FFUF{
		Target:   target,
		ToolsDir: toolsDir,
	}
}

func (f *FFUF) wordlistPath() string {
	if f.Wordlist != "" {
		if _, err := os.Stat(f.Wordlist); err == nil {
			return f.Wordlist
		}
	}
	candidates := []string{
		filepath.Join(f.ToolsDir, "wordlists", "common.txt"),
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

func (f *FFUF) Run(ctx context.Context) error {
	defer func() {
		if f.Results != nil {
			close(f.Results)
		}
	}()
	ffufPath := findTool("ffuf", filepath.Join(f.ToolsDir, "ffuf"))

	args := []string{
		"-u", fmt.Sprintf("%s/FUZZ", strings.TrimRight(f.Target, "/")),
		"-w", f.wordlistPath(),
		"-json",
	}
	if f.Extension != "" {
		args = append(args, "-e", f.Extension)
	}

	cmd := exec.CommandContext(ctx, ffufPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if f.Results != nil {
			f.Results <- types.Finding{
				ID:          "ffuf-skip",
				Title:       "FFUF not available",
				Description: "FFUF scanner encountered an error and was skipped",
				Severity:    types.SeverityInfo,
				ToolSource:  "ffuf",
				Timestamp:   time.Now(),
			}
		}
		return nil
	}

	if f.Results != nil {
		parseFFUFOutput(output, f.Results)
	}
	return nil
}

type ffufResult struct {
	URL              string `json:"url"`
	StatusCode       int    `json:"status_code"`
	ContentLength    int    `json:"content_length"`
	ContentType      string `json:"content_type"`
	RedirectLocation string `json:"redirectlocation"`
	Duration         int64  `json:"duration"`
}

func parseFFUFOutput(data []byte, results chan<- types.Finding) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var r ffufResult
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}

		if r.StatusCode == 0 || r.URL == "" {
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
			ID:          fmt.Sprintf("ffuf-%s-%d", r.URL, r.StatusCode),
			Title:       fmt.Sprintf("Discovered Endpoint [%d] %s", r.StatusCode, r.URL),
			Description: fmt.Sprintf("FFUF discovered %s with status %d (size: %d)", r.URL, r.StatusCode, r.ContentLength),
			Severity:    severity,
			AffectedURL: r.URL,
			ToolSource:  "ffuf",
			Timestamp:   time.Now(),
		}
	}
}
