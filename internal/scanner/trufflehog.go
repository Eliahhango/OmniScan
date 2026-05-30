package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Eliahhango/OmniScan/internal/normalizer"
	"github.com/Eliahhango/OmniScan/pkg/types"
)

type TruffleHog struct {
	Target   string
	ToolsDir string
	Results  chan types.Finding
}

func NewTruffleHog(target string, toolsDir string) *TruffleHog {
	return &TruffleHog{Target: target, ToolsDir: toolsDir}
}

func isTargetURL(target string) bool {
	if strings.Contains(target, "://") {
		return true
	}
	u, err := url.Parse("https://" + target)
	if err != nil {
		return false
	}
	return strings.Contains(u.Host, ".")
}

func (t *TruffleHog) Run(ctx context.Context) error {
	defer func() {
		if t.Results != nil {
			close(t.Results)
		}
	}()
	thPath := findTool("trufflehog", filepath.Join(t.ToolsDir, "trufflehog"))

	var args []string
	if isTargetURL(t.Target) {
		args = []string{"git", "--json", t.Target}
	} else {
		args = []string{"filesystem", "--json", t.Target}
	}

	cmd := exec.CommandContext(ctx, thPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if t.Results != nil {
			t.Results <- types.Finding{
				ID:          "trufflehog-unavailable",
				Title:       "TruffleHog Not Available",
				Description: fmt.Sprintf("TruffleHog scanner could not be executed. Install with: omniscan setup"),
				Severity:    types.SeverityInfo,
				ToolSource:  "trufflehog",
				Timestamp:   time.Now(),
			}
		}
		return nil
	}

	if t.Results != nil {
		parseTrufflehogOutput(output, t.Results)
	}
	return nil
}

type trufflehogResult struct {
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
			} `json:"Filesystem"`
			Git struct {
				File   string `json:"file"`
				Commit string `json:"commit"`
			} `json:"Git"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
	DetectorName        string `json:"DetectorName"`
	DetectorDescription string `json:"DetectorDescription"`
	DecoderName         string `json:"DecoderName"`
	Raw                 string `json:"Raw"`
	Redacted            bool   `json:"redacted"`
}

func sourceFile(r trufflehogResult) string {
	if r.SourceMetadata.Data.Filesystem.File != "" {
		return r.SourceMetadata.Data.Filesystem.File
	}
	return r.SourceMetadata.Data.Git.File
}

func parseTrufflehogOutput(data []byte, results chan<- types.Finding) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var r trufflehogResult
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}

		if r.DetectorName == "" {
			continue
		}

		file := sourceFile(r)
		results <- types.Finding{
			ID:          fmt.Sprintf("trufflehog-%s-%s", r.DetectorName, file),
			Title:       fmt.Sprintf("Secret Detected: %s", r.DetectorName),
			Description: fmt.Sprintf("TruffleHog detected a potential secret using detector %s in %s", r.DetectorName, file),
			Severity:    types.SeverityCritical,
			AffectedURL: file,
			ToolSource:  "trufflehog",
			Timestamp:   time.Now(),
			Payload:     normalizer.RedactSecret(r.Raw),
		}
	}
}
