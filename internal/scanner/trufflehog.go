package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

type TruffleHog struct {
	Target   string
	ToolsDir string
	Results  chan<- types.Finding
}

func NewTruffleHog(target string, toolsDir string) *TruffleHog {
	return &TruffleHog{Target: target, ToolsDir: toolsDir}
}

func (t *TruffleHog) Run(ctx context.Context) error {
	thPath := findTool("trufflehog", filepath.Join(t.ToolsDir, "trufflehog"))
	args := []string{"filesystem", "--json", t.Target}

	cmd := exec.CommandContext(ctx, thPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if t.Results != nil {
			t.Results <- types.Finding{
				ID:          "trufflehog-skip",
				Title:       "TruffleHog not available",
				Description: fmt.Sprintf("trufflehog error: %v", err),
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
		} `json:"Data"`
	} `json:"SourceMetadata"`
	DetectorName        string `json:"DetectorName"`
	DetectorDescription string `json:"DetectorDescription"`
	DecoderName         string `json:"DecoderName"`
	Raw                 string `json:"Raw"`
	Redacted            bool   `json:"redacted"`
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

		results <- types.Finding{
			ID:          fmt.Sprintf("trufflehog-%s-%s", r.DetectorName, r.SourceMetadata.Data.Filesystem.File),
			Title:       fmt.Sprintf("Secret Detected: %s", r.DetectorName),
			Description: fmt.Sprintf("TruffleHog detected a potential secret using detector %s in %s", r.DetectorName, r.SourceMetadata.Data.Filesystem.File),
			Severity:    types.SeverityCritical,
			AffectedURL: r.SourceMetadata.Data.Filesystem.File,
			ToolSource:  "trufflehog",
			Timestamp:   time.Now(),
		}
	}
}
