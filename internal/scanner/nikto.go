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

type Nikto struct {
	Target   string
	ToolsDir string
	Results  chan types.Finding
}

func NewNikto(target string, toolsDir string) *Nikto {
	return &Nikto{Target: target, ToolsDir: toolsDir}
}

func (n *Nikto) Run(ctx context.Context) error {
	defer func() {
		if n.Results != nil {
			close(n.Results)
		}
	}()

	if n.Results == nil {
		return nil
	}

	niktoPath := findTool("nikto", filepath.Join(n.ToolsDir, "nikto"))
	args := []string{"-h", n.Target, "-Format", "json", "-o", "-"}

	cmd := exec.CommandContext(ctx, niktoPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil
	}
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		if n.Results != nil {
			n.Results <- types.Finding{
				ID:          "nikto-unavailable",
				Title:       "Nikto Not Available",
				Description: fmt.Sprintf("Nikto scanner could not be executed: %v. Install via package manager: apt install nikto", err),
				Severity:    types.SeverityInfo,
				AffectedURL: n.Target,
				ToolSource:  "nikto",
				Timestamp:   time.Now(),
			}
		}
		return nil
	}

	parseNiktoOutput(bufio.NewScanner(stdout), n.Results)
	cmd.Wait()
	return nil
}

type niktoItem struct {
	ID          string `json:"id"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	OSVDB       string `json:"osvdb"`
	Description string `json:"description"`
}

func parseNiktoOutput(scanner *bufio.Scanner, results chan<- types.Finding) {
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var item niktoItem
		if err := json.Unmarshal(line, &item); err != nil {
			continue
		}
		results <- types.Finding{
			ID:          fmt.Sprintf("nikto-%s", item.ID),
			Title:       item.Description,
			Severity:    types.SeverityMedium,
			AffectedURL: item.URL,
			ToolSource:  "nikto",
			Timestamp:   time.Now(),
		}
	}
}
