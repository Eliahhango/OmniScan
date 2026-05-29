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

type Nikto struct {
	Target   string
	ToolsDir string
	Results  chan<- types.Finding
}

func NewNikto(target string, toolsDir string) *Nikto {
	return &Nikto{Target: target, ToolsDir: toolsDir}
}

func (n *Nikto) Run(ctx context.Context) error {
	niktoPath := findTool("nikto", filepath.Join(n.ToolsDir, "nikto"))
	args := []string{"-h", n.Target, "-Format", "json", "-o", "-"}

	cmd := exec.CommandContext(ctx, niktoPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if n.Results != nil {
			n.Results <- types.Finding{
				ID:          "nikto-skip",
				Title:       "Nikto not available",
				Description: fmt.Sprintf("nikto error: %v", err),
				Severity:    types.SeverityInfo,
				ToolSource:  "nikto",
				Timestamp:   time.Now(),
			}
		}
		return nil
	}

	if n.Results != nil {
		parseNiktoOutput(output, n.Results)
	}
	return nil
}

type niktoItem struct {
	ID          string `json:"id"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	OSVDB       string `json:"osvdb"`
	Description string `json:"description"`
}

func parseNiktoOutput(data []byte, results chan<- types.Finding) {
	var items []niktoItem
	if err := json.Unmarshal(data, &items); err != nil {
		return
	}
	for _, item := range items {
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
