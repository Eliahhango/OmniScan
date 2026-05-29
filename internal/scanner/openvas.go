package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

type OpenVAS struct {
	Target   string
	ToolsDir string
	Results  chan<- types.Finding
}

func NewOpenVAS(target string, toolsDir string) *OpenVAS {
	return &OpenVAS{Target: target, ToolsDir: toolsDir}
}

func (o *OpenVAS) Run(ctx context.Context) error {
	if o.Results != nil {
		o.Results <- types.Finding{
			ID:          "openvas-skip",
			Title:       "OpenVAS not available",
			Description: fmt.Sprintf("OpenVAS integration requires manual setup. Target: %s", o.Target),
			Severity:    types.SeverityInfo,
			ToolSource:  "openvas",
			Timestamp:   time.Now(),
		}
	}
	return nil
}
