package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Eliahhango/OmniScan/internal/version"
	"github.com/Eliahhango/OmniScan/pkg/types"
)

type Client struct {
	URLs    []string
	MinSeverity types.Severity
	client  *http.Client
	mu      sync.Mutex
	buffer  []types.Finding
}

func New(urls []string, minSeverity types.Severity) *Client {
	return &Client{
		URLs:        urls,
		MinSeverity: minSeverity,
		client:      &http.Client{Timeout: 10 * time.Second},
	}
}

var severityRank = map[types.Severity]int{
	types.SeverityCritical: 4,
	types.SeverityHigh:     3,
	types.SeverityMedium:   2,
	types.SeverityLow:      1,
	types.SeverityInfo:     0,
}

func (c *Client) ShouldSend(finding types.Finding) bool {
	if len(c.URLs) == 0 {
		return false
	}
	return severityRank[finding.Severity] >= severityRank[c.MinSeverity]
}

func (c *Client) Send(finding types.Finding) error {
	payload, err := json.Marshal(map[string]interface{}{
		"text":       fmt.Sprintf("[%s] %s\nTarget: %s\nTool: %s\nCVE: %s",
			finding.Severity, finding.Title, finding.AffectedURL, finding.ToolSource, finding.CVE),
		"findings": []types.Finding{finding},
	})
	if err != nil {
		return err
	}

	var lastErr error
	for _, url := range c.URLs {
		resp, err := c.client.Post(url, "application/json", bytes.NewReader(payload))
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return lastErr
}

func (c *Client) SendBatch(findings []types.Finding) error {
	if len(findings) == 0 || len(c.URLs) == 0 {
		return nil
	}

	var filtered []types.Finding
	for _, f := range findings {
		if severityRank[f.Severity] >= severityRank[c.MinSeverity] {
			filtered = append(filtered, f)
		}
	}
	if len(filtered) == 0 {
		return nil
	}

	payload, err := json.Marshal(map[string]interface{}{
		"text":    fmt.Sprintf("OmniScan %s: %d findings above %s threshold", version.Version, len(filtered), c.MinSeverity),
		"findings": filtered,
	})
	if err != nil {
		return err
	}

	var lastErr error
	for _, url := range c.URLs {
		resp, err := c.client.Post(url, "application/json", bytes.NewReader(payload))
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return lastErr
}
