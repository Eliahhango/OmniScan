package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

type ZAP struct {
	Target   string
	Host     string
	Port     int
	APIKey   string
	ToolsDir string
	Results  chan types.Finding
	cmd      *exec.Cmd
}

func generateAPIKey() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

func NewZAP(target string, toolsDir string) *ZAP {
	return &ZAP{
		Target:   target,
		Host:     "127.0.0.1",
		Port:     8080,
		APIKey:   generateAPIKey(),
		ToolsDir: toolsDir,
	}
}

func (z *ZAP) Run(ctx context.Context) error {
	defer func() {
		if z.Results != nil {
			close(z.Results)
		}
	}()
	zapNames := []string{"zap.sh", "zap"}
	if runtime.GOOS == "windows" {
		zapNames = []string{"zap.bat", "zap.cmd", "zap.bat", "zap"}
	}
	zapPath := findToolMulti(zapNames, filepath.Join(z.ToolsDir, "zap"))

	args := []string{
		"-daemon",
		"-host", z.Host,
		"-port", fmt.Sprintf("%d", z.Port),
		"-config", fmt.Sprintf("api.key=%s", z.APIKey),
	}

	cmd := exec.CommandContext(ctx, zapPath, args...)
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		if z.Results != nil {
			z.Results <- types.Finding{
				ID:          "zap-unavailable",
				Title:       "ZAP Not Available",
				Description: fmt.Sprintf("ZAP scanner could not be executed. Install ZAP manually: https://www.zaproxy.org/download/"),
				Severity:    types.SeverityInfo,
				ToolSource:  "zap",
				Timestamp:   time.Now(),
			}
		}
		return nil
	}
	z.cmd = cmd

	defer func() {
		shutdownURL := fmt.Sprintf("http://%s:%d/JSON/core/action/shutdown/?apikey=%s", z.Host, z.Port, z.APIKey)
		http.Get(shutdownURL)
		if z.cmd != nil && z.cmd.Process != nil {
			z.cmd.Process.Kill()
		}
	}()

	baseURL := fmt.Sprintf("http://%s:%d", z.Host, z.Port)

	if err := z.waitForReady(ctx, baseURL); err != nil {
		return fmt.Errorf("zap daemon not ready: %w", err)
	}

	scanID, err := z.startActiveScan(ctx, baseURL)
	if err != nil {
		return fmt.Errorf("zap start scan: %w", err)
	}

	if err := z.waitForScanComplete(ctx, baseURL, scanID); err != nil {
		return fmt.Errorf("zap scan %d: %w", scanID, err)
	}

	reportData, err := z.getJSONReport(ctx, baseURL)
	if err != nil {
		return fmt.Errorf("zap get report: %w", err)
	}

	if z.Results != nil {
		if err := parseZapReport(reportData, z.Results); err != nil {
			return fmt.Errorf("zap parse report: %w", err)
		}
	}

	return nil
}

func (z *ZAP) waitForReady(ctx context.Context, baseURL string) error {
	pollTicker := time.NewTicker(500 * time.Millisecond)
	defer pollTicker.Stop()

	timeout := time.After(60 * time.Second)

	client := &http.Client{Timeout: 2 * time.Second}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout waiting for ZAP daemon")
		case <-pollTicker.C:
			req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
	}
}

func (z *ZAP) startActiveScan(ctx context.Context, baseURL string) (int, error) {
	scanURL := fmt.Sprintf("%s/JSON/ascan/action/scan/?url=%s&recurse=true",
		baseURL, url.QueryEscape(z.Target))

	req, err := http.NewRequestWithContext(ctx, "GET", scanURL, nil)
	if err != nil {
		return 0, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var result struct {
		Scan string `json:"scan"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("unmarshal scan response: %w", err)
	}

	return strconv.Atoi(strings.TrimSpace(result.Scan))
}

func (z *ZAP) waitForScanComplete(ctx context.Context, baseURL string, scanID int) error {
	pollTicker := time.NewTicker(1 * time.Second)
	defer pollTicker.Stop()

	client := &http.Client{Timeout: 5 * time.Second}
	scanTimeout := time.After(10 * time.Minute)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-scanTimeout:
			return fmt.Errorf("ZAP active scan timed out after 10 minutes")
		case <-pollTicker.C:
			statusURL := fmt.Sprintf("%s/JSON/ascan/view/status/?scanId=%d", baseURL, scanID)

			req, err := http.NewRequestWithContext(ctx, "GET", statusURL, nil)
			if err != nil {
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}

			var status struct {
				Status string `json:"status"`
			}
			if err := json.Unmarshal(body, &status); err != nil {
				continue
			}

			if status.Status == "100" {
				return nil
			}
		}
	}
}

func (z *ZAP) getJSONReport(ctx context.Context, baseURL string) ([]byte, error) {
	reportURL := fmt.Sprintf("%s/OTHER/core/other/jsonreport/", baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", reportURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

type zapAlert struct {
	Alert        string `json:"alert"`
	RiskCode     int    `json:"riskcode"`
	Confidence   string `json:"confidence"`
	URL          string `json:"url"`
	Param        string `json:"param"`
	Attack       string `json:"attack"`
	Description  string `json:"description"`
	Solution     string `json:"solution"`
	CWEID        string `json:"cweid"`
	WASCID       string `json:"wascid"`
	Reference    string `json:"reference"`
	PluginID     string `json:"pluginId"`
}

func parseZapReport(data []byte, results chan<- types.Finding) error {
	var report struct {
		Site []struct {
			Alerts []zapAlert `json:"alerts"`
		} `json:"site"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return err
	}

	severityMap := map[int]types.Severity{
		0: types.SeverityInfo,
		1: types.SeverityLow,
		2: types.SeverityMedium,
		3: types.SeverityHigh,
	}

	for _, site := range report.Site {
		for _, alert := range site.Alerts {
			severity, ok := severityMap[alert.RiskCode]
			if !ok {
				severity = types.SeverityInfo
			}

			results <- types.Finding{
				ID:            fmt.Sprintf("zap-%s-%s", alert.PluginID, alert.URL),
				Title:         alert.Alert,
				Description:   alert.Description,
				Severity:      severity,
				AffectedURL:   alert.URL,
				AffectedParam: alert.Param,
				Payload:       alert.Attack,
				Remediation:   alert.Solution,
				CWE:           []string{fmt.Sprintf("CWE-%s", alert.CWEID)},
				ToolSource:    "zap",
				Timestamp:     time.Now(),
			}
		}
	}
	return nil
}

func severityToFloat(severity string) float64 {
	switch severity {
	case "critical":
		return 9.5
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 2.5
	default:
		return 0.0
	}
}

func roundFloat(f float64, n int) float64 {
	pow := math.Pow(10, float64(n))
	return math.Round(f*pow) / pow
}
