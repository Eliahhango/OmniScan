package normalizer

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

func ComputeID(finding *types.Finding) string {
	key := fmt.Sprintf("%s|%s|%s|%s", finding.ToolSource, finding.AffectedURL, finding.CVE, strings.Join(finding.CWE, ","))
	hash := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", hash[:8])
}

func ParseNucleiOutput(jsonLine []byte) (*types.Finding, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(jsonLine, &raw); err != nil {
		return nil, err
	}

	templateID, _ := raw["template-id"].(string)
	host, _ := raw["host"].(string)
	matchedAt, _ := raw["matched-at"].(string)
	if matchedAt == "" {
		matchedAt = host
	}

	var severity types.Severity
	var title string
	var remediation string

	if info, ok := raw["info"].(map[string]interface{}); ok {
		if s, ok := info["severity"].(string); ok {
			severity = types.Severity(s)
		}
		if n, ok := info["name"].(string); ok {
			title = n
		}
		if r, ok := info["remediation"].(string); ok {
			remediation = r
		}
	}

	if title == "" {
		title = templateID
	}

	finding := &types.Finding{
		Title:       title,
		Description: title,
		Severity:    severity,
		AffectedURL: matchedAt,
		CVE:         templateID,
		Remediation: remediation,
		ToolSource:  "nuclei",
		Timestamp:   time.Now(),
	}
	finding.ID = ComputeID(finding)
	return finding, nil
}

func ParseZapOutput(jsonReport []byte) ([]types.Finding, error) {
	var report struct {
		Site []struct {
			Alerts []struct {
				Alert       string `json:"alert"`
				RiskCode    int    `json:"riskcode"`
				URL         string `json:"url"`
				Param       string `json:"param"`
				Attack      string `json:"attack"`
				Description string `json:"description"`
				Solution    string `json:"solution"`
				CWEID       string `json:"cweid"`
				PluginID    string `json:"pluginId"`
			} `json:"alerts"`
		} `json:"site"`
	}

	if err := json.Unmarshal(jsonReport, &report); err != nil {
		return nil, err
	}

	severityMap := map[int]types.Severity{
		0: types.SeverityInfo,
		1: types.SeverityLow,
		2: types.SeverityMedium,
		3: types.SeverityHigh,
	}

	var findings []types.Finding
	for _, site := range report.Site {
		for _, alert := range site.Alerts {
			severity, ok := severityMap[alert.RiskCode]
			if !ok {
				severity = types.SeverityInfo
			}

			finding := types.Finding{
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
			finding.ID = ComputeID(&finding)
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func ParseNmapOutput(xmlData []byte) ([]types.Finding, error) {
	return nil, nil
}

func ParseNiktoOutput(jsonLine []byte) (*types.Finding, error) {
	var item struct {
		ID          string `json:"id"`
		URL         string `json:"url"`
		Description string `json:"description"`
		Method      string `json:"method"`
	}
	if err := json.Unmarshal(jsonLine, &item); err != nil {
		return nil, err
	}

	finding := &types.Finding{
		Title:       item.Description,
		Severity:    types.SeverityMedium,
		AffectedURL: item.URL,
		ToolSource:  "nikto",
		Timestamp:   time.Now(),
	}
	finding.ID = ComputeID(finding)
	return finding, nil
}

func ParseSemgrepOutput(jsonData []byte) ([]types.Finding, error) {
	var report struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
			Extra struct {
				Message  string `json:"message"`
				Severity string `json:"severity"`
				Metadata struct {
					CWE []string `json:"cwe"`
				} `json:"metadata"`
			} `json:"extra"`
		} `json:"results"`
	}

	if err := json.Unmarshal(jsonData, &report); err != nil {
		return nil, err
	}

	var findings []types.Finding
	for _, r := range report.Results {
		var severity types.Severity
		switch r.Extra.Severity {
		case "ERROR":
			severity = types.SeverityHigh
		case "WARNING":
			severity = types.SeverityMedium
		default:
			severity = types.SeverityLow
		}

		finding := types.Finding{
			Title:       r.CheckID,
			Description: r.Extra.Message,
			Severity:    severity,
			CWE:         r.Extra.Metadata.CWE,
			AffectedURL: fmt.Sprintf("%s:%d", r.Path, r.Start.Line),
			ToolSource:  "semgrep",
			Timestamp:   time.Now(),
		}
		finding.ID = ComputeID(&finding)
		findings = append(findings, finding)
	}
	return findings, nil
}

func ParseOpenVASOutput(xmlData []byte) ([]types.Finding, error) {
	return nil, nil
}

func RedactSecret(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

func ParseTrufflehogOutput(jsonLine []byte) (*types.Finding, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(jsonLine, &raw); err != nil {
		return nil, err
	}

	sourceMetadata, _ := raw["SourceMetadata"].(map[string]interface{})
	var remediation string
	if data, ok := sourceMetadata["Data"].(map[string]interface{}); ok {
		if file, ok := data["file"].(string); ok {
			remediation = fmt.Sprintf("Secret found in file: %s", file)
		}
	}

	detectorName, _ := raw["DetectorName"].(string)
	rawData, _ := raw["Raw"].(string)

	hash := sha256.Sum256([]byte(rawData))

	finding := &types.Finding{
		Title:       fmt.Sprintf("Secret: %s", detectorName),
		Description: fmt.Sprintf("Secret detected by TruffleHog - %s", detectorName),
		Severity:    types.SeverityCritical,
		Payload:     RedactSecret(rawData),
		SecretHash:  fmt.Sprintf("%x", hash),
		Remediation: remediation,
		ToolSource:  "trufflehog",
		Timestamp:   time.Now(),
	}
	finding.ID = ComputeID(finding)
	return finding, nil
}
