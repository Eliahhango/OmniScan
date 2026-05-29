package normalizer

import (
	"fmt"
	"strings"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

type DedupEngine struct {
	seen map[string]*types.Finding
}

func NewDedupEngine() *DedupEngine {
	return &DedupEngine{
		seen: make(map[string]*types.Finding),
	}
}

var severityRank = map[types.Severity]int{
	types.SeverityCritical: 4,
	types.SeverityHigh:     3,
	types.SeverityMedium:   2,
	types.SeverityLow:      1,
	types.SeverityInfo:     0,
}

func toolConfidence(tool string) int {
	switch strings.ToLower(tool) {
	case "nuclei":
		return 100
	case "zap":
		return 60
	case "semgrep":
		return 90
	case "gitleaks":
		return 85
	case "trufflehog":
		return 80
	case "custom":
		return 95
	default:
		return 50
	}
}

func CalculateConfidence(finding *types.Finding) int {
	base := toolConfidence(finding.ToolSource)
	if finding.Proof != "" {
		base += 15
	}
	if finding.Payload != "" {
		base += 10
	}
	if finding.CVE != "" {
		base += 5
	}
	if finding.CVSS >= 7.0 {
		base += 5
	}
	if base > 100 {
		base = 100
	}
	return base
}

func mergeFindings(existing, finding *types.Finding) *types.Finding {
	merged := *existing
	if severityRank[finding.Severity] > severityRank[existing.Severity] {
		merged.Severity = finding.Severity
	}
	if finding.CVSS > existing.CVSS {
		merged.CVSS = finding.CVSS
	}
	if finding.Description != "" && len(finding.Description) > len(existing.Description) {
		merged.Description = finding.Description
	}
	if finding.Remediation != "" {
		if existing.Remediation == "" {
			merged.Remediation = finding.Remediation
		} else if !strings.Contains(existing.Remediation, finding.Remediation) {
			merged.Remediation = existing.Remediation + "\n---\n" + finding.Remediation
		}
	}
	if finding.Proof != "" && existing.Proof == "" {
		merged.Proof = finding.Proof
	}
	if finding.Payload != "" && existing.Payload == "" {
		merged.Payload = finding.Payload
	}
	return &merged
}

func (d *DedupEngine) Add(finding *types.Finding) *types.Finding {
	for _, existing := range d.seen {
		if existing.ID == finding.ID {
			return existing
		}
	}

	key1 := fmt.Sprintf("url+cve:%s|%s", finding.AffectedURL, finding.CVE)
	cweStr := strings.Join(finding.CWE, ",")
	key2 := fmt.Sprintf("url+cwe+param:%s|%s|%s", finding.AffectedURL, cweStr, finding.AffectedParam)
	key3 := fmt.Sprintf("cve:%s", finding.CVE)

	for _, existing := range d.seen {
		matchedURL := existing.AffectedURL == finding.AffectedURL
		matchedCVE := existing.CVE != "" && existing.CVE == finding.CVE
		matchedCWEParam := len(existing.CWE) > 0 && len(finding.CWE) > 0 &&
			existing.CWE[0] == finding.CWE[0] &&
			existing.AffectedParam == finding.AffectedParam

		if (matchedURL && matchedCVE) || (matchedURL && matchedCWEParam) || matchedCVE {
			merged := mergeFindings(existing, finding)
			d.seen[key1] = merged
			d.seen[key2] = merged
			if merged.CVE != "" {
				d.seen[key3] = merged
			}
			return merged
		}
	}

	d.seen[key1] = finding
	d.seen[key2] = finding
	if finding.CVE != "" {
		d.seen[key3] = finding
	}
	return finding
}

func (d *DedupEngine) GetAll() []types.Finding {
	seen := make(map[string]bool)
	var result []types.Finding
	for _, f := range d.seen {
		if !seen[f.ID] {
			seen[f.ID] = true
			result = append(result, *f)
		}
	}
	return result
}

func (d *DedupEngine) Reset() {
	d.seen = make(map[string]*types.Finding)
}
