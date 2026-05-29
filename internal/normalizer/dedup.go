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

func (d *DedupEngine) Add(finding *types.Finding) *types.Finding {
	key1 := fmt.Sprintf("url+cve:%s|%s", finding.AffectedURL, finding.CVE)
	cweStr := strings.Join(finding.CWE, ",")
	key2 := fmt.Sprintf("url+cwe+param:%s|%s|%s", finding.AffectedURL, cweStr, finding.AffectedParam)
	key3 := fmt.Sprintf("cve:%s", finding.CVE)

	best := finding
	for _, existing := range d.seen {
		if existing.ID == finding.ID {
			return existing
		}
	}

	for _, existing := range d.seen {
		matchedURL := existing.AffectedURL == finding.AffectedURL
		matchedCVE := existing.CVE != "" && existing.CVE == finding.CVE
		matchedCWEParam := len(existing.CWE) > 0 && len(finding.CWE) > 0 &&
			existing.CWE[0] == finding.CWE[0] &&
			existing.AffectedParam == finding.AffectedParam

		if (matchedURL && matchedCVE) || (matchedURL && matchedCWEParam) || matchedCVE {
			newConf := CalculateConfidence(finding)
			oldConf := CalculateConfidence(existing)
			if newConf > oldConf {
				best = finding
			} else if oldConf > newConf {
				best = existing
			} else if matchedCVE && !matchedURL {
				if len(finding.Description) > len(existing.Description) {
					best = finding
				} else {
					best = existing
				}
			} else if finding.CVSS > existing.CVSS {
				best = finding
			} else {
				best = existing
			}
			break
		}
	}

	d.seen[key1] = best
	d.seen[key2] = best
	if best.CVE != "" {
		d.seen[key3] = best
	}

	return best
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
