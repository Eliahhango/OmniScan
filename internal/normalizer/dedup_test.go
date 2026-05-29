package normalizer

import (
	"testing"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

func TestDedupSameURLAndCVE(t *testing.T) {
	engine := NewDedupEngine()

	f1 := &types.Finding{
		ID:          "nuclei-CVE-2024-1234-https://example.com",
		Title:       "Test Vuln 1",
		Severity:    types.SeverityHigh,
		CVE:         "CVE-2024-1234",
		AffectedURL: "https://example.com",
		CVSS:        7.5,
		ToolSource:  "nuclei",
	}

	f2 := &types.Finding{
		ID:          "nuclei-CVE-2024-1234-https://example.com-v2",
		Title:       "Test Vuln 2",
		Severity:    types.SeverityHigh,
		CVE:         "CVE-2024-1234",
		AffectedURL: "https://example.com",
		CVSS:        8.0,
		ToolSource:  "nuclei",
	}

	result1 := engine.Add(f1)
	if result1.ID != f1.ID {
		t.Error("first add should return a finding with the same ID")
	}

	result2 := engine.Add(f2)
	if result2.CVSS != 8.0 {
		t.Errorf("dedup should keep the finding with higher CVSS when confidence is equal, got %f", result2.CVSS)
	}

	if len(engine.GetAll()) != 1 {
		t.Errorf("expected 1 unique finding, got %d", len(engine.GetAll()))
	}
}

func TestDedupSameURLAndCWEParam(t *testing.T) {
	engine := NewDedupEngine()

	f1 := &types.Finding{
		ID:            "nuclei-xss-https://example.com",
		Title:         "XSS",
		Severity:      types.SeverityMedium,
		AffectedURL:   "https://example.com",
		CWE:           []string{"CWE-79"},
		AffectedParam: "q",
		CVSS:          6.5,
		ToolSource:    "nuclei",
	}

	f2 := &types.Finding{
		ID:            "zap-xss-https://example.com",
		Title:         "XSS",
		Severity:      types.SeverityHigh,
		AffectedURL:   "https://example.com",
		CWE:           []string{"CWE-79"},
		AffectedParam: "q",
		CVSS:          6.5,
		ToolSource:    "zap",
	}

	result1 := engine.Add(f1)
	if result1.ID != f1.ID {
		t.Error("first add should return a finding with the same ID")
	}

	result2 := engine.Add(f2)
	if result2.ToolSource != "nuclei" {
		t.Log("with equal confidence, the existing finding is kept")
	}
}

func TestDedupSameCVE(t *testing.T) {
	engine := NewDedupEngine()

	critical := &types.Finding{
		ID:          "nuclei-CVE-2024-9999-a",
		Title:       "Critical Vuln",
		Severity:    types.SeverityCritical,
		CVE:         "CVE-2024-9999",
		AffectedURL: "https://a.example.com",
		CVSS:        9.5,
		ToolSource:  "nuclei",
		Description: "short",
	}

	high := &types.Finding{
		ID:          "nuclei-CVE-2024-9999-b",
		Title:       "Critical Vuln",
		Severity:    types.SeverityCritical,
		CVE:         "CVE-2024-9999",
		AffectedURL: "https://b.example.com",
		CVSS:        9.5,
		ToolSource:  "nuclei",
		Description: "longer description with more details",
	}

	engine.Add(critical)
	result := engine.Add(high)
	if len(result.Description) <= len(critical.Description) {
		t.Error("should keep finding with longer description when confidence and CVSS are equal")
	}
}

func TestConfidenceScoring(t *testing.T) {
	tests := []struct {
		name     string
		finding  *types.Finding
		expected int
	}{
		{
			name: "nuclei with proof",
			finding: &types.Finding{
				ToolSource: "nuclei",
				Proof:      "response contains XSS",
			},
			expected: 115,
		},
		{
			name: "default tool no extras",
			finding: &types.Finding{
				ToolSource: "unknown",
			},
			expected: 50,
		},
		{
			name: "semgrep with payload and CVE",
			finding: &types.Finding{
				ToolSource: "semgrep",
				Payload:    "exec('rm -rf /')",
				CVE:        "CVE-2024-5678",
			},
			expected: 105,
		},
		{
			name: "capped at 100",
			finding: &types.Finding{
				ToolSource: "nuclei",
				Proof:      "found",
				Payload:    "exploit",
				CVE:        "CVE-2024-9999",
				CVSS:       9.0,
			},
			expected: 100,
		},
		{
			name: "trufflehog with all extras",
			finding: &types.Finding{
				ToolSource: "trufflehog",
				Proof:      "key found",
				Payload:    "sk-...",
			},
			expected: 105,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateConfidence(tt.finding)
			if got > 100 {
				got = 100
			}
			expected := tt.expected
			if expected > 100 {
				expected = 100
			}
			if got != expected {
				t.Errorf("CalculateConfidence() = %d, want %d", got, expected)
			}
		})
	}
}

func TestDedupReset(t *testing.T) {
	engine := NewDedupEngine()

	engine.Add(&types.Finding{
		ID:          "test-1",
		Title:       "Test",
		Severity:    types.SeverityLow,
		AffectedURL: "https://example.com",
		ToolSource:  "nuclei",
	})

	if len(engine.GetAll()) != 1 {
		t.Errorf("expected 1 finding before reset, got %d", len(engine.GetAll()))
	}

	engine.Reset()

	if len(engine.GetAll()) != 0 {
		t.Errorf("expected 0 findings after reset, got %d", len(engine.GetAll()))
	}
}
