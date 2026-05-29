package scanner

import (
	"testing"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

func TestParseNucleiLine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *types.Finding
		wantErr bool
	}{
		{
			name:    "empty input",
			input:   ``,
			wantErr: true,
		},
		{
			name:    "invalid json",
			input:   `{not-json`,
			wantErr: true,
		},
		{
			name:  "critical severity",
			input: `{"template-id":"jwt-secret-exposure","info":{"name":"JWT Secret Exposure","severity":"critical","tags":["cve-2024-1234","jwt","exposure"]},"host":"https://example.com","matched-at":"https://example.com/auth","type":"http"}`,
			want: &types.Finding{
				ID:          "nuclei-jwt-secret-exposure-https://example.com/auth",
				Title:       "JWT Secret Exposure",
				Severity:    types.SeverityCritical,
				AffectedURL: "https://example.com/auth",
				CVE:         "CVE-2024-1234",
				ToolSource:  "nuclei",
				CWE:         []string{},
			},
			wantErr: false,
		},
		{
			name:  "low severity without matched-at",
			input: `{"template-id":"ssl-detect","info":{"name":"SSL Detection","severity":"low","tags":"ssl,detect"},"host":"https://example.com","type":"http"}`,
			want: &types.Finding{
				ID:          "nuclei-ssl-detect-https://example.com",
				Title:       "SSL Detection",
				Severity:    types.SeverityLow,
				AffectedURL: "https://example.com",
				ToolSource:  "nuclei",
				CWE:         []string{},
			},
			wantErr: false,
		},
		{
			name:  "medium severity with extracted results",
			input: `{"template-id":"sqli-detect","info":{"name":"SQL Injection","severity":"medium","description":"SQLi test","tags":["cve-2024-5678","sql-injection","sqli"]},"host":"https://target.com","matched-at":"https://target.com/page?id=1","type":"http","extracted-results":["admin' OR '1'='1"]}`,
			want: &types.Finding{
				ID:          "nuclei-sqli-detect-https://target.com/page?id=1",
				Title:       "SQL Injection",
				Severity:    types.SeverityMedium,
				AffectedURL: "https://target.com/page?id=1",
				CVE:         "CVE-2024-5678",
				ToolSource:  "nuclei",
				Description: "SQLi test",
				Proof:       "admin' OR '1'='1",
				CWE:         []string{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNucleiLine([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("parseNucleiLine() error = %v, wantErr = %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if got.ID != tt.want.ID {
				t.Errorf("ID = %q, want %q", got.ID, tt.want.ID)
			}
			if got.Title != tt.want.Title {
				t.Errorf("Title = %q, want %q", got.Title, tt.want.Title)
			}
			if got.Severity != tt.want.Severity {
				t.Errorf("Severity = %q, want %q", got.Severity, tt.want.Severity)
			}
			if got.AffectedURL != tt.want.AffectedURL {
				t.Errorf("AffectedURL = %q, want %q", got.AffectedURL, tt.want.AffectedURL)
			}
			if got.CVE != tt.want.CVE {
				t.Errorf("CVE = %q, want %q", got.CVE, tt.want.CVE)
			}
			if got.Description != tt.want.Description {
				t.Errorf("Description = %q, want %q", got.Description, tt.want.Description)
			}
			if got.Proof != tt.want.Proof {
				t.Errorf("Proof = %q, want %q", got.Proof, tt.want.Proof)
			}
			if len(got.CWE) != len(tt.want.CWE) {
				t.Errorf("CWE len = %d, want %d", len(got.CWE), len(tt.want.CWE))
			}
			if got.ToolSource != tt.want.ToolSource {
				t.Errorf("ToolSource = %q, want %q", got.ToolSource, tt.want.ToolSource)
			}
		})
	}
}

func TestParseNucleiLineSeverityLevels(t *testing.T) {
	levels := []struct {
		severity string
		expected types.Severity
	}{
		{"critical", types.SeverityCritical},
		{"high", types.SeverityHigh},
		{"medium", types.SeverityMedium},
		{"low", types.SeverityLow},
		{"info", types.SeverityInfo},
		{"unknown", types.Severity("unknown")},
	}

	for _, l := range levels {
		t.Run(string(l.expected), func(t *testing.T) {
			input := `{"template-id":"test","info":{"name":"Test","severity":"` + l.severity + `"},"host":"https://x.com"}`
			finding, err := parseNucleiLine([]byte(input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if finding.Severity != l.expected {
				t.Errorf("Severity = %q, want %q", finding.Severity, l.expected)
			}
		})
	}
}
