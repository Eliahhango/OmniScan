package normalizer

import (
	"testing"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

func TestCWEToOWASP2025Mapping(t *testing.T) {
	tests := []struct {
		name     string
		cwe      string
		expected string
	}{
		// A01 - Broken Access Control
		{"CWE-22 maps to Broken Access Control", "CWE-22", "A01-Broken Access Control"},
		{"CWE-287 maps to Broken Access Control", "CWE-287", "A01-Broken Access Control"},
		{"CWE-288 maps to Broken Access Control", "CWE-288", "A01-Broken Access Control"},
		// A02 - Cryptographic Failures
		{"CWE-311 maps to Cryptographic Failures", "CWE-311", "A02-Cryptographic Failures"},
		{"CWE-326 maps to Identification and Authentication Failures", "CWE-326", "A07-Identification and Authentication Failures"},
		// A03 - Injection
		{"CWE-79 maps to Injection", "CWE-79", "A03-Injection"},
		{"CWE-89 maps to Injection", "CWE-89", "A03-Injection"},
		{"CWE-78 maps to Injection", "CWE-78", "A03-Injection"},
		// A04 - Insecure Design
		{"CWE-73 maps to Insecure Design", "CWE-73", "A04-Insecure Design"},
		// A05 - Security Misconfiguration
		{"CWE-798 maps to Identification and Authentication Failures", "CWE-798", "A07-Identification and Authentication Failures"},
		// A06 - Vulnerable & Outdated Components
		{"CWE-937 maps to Vulnerable and Outdated Components", "CWE-937", "A06-Vulnerable and Outdated Components"},
		// A07 - Identification and Authentication Failures
		{"CWE-521 maps to Identification and Authentication Failures", "CWE-521", "A07-Identification and Authentication Failures"},
		// A08 - Software and Data Integrity Failures
		{"CWE-829 maps to Software and Data Integrity Failures", "CWE-829", "A08-Software and Data Integrity Failures"},
		// A09 - Security Logging and Monitoring Failures
		{"CWE-778 maps to Security Logging and Monitoring Failures", "CWE-778", "A09-Security Logging and Monitoring Failures"},
		// A10 - SSRF
		{"CWE-918 maps to SSRF", "CWE-918", "A10-Server-Side Request Forgery"},
		// Unknown CWE
		{"CWE-9999 returns empty", "CWE-9999", ""},
		{"empty CWE returns empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MapCWEToOWASP2025(tt.cwe)
			if result != tt.expected {
				t.Errorf("MapCWEToOWASP2025(%q) = %q, want %q", tt.cwe, result, tt.expected)
			}
		})
	}
}

func TestCWEToOWASP2025NoMatch(t *testing.T) {
	result := MapCWEToOWASP2025("CWE-XXXX")
	if result != "" {
		t.Errorf("expected empty result for no match, got %q", result)
	}
}

func TestCWEToOWASP2025EmptyInput(t *testing.T) {
	result := MapCWEToOWASP2025("")
	if result != "" {
		t.Errorf("expected empty result for empty input, got %q", result)
	}
}

func TestEnrichWithOWASP2025(t *testing.T) {
	f := &types.Finding{
		CWE: []string{"CWE-79", "CWE-89"},
	}
	EnrichWithOWASP2025(f)
	if f.OWASP2025 != "A03-Injection" {
		t.Errorf("expected A03-Injection, got %q", f.OWASP2025)
	}
}

func TestEnrichWithOWASP2025NoMatch(t *testing.T) {
	f := &types.Finding{
		CWE: []string{"CWE-XXXX"},
	}
	EnrichWithOWASP2025(f)
	if f.OWASP2025 != "" {
		t.Errorf("expected empty OWASP, got %q", f.OWASP2025)
	}
}
