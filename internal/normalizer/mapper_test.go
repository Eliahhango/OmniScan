package normalizer

import (
	"testing"
)

func TestCWEToOWASPMapping(t *testing.T) {
	tests := []struct {
		name     string
		cwe      string
		expected string
	}{
		// A01 - Broken Access Control
		{"CWE-22 maps to Broken Access Control", "CWE-22", "A01 - Broken Access Control"},
		{"CWE-862 maps to Broken Access Control", "CWE-862", "A01 - Broken Access Control"},
		{"CWE-352 maps to Broken Access Control", "CWE-352", "A01 - Broken Access Control"},
		// A02 - Cryptographic Failures
		{"CWE-311 maps to Cryptographic Failures", "CWE-311", "A02 - Cryptographic Failures"},
		{"CWE-326 maps to Cryptographic Failures", "CWE-326", "A02 - Cryptographic Failures"},
		// A03 - Injection
		{"CWE-79 maps to Injection", "CWE-79", "A03 - Injection"},
		{"CWE-89 maps to Injection", "CWE-89", "A03 - Injection"},
		{"CWE-78 maps to Injection", "CWE-78", "A03 - Injection"},
		// A04 - Insecure Design
		{"CWE-502 maps to Insecure Design", "CWE-502", "A04 - Insecure Design"},
		// A05 - Security Misconfiguration
		{"CWE-798 maps to Security Misconfiguration", "CWE-798", "A05 - Security Misconfiguration"},
		// A06 - Vulnerable & Outdated Components
		{"CWE-937 maps to Vulnerable & Outdated Components", "CWE-937", "A06 - Vulnerable & Outdated Components"},
		// A07 - Identification & Auth Failures
		{"CWE-521 maps to Identification & Auth Failures", "CWE-521", "A07 - Identification & Auth Failures"},
		// A08 - Software & Data Integrity Failures
		{"CWE-829 maps to Software & Data Integrity Failures", "CWE-829", "A08 - Software & Data Integrity Failures"},
		// A09 - Security Logging & Monitoring Failures
		{"CWE-778 maps to Security Logging & Monitoring Failures", "CWE-778", "A09 - Security Logging & Monitoring Failures"},
		// A10 - SSRF
		{"CWE-918 maps to SSRF", "CWE-918", "A10 - Server-Side Request Forgery"},
		// Unknown CWE
		{"CWE-9999 returns empty", "CWE-9999", ""},
		{"empty CWE returns empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cwes := []string{}
			if tt.cwe != "" {
				cwes = []string{tt.cwe}
			}
			result := MapCWEToOWASP(cwes)
			if result != tt.expected {
				t.Errorf("MapCWEToOWASP(%q) = %q, want %q", tt.cwe, result, tt.expected)
			}
		})
	}
}

func TestCWEToOWASPFirstMatchOnly(t *testing.T) {
	cwes := []string{"CWE-22", "CWE-79", "CWE-89"}
	result := MapCWEToOWASP(cwes)
	if result != "A01 - Broken Access Control" {
		t.Errorf("expected first match A01, got %q", result)
	}
}

func TestCWEToOWASPNoMatch(t *testing.T) {
	cwes := []string{"CWE-XXXX", "INVALID"}
	result := MapCWEToOWASP(cwes)
	if result != "" {
		t.Errorf("expected empty result for no match, got %q", result)
	}
}

func TestCWEToOWASPEmptyInput(t *testing.T) {
	result := MapCWEToOWASP([]string{})
	if result != "" {
		t.Errorf("expected empty result for empty input, got %q", result)
	}
}
