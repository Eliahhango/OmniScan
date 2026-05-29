package types

import (
	"testing"
)

func TestScanStageNames(t *testing.T) {
	tests := []struct {
		stage    ScanStage
		expected string
	}{
		{StageRecon, "Recon"},
		{StageCrawling, "Crawling"},
		{StageFuzzing, "Fuzzing"},
		{StageVulnScan, "Vulnerability Scan"},
		{StageDeepScan, "Deep Scan"},
		{StageSAST, "SAST"},
		{StageSecrets, "Secrets"},
		{StageReporting, "Reporting"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			name, ok := StageNames[tt.stage]
			if !ok {
				t.Errorf("StageNames missing entry for Stage %d", tt.stage)
				return
			}
			if name != tt.expected {
				t.Errorf("StageNames[%d] = %q, want %q", tt.stage, name, tt.expected)
			}
		})
	}
}

func TestSeverityConstants(t *testing.T) {
	if SeverityCritical != "critical" {
		t.Errorf("SeverityCritical = %q, want %q", SeverityCritical, "critical")
	}
	if SeverityHigh != "high" {
		t.Errorf("SeverityHigh = %q, want %q", SeverityHigh, "high")
	}
	if SeverityMedium != "medium" {
		t.Errorf("SeverityMedium = %q, want %q", SeverityMedium, "medium")
	}
	if SeverityLow != "low" {
		t.Errorf("SeverityLow = %q, want %q", SeverityLow, "low")
	}
	if SeverityInfo != "info" {
		t.Errorf("SeverityInfo = %q, want %q", SeverityInfo, "info")
	}
}
