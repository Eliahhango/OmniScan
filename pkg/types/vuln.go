package types

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type ScanStage int

const (
	StageRecon     ScanStage = 0
	StageCrawling  ScanStage = 1
	StageFuzzing   ScanStage = 2
	StageVulnScan  ScanStage = 3
	StageDeepScan  ScanStage = 4
	StageSAST      ScanStage = 5
	StageSecrets   ScanStage = 6
	StageReporting ScanStage = 7
)

var StageNames = map[ScanStage]string{
	StageRecon:     "Recon",
	StageCrawling:  "Crawling",
	StageFuzzing:   "Fuzzing",
	StageVulnScan:  "Vulnerability Scan",
	StageDeepScan:  "Deep Scan",
	StageSAST:      "SAST",
	StageSecrets:   "Secrets",
	StageReporting: "Reporting",
}

type Finding struct {
	ID             string    `json:"id"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Severity       Severity  `json:"severity"`
	CVSS           float64   `json:"cvss"`
	CVE            string    `json:"cve,omitempty"`
	CWE            []string  `json:"cwe,omitempty"`
	OWASP2025      string    `json:"owasp2025,omitempty"`
	AffectedURL    string    `json:"affected_url"`
	AffectedParam  string    `json:"affected_param,omitempty"`
	Payload        string    `json:"payload,omitempty"`
	Proof          string    `json:"proof,omitempty"`
	Remediation    string    `json:"remediation,omitempty"`
	ToolSource     string    `json:"tool_source"`
	Timestamp      time.Time `json:"timestamp"`
	CVSSVector     string    `json:"cvss_vector,omitempty"`
	EPSS           float64   `json:"epss,omitempty"`
	FalsePositive  bool      `json:"false_positive"`
	BountyPlatforms []string `json:"bounty_platforms,omitempty"`
}

type ScanPipeline struct {
	Target   string
	Scope    []string
	Stage    ScanStage
	Progress float64
	Findings []Finding
	StartTime time.Time
}

type ScanConfig struct {
	Target      string   `yaml:"target"`
	Scope       []string `yaml:"scope"`
	Tools       []string `yaml:"tools"`
	RateLimit   int      `yaml:"rate_limit"`
	Concurrency int      `yaml:"concurrency"`
	OutputDir   string   `yaml:"output_dir"`
	Resume      bool     `yaml:"resume"`
}
