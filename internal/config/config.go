package config

import (
	"os"

	"github.com/Eliahhango/OmniScan/pkg/types"
	"gopkg.in/yaml.v3"
)

type Config struct {
	DBPath      string   `yaml:"db_path"`
	OutputDir   string   `yaml:"output_dir"`
	TemplateDir string   `yaml:"template_dir"`
	ToolsDir    string   `yaml:"tools_dir"`
	Concurrency int      `yaml:"concurrency"`
	RateLimit   int      `yaml:"rate_limit"`
	Nuclei      ToolConfig `yaml:"nuclei"`
	ZAP         ToolConfig `yaml:"zap"`
	Nmap        ToolConfig `yaml:"nmap"`
	OpenVAS     ToolConfig `yaml:"openvas"`
	Nikto       ToolConfig `yaml:"nikto"`
	Semgrep     ToolConfig `yaml:"semgrep"`
	FFUF        ToolConfig `yaml:"ffuf"`
}

type ToolConfig struct {
	Path    string `yaml:"path"`
	Enabled bool   `yaml:"enabled"`
	Timeout int    `yaml:"timeout"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Defaults(), nil
	}
	cfg := Defaults()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func Defaults() *Config {
	return &Config{
		DBPath:      "omniscan.db",
		OutputDir:   "reports",
		TemplateDir: "templates",
		ToolsDir:    "tools",
		Concurrency: 5,
		RateLimit:   150,
		Nuclei:      ToolConfig{Path: "nuclei", Enabled: true, Timeout: 1800},
		ZAP:         ToolConfig{Path: "zap", Enabled: true, Timeout: 3600},
		Nmap:        ToolConfig{Path: "nmap", Enabled: true, Timeout: 1800},
		OpenVAS:     ToolConfig{Path: "openvas", Enabled: false, Timeout: 3600},
		Nikto:       ToolConfig{Path: "nikto", Enabled: true, Timeout: 1800},
		Semgrep:     ToolConfig{Path: "semgrep", Enabled: false, Timeout: 1800},
		FFUF:        ToolConfig{Path: "ffuf", Enabled: true, Timeout: 1800},
	}
}

func (c *Config) ToScanConfig(target string) *types.ScanConfig {
	return &types.ScanConfig{
		Target:      target,
		RateLimit:   c.RateLimit,
		Concurrency: c.Concurrency,
		OutputDir:   c.OutputDir,
	}
}
