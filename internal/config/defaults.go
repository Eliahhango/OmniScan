package config

var DefaultConfigYAML = `db_path: omniscan.db
output_dir: reports
template_dir: templates
tools_dir: tools
concurrency: 5
rate_limit: 150
nuclei:
  path: nuclei
  enabled: true
  timeout: 1800
zap:
  path: zap
  enabled: true
  timeout: 3600
nmap:
  path: nmap
  enabled: true
  timeout: 1800
openvas:
  path: openvas
  enabled: false
  timeout: 3600
nikto:
  path: nikto
  enabled: true
  timeout: 1800
semgrep:
  path: semgrep
  enabled: false
  timeout: 1800
ffuf:
  path: ffuf
  enabled: true
  timeout: 1800
`
