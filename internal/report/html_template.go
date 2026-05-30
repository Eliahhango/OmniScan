package report

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Report - {{.Target}}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background: #0d1117; color: #c9d1d9; padding: 0; line-height: 1.6; }

  /* Cover Page */
  .cover { background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #1c2333 100%); min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; padding: 40px; border-bottom: 3px solid #30363d; }
  .cover h1 { color: #58a6ff; font-size: 3em; margin-bottom: 10px; letter-spacing: -0.5px; }
  .cover .subtitle { color: #8b949e; font-size: 1.2em; margin-bottom: 30px; }
  .cover .meta-box { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 30px 50px; display: inline-block; text-align: left; }
  .cover .meta-box div { margin: 8px 0; color: #c9d1d9; }
  .cover .meta-box span { color: #58a6ff; font-weight: 600; }
  .cover .badge { display: inline-block; background: #1f6feb33; color: #58a6ff; border: 1px solid #1f6feb; padding: 8px 24px; border-radius: 20px; font-size: 0.9em; margin-top: 30px; }
  .risk-badge { display: inline-block; padding: 6px 24px; border-radius: 20px; font-size: 1.1em; font-weight: 700; margin-top: 10px; }
  .risk-critical { background: #f8514933; color: #f85149; border: 2px solid #f85149; }
  .risk-high { background: #d2992233; color: #d29922; border: 2px solid #d29922; }
  .risk-medium { background: #58a6ff33; color: #58a6ff; border: 2px solid #58a6ff; }
  .risk-low { background: #3fb95033; color: #3fb950; border: 2px solid #3fb950; }
  .risk-none { background: #8b949e33; color: #8b949e; border: 2px solid #8b949e; }

  .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }

  /* Section Headers */
  h2 { color: #f0f6fc; font-size: 1.5em; margin: 40px 0 20px; border-bottom: 2px solid #30363d; padding-bottom: 10px; display: flex; align-items: center; gap: 10px; }
  h2 .section-num { background: #1f6feb; color: #fff; font-size: 0.7em; padding: 2px 12px; border-radius: 12px; }
  h3 { color: #f0f6fc; font-size: 1.15em; }

  .meta { color: #8b949e; margin-bottom: 30px; display: flex; flex-wrap: wrap; gap: 20px; }
  .meta span { margin-right: 20px; }

  /* Stats / Severity Cards */
  .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 30px; }
  .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; transition: transform 0.2s; }
  .stat-card:hover { transform: translateY(-2px); }
  .stat-card .count { font-size: 2.5em; font-weight: 700; }
  .stat-card .label { color: #8b949e; font-size: 0.85em; margin-top: 5px; text-transform: uppercase; letter-spacing: 0.5px; }
  .critical .count { color: #f85149; }
  .high .count { color: #d29922; }
  .medium .count { color: #58a6ff; }
  .low .count { color: #3fb950; }
  .info .count { color: #8b949e; }

  /* Summary bar chart */
  .chart-container { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 30px; }
  .chart-bar-row { display: flex; align-items: center; margin: 8px 0; gap: 10px; }
  .chart-label { width: 80px; font-size: 0.85em; color: #8b949e; text-align: right; }
  .chart-bar-bg { flex: 1; height: 28px; background: #21262d; border-radius: 4px; overflow: hidden; }
  .chart-bar { height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 10px; font-size: 0.8em; font-weight: 600; color: #fff; min-width: 30px; transition: width 0.5s; }
  .bar-critical { background: linear-gradient(90deg, #f85149, #da3633); }
  .bar-high { background: linear-gradient(90deg, #d29922, #bb8009); }
  .bar-medium { background: linear-gradient(90deg, #58a6ff, #1f6feb); }
  .bar-low { background: linear-gradient(90deg, #3fb950, #238636); }
  .bar-info { background: linear-gradient(90deg, #8b949e, #6e7681); }

  /* Findings */
  .finding { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
  .finding-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; cursor: pointer; user-select: none; }
  .finding-header:hover { background: #1c2333; }
  .finding-header h3 { margin: 0; font-size: 1em; flex: 1; }
  .finding .severity-badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.75em; font-weight: 700; text-transform: uppercase; margin-right: 12px; white-space: nowrap; }
  .severity-critical { background: #f8514933; color: #f85149; border: 1px solid #f85149; }
  .severity-high { background: #d2992233; color: #d29922; border: 1px solid #d29922; }
  .severity-medium { background: #58a6ff33; color: #58a6ff; border: 1px solid #58a6ff; }
  .severity-low { background: #3fb95033; color: #3fb950; border: 1px solid #3fb950; }
  .severity-info { background: #8b949e33; color: #8b949e; border: 1px solid #8b949e; }
  .finding-body { padding: 0 20px 16px; display: none; }
  .finding-body.open { display: block; }
  .finding .details { color: #8b949e; font-size: 0.9em; }
  .finding .details div { margin: 4px 0; }
  .finding .details .label { color: #58a6ff; font-weight: 600; }
  .toggle-icon { color: #8b949e; transition: transform 0.2s; font-size: 0.8em; margin-left: 12px; }
  .finding-header.open .toggle-icon { transform: rotate(90deg); }

  /* OWASP chart */
  .owasp-grid { margin-top: 10px; }
  .owasp-bar-row { display: flex; align-items: center; margin-bottom: 6px; }
  .owasp-label { width: 260px; font-size: 0.82em; color: #c9d1d9; text-align: right; padding-right: 12px; flex-shrink: 0; }
  .owasp-bar-bg { flex: 1; height: 22px; background: #21262d; border-radius: 4px; overflow: hidden; }
  .owasp-bar { height: 100%; background: #1f6feb; border-radius: 4px; font-size: 0.75em; color: #fff; line-height: 22px; padding-left: 8px; min-width: 20px; }

  /* CVSS indicator */
  .cvss-pill { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 0.8em; font-weight: 600; }
  .cvss-high { background: #da363333; color: #f85149; border: 1px solid #da3633; }
  .cvss-medium { background: #bb800933; color: #d29922; border: 1px solid #bb8009; }
  .cvss-low { background: #23863633; color: #3fb950; border: 1px solid #238636; }

  /* Tables */
  table { width: 100%; border-collapse: collapse; margin: 15px 0; }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #21262d; }
  th { background: #161b22; color: #8b949e; font-weight: 600; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }
  td { color: #c9d1d9; font-size: 0.9em; }
  tr:hover td { background: #1c2333; }

  /* Filter buttons */
  .filter-bar { display: flex; gap: 8px; margin-bottom: 20px; flex-wrap: wrap; }
  .filter-btn { padding: 6px 16px; border-radius: 20px; border: 1px solid #30363d; background: transparent; color: #c9d1d9; cursor: pointer; font-size: 0.85em; transition: all 0.2s; }
  .filter-btn:hover { border-color: #58a6ff; color: #58a6ff; }
  .filter-btn.active { background: #1f6feb33; border-color: #1f6feb; color: #58a6ff; }

  /* Appendix styling */
  .appendix { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 15px; }
  .appendix h3 { color: #f0f6fc; margin-bottom: 15px; }
  .proof-block { background: #0d1117; border: 1px solid #21262d; border-radius: 6px; padding: 16px; margin: 10px 0; font-family: 'SFMono-Regular', 'Consolas', 'Liberation Mono', monospace; font-size: 0.85em; white-space: pre-wrap; word-break: break-all; color: #f0f6fc; }
  .proof-block .proof-label { color: #8b949e; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 0.85em; margin-bottom: 6px; }

  .footer { text-align: center; color: #8b949e; margin-top: 40px; padding: 30px 20px; border-top: 1px solid #30363d; font-size: 0.85em; }
  .footer-print { display: none; }

  .print-only { display: none; }
  @media print {
    .no-print { display: none; }
    .print-only { display: block; }
    body { background: #fff; color: #000; padding: 0; }
    .cover { min-height: 90vh; background: #fff; border-bottom: 2px solid #333; }
    .cover h1 { color: #1f6feb; }
    .stat-card, .finding, .appendix, .chart-container { border-color: #ddd; background: #f6f8fa; }
    .chart-bar-bg { background: #e1e4e8; }
    .finding-body { display: block !important; }
    .toggle-icon { display: none; }
  }

  /* Tabs */
  .tab-bar { display: flex; gap: 0; margin-bottom: 20px; border-bottom: 1px solid #30363d; }
  .tab-btn { padding: 10px 24px; background: transparent; border: none; color: #8b949e; cursor: pointer; font-size: 0.9em; border-bottom: 2px solid transparent; transition: all 0.2s; }
  .tab-btn:hover { color: #c9d1d9; }
  .tab-btn.active { color: #58a6ff; border-bottom-color: #58a6ff; }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
</style>
</head>
<body>

<!-- Cover Page -->
<div class="cover">
  <div class="badge">OmniScan Security Assessment</div>
  <p style="color: #888; font-size: 0.85em; margin-top: 4px;">EliTechWiz / <a href="https://github.com/Eliahhango" style="color: #58a6ff;">github.com/Eliahhango</a></p>
  <h1>{{.Target}}</h1>
  <p class="subtitle">Comprehensive Vulnerability Report &mdash; OWASP Top 10:2025 Mapped</p>
  <div class="meta-box">
    <div><span>Scan Date:</span> {{.ScanDate}}</div>
    <div><span>Duration:</span> {{.Duration}}</div>
    <div><span>Total Vulnerabilities:</span> {{.TotalVulns}}</div>
    <div><span>Tools Used:</span> {{range $i, $t := .ToolsUsed}}{{if $i}}, {{end}}{{$t}}{{end}}</div>
    <div><span>Distinct CWEs:</span> {{.CWECount}}</div>
    <div><span>OWASP Categories Affected:</span> {{.OWASPCoverage}}/10</div>
  </div>
  {{if gt .TotalVulns 0}}
  <div class="risk-badge risk-{{.RiskLabel | lower}}">Risk Score: {{printf "%.0f" .RiskScore}} / {{.RiskLabel}}</div>
  {{else}}
  <div class="risk-badge risk-none">Risk Score: 0 / None — No Vulnerabilities Found</div>
  {{end}}
  <div style="margin-top: 40px; color: #8b949e; font-size: 0.85em;">
    Generated {{.GeneratedAt}} &mdash; Confidential
  </div>
</div>

<div class="container">

<!-- 1. Executive Summary -->
<h2><span class="section-num">1</span> Executive Summary</h2>
<p style="color: #8b949e; margin-bottom: 20px;">
  This report presents the findings of a security assessment of <strong>{{.Target}}</strong>.
  A total of <strong>{{.TotalVulns}}</strong> vulnerabilities were identified.
  Risk score: <strong>{{printf "%.0f" .RiskScore}}/{{.RiskLabel}}</strong>.
</p>

<div class="chart-container">
  <h3 style="color: #f0f6fc; font-size: 1em; margin-bottom: 15px;">Severity Impact Reference</h3>
  <table>
    <tr><th>Severity</th><th>Impact</th></tr>
    <tr><td><span class="severity-badge severity-critical">Critical</span></td><td>Immediate and severe threat. Could lead to full system compromise, data breach, or remote code execution. Requires urgent patching and mitigation within 24 hours.</td></tr>
    <tr><td><span class="severity-badge severity-high">High</span></td><td>Significant security risk. Could lead to sensitive data exposure, privilege escalation, or service disruption. Should be addressed within one week.</td></tr>
    <tr><td><span class="severity-badge severity-medium">Medium</span></td><td>Moderate risk. Could be exploited under specific conditions or in combination with other vulnerabilities. Should be addressed within one month.</td></tr>
    <tr><td><span class="severity-badge severity-low">Low</span></td><td>Minor security concern. Limited impact or requires unlikely attack scenario. Should be addressed during next maintenance cycle.</td></tr>
    <tr><td><span class="severity-badge severity-info">Info</span></td><td>Informational only. No direct security impact but useful for understanding the attack surface. Review for potential enrichment of other findings.</td></tr>
  </table>
</div>

{{if eq .TotalVulns 0}}
<div class="chart-container" style="text-align: center; padding: 40px;">
  <h3 style="color: #3fb950; font-size: 1.3em; margin-bottom: 15px;">No Vulnerabilities Detected</h3>
  <p style="color: #8b949e;">The scan completed successfully but no security vulnerabilities were found. This could mean:</p>
  <ul style="color: #8b949e; text-align: left; display: inline-block; margin-top: 10px;">
    <li>The target is well-secured with no known vulnerabilities</li>
    <li>Not all scanning tools were installed on the scanning system</li>
    <li>Additional authentication or configuration may be needed for deeper scanning</li>
  </ul>
  <p style="color: #8b949e; margin-top: 15px;"><strong>Recommendation:</strong> Run <code>omniscan setup</code> to install all tools, and consider adding API keys or authenticated scan configuration for comprehensive coverage.</p>
</div>
{{end}}

<div class="stats">
  <div class="stat-card critical"><div class="count">{{.SeverityBreakdown.Critical}}</div><div class="label">Critical</div></div>
  <div class="stat-card high"><div class="count">{{.SeverityBreakdown.High}}</div><div class="label">High</div></div>
  <div class="stat-card medium"><div class="count">{{.SeverityBreakdown.Medium}}</div><div class="label">Medium</div></div>
  <div class="stat-card low"><div class="count">{{.SeverityBreakdown.Low}}</div><div class="label">Low</div></div>
  <div class="stat-card info"><div class="count">{{.SeverityBreakdown.Info}}</div><div class="label">Info</div></div>
</div>

<div class="chart-container">
  <h3 style="color: #f0f6fc; font-size: 1em; margin-bottom: 15px;">Severity Distribution</h3>
  <div class="chart-bar-row" data-count="{{.SeverityBreakdown.Critical}}" data-total="{{.TotalVulns}}"><div class="chart-label">Critical</div><div class="chart-bar-bg"><div class="chart-bar bar-critical" style="width: 0%;">{{.SeverityBreakdown.Critical}}</div></div></div>
  <div class="chart-bar-row" data-count="{{.SeverityBreakdown.High}}" data-total="{{.TotalVulns}}"><div class="chart-label">High</div><div class="chart-bar-bg"><div class="chart-bar bar-high" style="width: 0%;">{{.SeverityBreakdown.High}}</div></div></div>
  <div class="chart-bar-row" data-count="{{.SeverityBreakdown.Medium}}" data-total="{{.TotalVulns}}"><div class="chart-label">Medium</div><div class="chart-bar-bg"><div class="chart-bar bar-medium" style="width: 0%;">{{.SeverityBreakdown.Medium}}</div></div></div>
  <div class="chart-bar-row" data-count="{{.SeverityBreakdown.Low}}" data-total="{{.TotalVulns}}"><div class="chart-label">Low</div><div class="chart-bar-bg"><div class="chart-bar bar-low" style="width: 0%;">{{.SeverityBreakdown.Low}}</div></div></div>
  <div class="chart-bar-row" data-count="{{.SeverityBreakdown.Info}}" data-total="{{.TotalVulns}}"><div class="chart-label">Info</div><div class="chart-bar-bg"><div class="chart-bar bar-info" style="width: 0%;">{{.SeverityBreakdown.Info}}</div></div></div>
</div>

<div class="chart-container">
  <h3 style="color: #f0f6fc; font-size: 1em; margin-bottom: 15px;">OWASP Top 10:2025 Coverage</h3>
  <div class="owasp-grid">
    {{$total := .TotalVulns}}{{$owasp := .OWASPCounts}}
    {{range $cat := owaspCategories}}{{$count := index $owasp $cat}}
    <div class="owasp-bar-row"><div class="owasp-label">{{$cat}}</div><div class="owasp-bar-bg"><div class="owasp-bar" style="width: {{if gt $count 0}}{{percent $count $total}}{{else}}0%{{end}};">{{if gt $count 0}}{{$count}}{{end}}</div></div></div>
    {{end}}
  </div>
</div>

<!-- 2. Top Critical Findings -->
<h2><span class="section-num">2</span> Top Critical Findings</h2>
{{if .TopCritical}}
  {{range .TopCritical}}
  <div class="finding">
    <div class="finding-header open" onclick="toggleFinding(this)">
      <div>
        <span class="severity-badge severity-{{.Severity}}">{{.Severity}}</span>
        <span class="cvss-pill cvss-{{if ge .CVSS 7.0}}high{{else if ge .CVSS 4.0}}medium{{else}}low{{end}}">CVSS {{printf "%.1f" .CVSS}}</span>
      </div>
      <h3>{{.Title}}</h3>
      <span class="toggle-icon">&#9654;</span>
    </div>
    <div class="finding-body open">
      <div class="details">
        {{if .CVE}}<div><span class="label">CVE:</span> {{.CVE}}</div>{{end}}
        {{if .CWE}}<div><span class="label">CWE:</span> {{index .CWE 0}}</div>{{end}}
        {{if .OWASP2025}}<div><span class="label">OWASP:</span> {{.OWASP2025}}</div>{{end}}
        {{if .AffectedURL}}<div><span class="label">URL:</span> {{.AffectedURL}}</div>{{end}}
        {{if .AffectedParam}}<div><span class="label">Parameter:</span> {{.AffectedParam}}</div>{{end}}
        {{if .ToolSource}}<div><span class="label">Tool:</span> {{.ToolSource}}</div>{{end}}
        {{if .Description}}<div><span class="label">Description:</span> {{.Description}}</div>{{end}}
        {{if .Remediation}}<div><span class="label">Remediation:</span> {{.Remediation}}</div>{{end}}
      </div>
    </div>
  </div>
  {{end}}
{{else}}
  <p style="color: #8b949e;">No critical or high severity findings.</p>
{{end}}

<!-- 3. All Findings -->
<h2><span class="section-num">3</span> All Findings ({{.TotalVulns}})</h2>

<div class="tab-bar">
  <button class="tab-btn active" onclick="switchTab('card-view', this)">Card View</button>
  <button class="tab-btn" onclick="switchTab('table-view', this)">Table View</button>
</div>

<div id="card-view" class="tab-content active">
  {{range .Findings}}
  <div class="finding">
    <div class="finding-header" onclick="toggleFinding(this)">
      <div>
        <span class="severity-badge severity-{{.Severity}}">{{.Severity}}</span>
        <span class="cvss-pill cvss-{{if ge .CVSS 7.0}}high{{else if ge .CVSS 4.0}}medium{{else}}low{{end}}">CVSS {{printf "%.1f" .CVSS}}</span>
      </div>
      <h3>{{.Title}}</h3>
      <span class="toggle-icon">&#9654;</span>
    </div>
    <div class="finding-body">
      <div class="details">
        <div><span class="label">Tool:</span> {{.ToolSource}}</div>
        {{if .CVE}}<div><span class="label">CVE:</span> {{.CVE}}</div>{{end}}
        {{if .CWE}}<div><span class="label">CWE:</span> {{index .CWE 0}}</div>{{end}}
        {{if .OWASP2025}}<div><span class="label">OWASP:</span> {{.OWASP2025}}</div>{{end}}
        {{if .AffectedURL}}<div><span class="label">URL:</span> {{.AffectedURL}}</div>{{end}}
        {{if .AffectedParam}}<div><span class="label">Parameter:</span> {{.AffectedParam}}</div>{{end}}
        {{if .Description}}<div><span class="label">Description:</span> {{.Description}}</div>{{end}}
        {{if .Remediation}}<div><span class="label">Remediation:</span> {{.Remediation}}</div>{{end}}
      </div>
    </div>
  </div>
  {{end}}
</div>

<div id="table-view" class="tab-content">
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Title</th>
        <th>CVE</th>
        <th>CWE</th>
        <th>OWASP</th>
        <th>CVSS</th>
        <th>Tool</th>
      </tr>
    </thead>
    <tbody>
      {{range .Findings}}
      <tr>
        <td><span class="severity-badge severity-{{.Severity}}" style="font-size: 0.7em;">{{.Severity}}</span></td>
        <td>{{.Title}}</td>
        <td>{{if .CVE}}{{.CVE}}{{else}}&mdash;{{end}}</td>
        <td>{{if .CWE}}{{index .CWE 0}}{{else}}&mdash;{{end}}</td>
        <td>{{if .OWASP2025}}{{.OWASP2025}}{{else}}&mdash;{{end}}</td>
        <td><span class="cvss-pill cvss-{{if ge .CVSS 7.0}}high{{else if ge .CVSS 4.0}}medium{{else}}low{{end}}">{{printf "%.1f" .CVSS}}</span></td>
        <td>{{.ToolSource}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
</div>

<!-- Appendix A: Proofs & Payloads -->
<h2><span class="section-num">A</span> Appendix A: Proofs & Payloads</h2>
{{$hasProof := false}}
{{range .Findings}}{{if or .Proof .Payload}}{{$hasProof = true}}{{end}}{{end}}
{{if $hasProof}}
  {{range .Findings}}
    {{if or .Proof .Payload}}
    <div class="appendix">
      <h3>{{.Title}}</h3>
      {{if .AffectedURL}}<div style="color: #8b949e; margin-bottom: 10px;"><span class="label">URL:</span> {{.AffectedURL}}</div>{{end}}
      {{if .Proof}}<div class="proof-block"><div class="proof-label">Proof of Concept:</div>{{.Proof}}</div>{{end}}
      {{if .Payload}}<div class="proof-block"><div class="proof-label">Payload:</div><code>{{.Payload}}</code></div>{{end}}
    </div>
    {{end}}
  {{end}}
{{else}}
  <p style="color: #8b949e;">No proof-of-concept data or payloads recorded for any findings.</p>
{{end}}

<!-- Appendix B: Raw Tool Output -->
<h2><span class="section-num">B</span> Appendix B: Raw Tool Details</h2>
{{range .Findings}}
<div class="appendix">
  <h3>{{.Title}} <span style="color: #8b949e; font-weight: normal; font-size: 0.85em;">({{.ToolSource}})</span></h3>
  <div style="color: #8b949e;">
    <div><span class="label">ID:</span> {{.ID}}</div>
    <div><span class="label">Severity:</span> {{.Severity}} | <span class="label">CVSS:</span> {{printf "%.1f" .CVSS}}</div>
    <div><span class="label">CVE:</span> {{if .CVE}}{{.CVE}}{{else}}N/A{{end}} | <span class="label">CWE:</span> {{if .CWE}}{{.CWE}}{{else}}N/A{{end}}</div>
    <div><span class="label">OWASP:</span> {{if .OWASP2025}}{{.OWASP2025}}{{else}}Unmapped{{end}}</div>
    <div><span class="label">Affected URL:</span> {{if .AffectedURL}}{{.AffectedURL}}{{else}}N/A{{end}}</div>
    <div><span class="label">Parameter:</span> {{if .AffectedParam}}{{.AffectedParam}}{{else}}N/A{{end}}</div>
    <div><span class="label">Tool Source:</span> {{.ToolSource}}</div>
    <div><span class="label">Timestamp:</span> {{.Timestamp}}</div>
    <div><span class="label">Description:</span> {{.Description}}</div>
    <div><span class="label">Remediation:</span> {{if .Remediation}}{{.Remediation}}{{else}}Not specified{{end}}</div>
    {{if .CVSSVector}}<div><span class="label">CVSS Vector:</span> {{.CVSSVector}}</div>{{end}}
    {{if .EPSS}}<div><span class="label">EPSS:</span> {{printf "%.4f" .EPSS}}</div>{{end}}
    {{if .FalsePositive}}<div><span class="label">Status:</span> Marked as False Positive</div>{{end}}
  </div>
</div>
{{end}}

<div class="footer">
  Generated by <strong>OmniScan</strong> (EliTechWiz) on {{.GeneratedAt}} &mdash; Confidential Report<br>
  <span style="font-size: 0.85em;">Developer: <a href="https://github.com/Eliahhango">github.com/Eliahhango</a> &bull; OWASP Top 10:2025 &bull; CVSS 3.1 Scoring</span>
</div>

</div>

<script>
function toggleFinding(header) {
  header.classList.toggle('open');
  var body = header.nextElementSibling;
  if (body) body.classList.toggle('open');
}

function switchTab(tabId, btn) {
  document.querySelectorAll('.tab-content').forEach(function(el) { el.classList.remove('active'); });
  document.querySelectorAll('.tab-btn').forEach(function(el) { el.classList.remove('active'); });
  document.getElementById(tabId).classList.add('active');
  btn.classList.add('active');
}

// Calculate chart bar widths
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.chart-bar-row').forEach(function(row) {
    var count = parseInt(row.getAttribute('data-count')) || 0;
    var total = parseInt(row.getAttribute('data-total')) || 1;
    var pct = (count / total) * 100;
    if (pct < 2 && count > 0) pct = 2;
    row.querySelector('.chart-bar').style.width = pct.toFixed(0) + '%';
  });
});
</script>

</body>
</html>`
