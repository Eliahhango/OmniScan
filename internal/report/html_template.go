package report

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Assessment Report - {{.Target}}</title>
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
  h3 { color: #f0f6fc; font-size: 1.15em; margin-bottom: 10px; }
  h4 { color: #c9d1d9; font-size: 1em; margin: 15px 0 8px; }

  /* TOC */
  .toc { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px 30px; margin-bottom: 30px; }
  .toc h2 { margin-top: 0; }
  .toc ol { color: #c9d1d9; padding-left: 20px; }
  .toc li { margin: 6px 0; }
  .toc a { color: #58a6ff; text-decoration: none; }
  .toc a:hover { text-decoration: underline; }
  .toc .toc-sub { color: #8b949e; font-size: 0.9em; padding-left: 20px; list-style-type: circle; }

  /* Narrative sections */
  .narrative { color: #c9d1d9; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; line-height: 1.7; }
  .narrative p { margin-bottom: 12px; }
  .narrative strong { color: #f0f6fc; }
  .narrative ul { padding-left: 20px; margin-bottom: 12px; }
  .narrative li { margin: 4px 0; }

  /* Info cards */
  .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 15px; margin-bottom: 20px; }
  .info-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 20px; }
  .info-card .card-label { color: #8b949e; font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
  .info-card .card-value { color: #f0f6fc; font-size: 1em; font-weight: 600; }

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
  .finding { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
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
  .finding .impact-box { background: #0d1117; border-left: 3px solid #f85149; border-radius: 4px; padding: 12px 16px; margin: 10px 0; }
  .finding .impact-box.high-impact { border-left-color: #d29922; }
  .finding .impact-box.medium-impact { border-left-color: #58a6ff; }
  .finding .impact-box.low-impact { border-left-color: #3fb950; }
  .finding .impact-box .impact-label { color: #8b949e; font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
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

  /* Strengths / Recommendations */
  .strength-list { list-style: none; padding: 0; }
  .strength-list li { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px 18px; margin-bottom: 8px; display: flex; align-items: flex-start; gap: 10px; }
  .strength-list .icon { color: #3fb950; font-size: 1.1em; flex-shrink: 0; margin-top: 2px; }
  .rec-list { list-style: none; padding: 0; }
  .rec-list li { background: #161b22; border: 1px solid #30363d; border-left: 3px solid #58a6ff; border-radius: 8px; padding: 14px 18px; margin-bottom: 8px; }
  .rec-list .rec-num { display: inline-block; background: #1f6feb; color: #fff; width: 24px; height: 24px; border-radius: 12px; text-align: center; line-height: 24px; font-size: 0.8em; font-weight: 700; margin-right: 10px; flex-shrink: 0; }

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
    .stat-card, .finding, .appendix, .chart-container, .narrative, .toc, .strength-list li, .rec-list li, .info-card { border-color: #ddd; background: #f6f8fa; }
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

<!-- ============================================================ -->
<!-- Cover Page -->
<!-- ============================================================ -->
<div class="cover">
  <div class="badge">OmniScan v{{.Version}} &mdash; Security Assessment</div>
  <p style="color: #888; font-size: 0.85em; margin-top: 4px;">EliTechWiz / <a href="https://github.com/Eliahhango" style="color: #58a6ff;">github.com/Eliahhango</a></p>
  <h1>{{.Target}}</h1>
  <p class="subtitle">Comprehensive Vulnerability Assessment &mdash; OWASP Top 10:2025 Mapped</p>
  <div class="meta-box">
    <div><span>Scan Date:</span> {{.ScanDate}}</div>
    <div><span>Duration:</span> {{.Duration}}</div>
    <div><span>Total Vulnerabilities:</span> {{.TotalVulns}}</div>
    <div><span>Tools Used:</span> {{range $i, $t := .ToolsUsed}}{{if $i}}, {{end}}{{$t}}{{end}}</div>
    <div><span>Assessment Type:</span> External Vulnerability Assessment</div>
    <div><span>Classification:</span> Confidential</div>
  </div>
  {{if gt .TotalVulns 0}}
  <div class="risk-badge risk-{{.RiskLabel | lower}}">Overall Risk: {{.RiskLabel}} (Score: {{printf "%.0f" .RiskScore}})</div>
  {{else}}
  <div class="risk-badge risk-none">Overall Risk: None — No Vulnerabilities Found</div>
  {{end}}
  <div style="margin-top: 40px; color: #8b949e; font-size: 0.85em;">
    Generated {{.GeneratedAt}} &mdash; Confidential Document
  </div>
</div>

<!-- ============================================================ -->
<div class="container">

<!-- ============================================================ -->
<!-- Table of Contents -->
<!-- ============================================================ -->
<div class="toc no-print">
  <h2>Table of Contents</h2>
  <ol>
    <li><a href="#s-exec">Executive Summary</a></li>
    <li><a href="#s-scope">Scope &amp; Methodology</a></li>
    <li><a href="#s-summary">Findings Summary</a>
      <ul class="toc-sub">
        <li><a href="#s-stats">Severity Distribution</a></li>
        <li><a href="#s-owasp">OWASP Top 10:2025 Coverage</a></li>
      </ul>
    </li>
    <li><a href="#s-strengths">Observed Security Strengths</a></li>
    <li><a href="#s-critical">Top Critical Findings</a></li>
    <li><a href="#s-findings">Detailed Findings ({{.TotalVulns}})</a></li>
    <li><a href="#s-recs">Strategic Recommendations</a></li>
    <li><a href="#s-app-a">Appendix A: Proofs &amp; Payloads</a></li>
    <li><a href="#s-app-b">Appendix B: Raw Tool Details</a></li>
  </ol>
</div>

<!-- ============================================================ -->
<!-- 1. Executive Summary -->
<!-- ============================================================ -->
<h2 id="s-exec"><span class="section-num">1</span> Executive Summary</h2>

<div class="info-grid">
  <div class="info-card"><div class="card-label">Overall Risk</div><div class="card-value">{{.RiskLabel}}</div></div>
  <div class="info-card"><div class="card-label">Total Findings</div><div class="card-value">{{.TotalVulns}}</div></div>
  <div class="info-card"><div class="card-label">Avg CVSS Score</div><div class="card-value">{{printf "%.1f" .CVSSAvg}}</div></div>
  <div class="info-card"><div class="card-label">CWE Categories</div><div class="card-value">{{.CWECount}}</div></div>
  <div class="info-card"><div class="card-label">OWASP Coverage</div><div class="card-value">{{.OWASPCoverage}}/10</div></div>
  <div class="info-card"><div class="card-label">Duration</div><div class="card-value">{{.Duration}}</div></div>
</div>

<div class="narrative">
  <p>{{.ExecutiveSummary}}</p>
</div>

{{if gt .TotalVulns 0}}
<div class="chart-container">
  <h3 style="color: #f0f6fc; font-size: 1em; margin-bottom: 15px;">Severity Impact Reference</h3>
  <table>
    <tr><th>Severity</th><th>Impact</th><th>Remediation Timeline</th></tr>
    <tr><td><span class="severity-badge severity-critical">Critical</span></td><td>Immediate and severe threat. Could lead to full system compromise, data breach, or remote code execution.</td><td><strong>24 hours</strong></td></tr>
    <tr><td><span class="severity-badge severity-high">High</span></td><td>Significant security risk. Could lead to sensitive data exposure, privilege escalation, or service disruption.</td><td><strong>1 week</strong></td></tr>
    <tr><td><span class="severity-badge severity-medium">Medium</span></td><td>Moderate risk. Exploitable under specific conditions or combined with other vulnerabilities.</td><td><strong>1 month</strong></td></tr>
    <tr><td><span class="severity-badge severity-low">Low</span></td><td>Minor security concern. Limited impact or requires unlikely attack scenario.</td><td><strong>Next maintenance</strong></td></tr>
    <tr><td><span class="severity-badge severity-info">Info</span></td><td>Informational only. No direct security impact but useful for understanding the attack surface.</td><td><strong>Review</strong></td></tr>
  </table>
</div>
{{end}}

{{if eq .TotalVulns 0}}
<div class="chart-container" style="text-align: center; padding: 40px;">
  <h3 style="color: #3fb950; font-size: 1.3em; margin-bottom: 15px;">No Vulnerabilities Detected</h3>
  <p style="color: #8b949e;">The assessment completed successfully but no security vulnerabilities were found. This could indicate:</p>
  <ul style="color: #8b949e; text-align: left; display: inline-block; margin-top: 10px;">
    <li>The target is well-secured with no known vulnerabilities in the tested attack surface</li>
    <li>Not all scanning engines were available on the scanning system</li>
    <li>Additional authentication or configuration may be needed for deeper coverage</li>
  </ul>
  <p style="color: #8b949e; margin-top: 15px;"><strong>Recommendation:</strong> Run <code>omniscan setup</code> to install all tools and consider adding API keys or authenticated scan configuration for comprehensive coverage.</p>
</div>
{{end}}

<!-- ============================================================ -->
<!-- 2. Scope & Methodology -->
<!-- ============================================================ -->
<h2 id="s-scope"><span class="section-num">2</span> Scope &amp; Methodology</h2>

<div class="narrative">
  <h4>Scope</h4>
  <p>{{.Scope}}</p>

  <h4>Methodology</h4>
  <p>{{.Methodology}}</p>

  <h4>Standards &amp; Frameworks</h4>
  <ul>
    <li><strong>Vulnerability Scoring:</strong> CVSS v3.1 (Common Vulnerability Scoring System)</li>
    <li><strong>Vulnerability Classification:</strong> CWE (Common Weakness Enumeration)</li>
    <li><strong>Vulnerability Context:</strong> OWASP Top 10:2025 (Open Web Application Security Project)</li>
    <li><strong>Exploit Prediction:</strong> EPSS (Exploit Prediction Scoring System via FIRST.org)</li>
    <li><strong>CVE Mapping:</strong> National Vulnerability Database (NVD)</li>
  </ul>

  <h4>Assessment Activities</h4>
  <ul>
    <li>Network reconnaissance and port/service discovery</li>
    <li>Web application crawling and endpoint enumeration</li>
    <li>Vulnerability scanning using CVE template matching</li>
    <li>Web server misconfiguration and vulnerability assessment</li>
    <li>Directory and endpoint fuzzing</li>
    <li>Subdomain enumeration and HTTP service probing</li>
    <li>Static code analysis and secret detection</li>
    <li>Dependency and component vulnerability auditing</li>
  </ul>

  <h4>Tools Used</h4>
  <ul>
    {{range .ToolsUsed}}
    <li><strong>{{.}}</strong></li>
    {{end}}
  </ul>

  <h4>Limitations</h4>
  <ul>
    <li>This assessment was performed from an external perspective without authenticated access unless specified</li>
    <li>Findings reflect the security posture at the time of testing and may change as systems evolve</li>
    <li>Some vulnerabilities may require authenticated scanning or manual validation to confirm</li>
    <li>Not all available scanning engines may have been installed on the scanning system</li>
  </ul>
</div>

<!-- ============================================================ -->
<!-- 3. Findings Summary -->
<!-- ============================================================ -->
<h2 id="s-summary"><span class="section-num">3</span> Findings Summary</h2>

<div class="stats" id="s-stats">
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

<div class="chart-container" id="s-owasp">
  <h3 style="color: #f0f6fc; font-size: 1em; margin-bottom: 15px;">OWASP Top 10:2025 Coverage</h3>
  <p style="color: #8b949e; font-size: 0.85em; margin-bottom: 15px;">Findings mapped across {{.OWASPCoverage}} of 10 OWASP Top 10:2025 categories. Bar width represents proportion of total findings.</p>
  <div class="owasp-grid">
    {{$total := .TotalVulns}}{{$owasp := .OWASPCounts}}
    {{range $cat := owaspCategories}}{{$count := index $owasp $cat}}
    <div class="owasp-bar-row"><div class="owasp-label">{{$cat}}</div><div class="owasp-bar-bg"><div class="owasp-bar" style="width: {{if gt $count 0}}{{percent $count $total}}{{else}}0%{{end}};">{{if gt $count 0}}{{$count}}{{end}}</div></div></div>
    {{end}}
  </div>
</div>

<!-- ============================================================ -->
<!-- 4. Observed Security Strengths -->
<!-- ============================================================ -->
<h2 id="s-strengths"><span class="section-num">4</span> Observed Security Strengths</h2>

{{if .ObservedStrengths}}
<ul class="strength-list">
  {{range .ObservedStrengths}}
  <li><span class="icon">&#10003;</span> {{.}}</li>
  {{end}}
</ul>
{{else}}
<p style="color: #8b949e;">No specific security strengths were identified during this assessment.</p>
{{end}}

<!-- ============================================================ -->
<!-- 5. Top Critical Findings -->
<!-- ============================================================ -->
<h2 id="s-critical"><span class="section-num">5</span> Top Critical Findings</h2>

{{if .TopCritical}}
<p style="color: #8b949e; margin-bottom: 15px;">The following {{len .TopCritical}} findings represent the highest risk vulnerabilities identified during this assessment and should be prioritized for immediate remediation.</p>
<div class="filter-bar no-print">
  <button class="filter-btn active" onclick="filterTopFindings('all', this)">All</button>
  <button class="filter-btn" onclick="filterTopFindings('critical', this)">Critical</button>
  <button class="filter-btn" onclick="filterTopFindings('high', this)">High</button>
</div>
  {{range .TopCritical}}
  <div class="finding top-finding" data-severity="{{.Severity}}">
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
        {{if .CVE}}<div><span class="label">CVE:</span> <a href="https://nvd.nist.gov/vuln/detail/{{.CVE}}" style="color: #58a6ff;" target="_blank">{{.CVE}}</a></div>{{end}}
        {{if .CWE}}<div><span class="label">CWE:</span> {{index .CWE 0}}</div>{{end}}
        {{if .OWASP2025}}<div><span class="label">OWASP:</span> {{.OWASP2025}}</div>{{end}}
        {{if .AffectedURL}}<div><span class="label">Affected URL:</span> {{.AffectedURL}}</div>{{end}}
        {{if .AffectedParam}}<div><span class="label">Parameter:</span> {{.AffectedParam}}</div>{{end}}
        {{if .ToolSource}}<div><span class="label">Discovered By:</span> {{.ToolSource}}</div>{{end}}
        {{if .EPSS}}<div><span class="label">EPSS:</span> {{printf "%.4f" .EPSS}} ({{if ge .EPSS 0.5}}High{{else if ge .EPSS 0.1}}Medium{{else}}Low{{end}} exploit probability)</div>{{end}}
      </div>
      {{if .Description}}
      <div class="impact-box">
        <div class="impact-label">Description</div>
        {{.Description}}
      </div>
      {{end}}
      {{if .Remediation}}
      <div class="impact-box" style="border-left-color: #3fb950;">
        <div class="impact-label">Remediation</div>
        {{.Remediation}}
      </div>
      {{end}}
    </div>
  </div>
  {{end}}
{{else}}
<p style="color: #8b949e;">No critical or high severity findings were identified during this assessment.</p>
{{end}}

<!-- ============================================================ -->
<!-- 6. Detailed Findings -->
<!-- ============================================================ -->
<h2 id="s-findings"><span class="section-num">6</span> All Findings ({{.TotalVulns}})</h2>

<div class="tab-bar no-print">
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
        {{if .CVE}}<div><span class="label">CVE:</span> <a href="https://nvd.nist.gov/vuln/detail/{{.CVE}}" style="color: #58a6ff;" target="_blank">{{.CVE}}</a></div>{{end}}
        {{if .CWE}}<div><span class="label">CWE:</span> {{index .CWE 0}}</div>{{end}}
        {{if .OWASP2025}}<div><span class="label">OWASP:</span> {{.OWASP2025}}</div>{{end}}
        {{if .AffectedURL}}<div><span class="label">Affected URL:</span> {{.AffectedURL}}</div>{{end}}
        {{if .AffectedParam}}<div><span class="label">Parameter:</span> {{.AffectedParam}}</div>{{end}}
        {{if .ToolSource}}<div><span class="label">Discovered By:</span> {{.ToolSource}}</div>{{end}}
        {{if .CVSSVector}}<div><span class="label">CVSS Vector:</span> {{.CVSSVector}}</div>{{end}}
        {{if .EPSS}}<div><span class="label">EPSS:</span> {{printf "%.4f" .EPSS}}</div>{{end}}
      </div>
      {{if .Description}}
      <div class="impact-box">
        <div class="impact-label">Description &amp; Impact</div>
        {{.Description}}
      </div>
      {{end}}
      {{if .Remediation}}
      <div class="impact-box" style="border-left-color: #3fb950;">
        <div class="impact-label">Remediation Guidance</div>
        {{.Remediation}}
      </div>
      {{end}}
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
        <th>EPSS</th>
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
        <td>{{if gt .EPSS 0.0}}{{printf "%.2f" .EPSS}}{{else}}&mdash;{{end}}</td>
        <td>{{.ToolSource}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
</div>

<!-- ============================================================ -->
<!-- 7. Strategic Recommendations -->
<!-- ============================================================ -->
<h2 id="s-recs"><span class="section-num">7</span> Strategic Recommendations</h2>

{{if .StrategicRecommendations}}
<ol class="rec-list">
  {{range $i, $rec := .StrategicRecommendations}}
  <li><span class="rec-num">{{add $i 1}}</span> {{$rec}}</li>
  {{end}}
</ol>
{{else}}
<p style="color: #8b949e;">No specific recommendations at this time.</p>
{{end}}

<!-- ============================================================ -->
<!-- Appendix A: Proofs & Payloads -->
<!-- ============================================================ -->
<h2 id="s-app-a"><span class="section-num">A</span> Appendix A: Proofs &amp; Payloads</h2>
{{$hasProof := false}}
{{range .Findings}}{{if or .Proof .Payload}}{{$hasProof = true}}{{end}}{{end}}
{{if $hasProof}}
  {{range .Findings}}
    {{if or .Proof .Payload}}
    <div class="appendix">
      <h3>{{.Title}} <span style="color: #8b949e; font-weight: normal; font-size: 0.85em;">({{.ToolSource}})</span></h3>
      {{if .AffectedURL}}<div style="color: #8b949e; margin-bottom: 10px;"><span class="label">URL:</span> {{.AffectedURL}}</div>{{end}}
      {{if .Proof}}<div class="proof-block"><div class="proof-label">Proof of Concept:</div>{{.Proof}}</div>{{end}}
      {{if .Payload}}<div class="proof-block"><div class="proof-label">Payload:</div><code>{{.Payload}}</code></div>{{end}}
    </div>
    {{end}}
  {{end}}
{{else}}
<p style="color: #8b949e;">No proof-of-concept data or payloads were recorded for any findings in this assessment. Evidence collection is tool-dependent and may require manual capture.</p>
{{end}}

<!-- ============================================================ -->
<!-- Appendix B: Raw Tool Details -->
<!-- ============================================================ -->
<h2 id="s-app-b"><span class="section-num">B</span> Appendix B: Raw Tool Details</h2>
{{range .Findings}}
<div class="appendix">
  <h3>{{.Title}} <span style="color: #8b949e; font-weight: normal; font-size: 0.85em;">({{.ToolSource}})</span></h3>
  <div style="color: #8b949e;">
    <div><span class="label">Finding ID:</span> {{.ID}}</div>
    <div><span class="label">Severity:</span> {{.Severity}} &mdash; <span class="label">CVSS v3.1:</span> {{printf "%.1f" .CVSS}}</div>
    <div><span class="label">CVE:</span> {{if .CVE}}{{.CVE}}{{else}}N/A{{end}} &mdash; <span class="label">CWE:</span> {{if .CWE}}{{index .CWE 0}}{{else}}N/A{{end}}</div>
    <div><span class="label">OWASP Top 10:2025:</span> {{if .OWASP2025}}{{.OWASP2025}}{{else}}Unmapped{{end}}</div>
    <div><span class="label">EPSS Score:</span> {{if gt .EPSS 0.0}}{{printf "%.4f" .EPSS}}{{else}}Not available{{end}}</div>
    <div><span class="label">Affected URL:</span> {{if .AffectedURL}}{{.AffectedURL}}{{else}}N/A{{end}}</div>
    <div><span class="label">Parameter:</span> {{if .AffectedParam}}{{.AffectedParam}}{{else}}N/A{{end}}</div>
    <div><span class="label">Tool Source:</span> {{.ToolSource}}</div>
    <div><span class="label">Timestamp:</span> {{.Timestamp}}</div>
    {{if .CVSSVector}}<div><span class="label">CVSS Vector:</span> {{.CVSSVector}}</div>{{end}}
    {{if .FalsePositive}}<div><span class="label">Status:</span> Marked as False Positive</div>{{end}}
  </div>
  {{if .Description}}
  <div style="margin-top: 10px; padding: 10px; background: #0d1117; border-radius: 4px;">
    <div style="color: #8b949e; font-size: 0.85em; margin-bottom: 4px;">Description</div>
    <div style="color: #c9d1d9;">{{.Description}}</div>
  </div>
  {{end}}
  {{if .Remediation}}
  <div style="margin-top: 10px; padding: 10px; background: #0d1117; border-left: 3px solid #3fb950; border-radius: 4px;">
    <div style="color: #8b949e; font-size: 0.85em; margin-bottom: 4px;">Remediation</div>
    <div style="color: #c9d1d9;">{{.Remediation}}</div>
  </div>
  {{end}}
</div>
{{end}}

<!-- ============================================================ -->
<!-- Footer -->
<!-- ============================================================ -->
<div class="footer">
  Generated by <strong>OmniScan v{{.Version}}</strong> (EliTechWiz) on {{.GeneratedAt}} &mdash; Confidential Document<br>
  <span style="font-size: 0.85em;">Developer: <a href="https://github.com/Eliahhango" style="color: #58a6ff;">github.com/Eliahhango</a> &bull; OWASP Top 10:2025 &bull; CVSS v3.1 &bull; CWE &bull; EPSS</span>
  <div style="margin-top: 8px; font-size: 0.8em; color: #6e7681;">
    This document contains confidential and proprietary information. Unauthorized distribution or disclosure is prohibited.<br>
    Assessment conducted {{.ScanDate}}. Findings reflect the security posture at the time of testing and may change as systems evolve.
  </div>
</div>

</div>

<!-- ============================================================ -->
<!-- JavaScript -->
<!-- ============================================================ -->
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

function filterTopFindings(sev, btn) {
  document.querySelectorAll('.top-finding').forEach(function(el) {
    if (sev === 'all' || el.getAttribute('data-severity') === sev) {
      el.style.display = '';
    } else {
      el.style.display = 'none';
    }
  });
  document.querySelectorAll('.filter-btn').forEach(function(el) { el.classList.remove('active'); });
  btn.classList.add('active');
}

// Calculate chart bar widths on load
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
