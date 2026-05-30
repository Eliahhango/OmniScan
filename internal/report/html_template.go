package report

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Assessment Report - {{.Target}}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background: #0d1117; color: #c9d1d9; padding: 40px 20px; line-height: 1.6; }
  .container { max-width: 1000px; margin: 0 auto; }
  h1 { color: #58a6ff; font-size: 2em; margin-bottom: 5px; }
  h2 { color: #f0f6fc; font-size: 1.5em; margin: 40px 0 15px; border-bottom: 2px solid #30363d; padding-bottom: 8px; }
  h3 { color: #f0f6fc; font-size: 1.15em; margin: 25px 0 10px; }
  h4 { color: #c9d1d9; font-size: 1em; margin: 15px 0 8px; }
  p { margin-bottom: 12px; }
  table { width: 100%; border-collapse: collapse; margin: 15px 0; }
  th, td { padding: 8px 12px; text-align: left; border: 1px solid #30363d; }
  th { background: #161b22; color: #58a6ff; font-weight: 600; }
  tr:nth-child(even) { background: #161b22; }
  tr:nth-child(odd) { background: #0d1117; }
  code { background: #21262d; padding: 2px 6px; border-radius: 4px; font-family: 'Fira Code', monospace; font-size: 0.9em; }
  pre { background: #21262d; padding: 16px; border-radius: 8px; overflow-x: auto; margin: 10px 0; }
  pre code { background: none; padding: 0; }
  blockquote { border-left: 3px solid #58a6ff; margin: 15px 0; padding: 10px 15px; background: #161b22; border-radius: 4px; }
  hr { border: none; border-top: 1px solid #30363d; margin: 30px 0; }
  .cover { text-align: center; padding: 60px 0; }
  .cover h1 { font-size: 2.5em; }
  .cover .meta { color: #8b949e; margin: 5px 0; }
  .risk-badge { display: inline-block; padding: 6px 20px; border-radius: 20px; font-weight: 700; }
  .risk-critical { background: #f8514933; color: #f85149; border: 2px solid #f85149; }
  .risk-high { background: #d2992233; color: #d29922; border: 2px solid #d29922; }
  .risk-medium { background: #58a6ff33; color: #58a6ff; border: 2px solid #58a6ff; }
  .risk-low { background: #3fb95033; color: #3fb950; border: 2px solid #3fb950; }
  .risk-none { background: #8b949e33; color: #8b949e; border: 2px solid #8b949e; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.75em; font-weight: 700; }
  .badge-critical { background: #f8514933; color: #f85149; border: 1px solid #f85149; }
  .badge-high { background: #d2992233; color: #d29922; border: 1px solid #d29922; }
  .badge-medium { background: #58a6ff33; color: #58a6ff; border: 1px solid #58a6ff; }
  .badge-low { background: #3fb95033; color: #3fb950; border: 1px solid #3fb950; }
  .badge-info { background: #8b949e33; color: #8b949e; border: 1px solid #8b949e; }
  .badge-active { background: #3fb95033; color: #3fb950; border: 1px solid #3fb950; }
  .badge-unavailable { background: #f8514933; color: #f85149; border: 1px solid #f85149; }
  .finding { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
  .finding h3 { margin-top: 0; }
  .warning { background: #d2992233; border-left: 3px solid #d29922; padding: 12px 16px; border-radius: 4px; margin: 15px 0; }
  .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }
  .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }
  .stat-card .count { font-size: 2.5em; font-weight: 700; }
  .stat-card .label { color: #8b949e; font-size: 0.85em; text-transform: uppercase; }
  .critical .count { color: #f85149; }
  .high .count { color: #d29922; }
  .medium .count { color: #58a6ff; }
  .low .count { color: #3fb950; }
  .info .count { color: #8b949e; }
  .footer { text-align: center; color: #8b949e; font-size: 0.85em; margin-top: 60px; padding-top: 20px; border-top: 1px solid #30363d; }
</style>
</head>
<body>
<div class="container">

<!-- COVER -->
<div class="cover">
  <h1>Vulnerability Assessment Report</h1>
  <p class="meta"><strong>Target:</strong> {{.Target}}</p>
  <p class="meta"><strong>Classification:</strong> CONFIDENTIAL — For Authorized Use Only</p>
  <p class="meta"><strong>Assessment Date:</strong> {{.ScanDate}}</p>
  <p class="meta"><strong>Prepared By:</strong> {{.PreparedBy}}</p>
  <p class="meta"><strong>Report Status:</strong> {{.ReportStatus}}</p>
  <p class="meta"><strong>Version:</strong> OmniScan {{.Version}}</p>
  <div style="margin-top:20px"><span class="risk-badge {{.RiskClass}}">{{.RiskLabel}}</span></div>
</div>

<!-- TOC -->
<h2>Table of Contents</h2>
<ol>
  <li><a href="#s1">Executive Summary</a></li>
  <li><a href="#s2">Scope &amp; Methodology</a></li>
  <li><a href="#s3">Risk Rating Matrix</a></li>
  <li><a href="#s4">Findings Overview</a></li>
  <li><a href="#s5">Detailed Findings</a></li>
  <li><a href="#s6">Attack Surface Analysis</a></li>
  <li><a href="#s7">Remediation Roadmap</a></li>
  <li><a href="#s8">Observed Strengths</a></li>
  <li><a href="#s9">Appendices</a></li>
</ol>

<!-- 1. EXECUTIVE SUMMARY -->
<h2 id="s1">1. Executive Summary</h2>

<h3>1.1 Assessment Overview</h3>
<p>{{.Scope}}</p>

{{if .CoverageWarning}}
<blockquote><strong>Note on Tool Coverage:</strong> {{.CoverageWarning}}</blockquote>
{{end}}

<h3>1.2 Risk Summary</h3>
<table>
  <tr><th>Metric</th><th>Value</th></tr>
  <tr><td><strong>Overall Risk Posture</strong></td><td>{{.RiskLabel}}</td></tr>
  <tr><td><strong>Total Findings</strong></td><td>{{.TotalVulns}}</td></tr>
  <tr><td><strong>Critical</strong></td><td>{{.SeverityBreakdown.Critical}}</td></tr>
  <tr><td><strong>High</strong></td><td>{{.SeverityBreakdown.High}}</td></tr>
  <tr><td><strong>Medium</strong></td><td>{{.SeverityBreakdown.Medium}}</td></tr>
  <tr><td><strong>Low</strong></td><td>{{.SeverityBreakdown.Low}}</td></tr>
  {{if gt .CVSSAvg 0.0}}<tr><td><strong>CVSS Average (scored)</strong></td><td>~{{printf "%.1f" .CVSSAvg}}</td></tr>{{end}}
  <tr><td><strong>Scan Coverage</strong></td><td>{{.EnginesActive}}/{{.EnginesTotal}} engines active</td></tr>
</table>

{{if .TopCritical}}
<h3>1.3 Key Findings</h3>
{{range .TopCritical}}
<div class="finding">
  <h3><span class="badge badge-{{severityClass .Severity}}">{{.Severity}}</span> {{.Title}}</h3>
  <p>{{.AffectedURL}}</p>
</div>
{{end}}
{{end}}

<h3>1.4 Business Impact Statement</h3>
<p>A web application collects user accounts, session data, and potentially payment information. The absence of security headers directly affects:</p>
<ul>
  <li><strong>User trust and data integrity</strong> — XSS and clickjacking attacks can steal session tokens or redirect users to phishing pages.</li>
  <li><strong>Regulatory exposure</strong> — Depending on jurisdiction, inadequate transport security may violate data protection obligations.</li>
  <li><strong>Reputational risk</strong> — Browser security warnings or a publicized incident can permanently damage a brand's credibility.</li>
</ul>
{{if gt .TotalVulns 0}}<p><strong>Remediation of all findings can be completed in under one hour</strong> through server configuration changes and requires no code changes.</p>{{end}}

<!-- 2. SCOPE & METHODOLOGY -->
<h2 id="s2">2. Scope &amp; Methodology</h2>

<h3>2.1 Target Scope</h3>
<table>
  <tr><th>Item</th><th>Details</th></tr>
  <tr><td><strong>Primary Domain</strong></td><td>{{.Target}}</td></tr>
  <tr><td><strong>Assessment Type</strong></td><td>External Black-Box</td></tr>
  <tr><td><strong>Authentication Tested</strong></td><td>None (unauthenticated only)</td></tr>
</table>

<h3>2.2 Methodology</h3>
<p>Testing followed a structured approach aligned to industry standards:</p>
<pre>Phase 1: Reconnaissance
  └─ DNS enumeration, IP resolution, port scanning, crawler mapping

Phase 2: Header &amp; Configuration Analysis
  └─ HTTP security header audit, TLS configuration review

Phase 3: Automated Scanning
  └─ Custom header checks, custom port scans
  {{if lt .EnginesActive .EnginesTotal}}└─ [Planned but unavailable]: Additional scanning engines{{end}}

Phase 4: Reporting
  └─ Finding classification (CVSS v3.1), remediation guidance, risk narrative</pre>

<h3>2.3 Standards Applied</h3>
<table>
  <tr><th>Standard</th><th>Purpose</th></tr>
  <tr><td>OWASP Top 10:2025</td><td>Web application vulnerability classification</td></tr>
  <tr><td>CVSS v3.1</td><td>Severity scoring</td></tr>
  <tr><td>CWE</td><td>Weakness categorization</td></tr>
  <tr><td>EPSS</td><td>Exploit likelihood scoring</td></tr>
</table>

{{if .CoverageWarning}}
<h3>2.4 Limitations</h3>
<ul>
  <li><strong>Incomplete tooling:</strong> Findings may be incomplete.</li>
  <li><strong>No authenticated testing:</strong> Vulnerabilities behind login pages were not assessed.</li>
  <li><strong>No source code access:</strong> Static analysis could not run due to tooling issues.</li>
  <li><strong>No secret scanning:</strong> Credential leaks in code/configs were not checked.</li>
</ul>
{{end}}

<!-- 3. RISK RATING MATRIX -->
<h2 id="s3">3. Risk Rating Matrix</h2>

<h3>3.1 CVSS Severity Reference</h3>
<table>
  <tr><th>Severity</th><th>CVSS v3.1 Range</th><th>Description</th></tr>
  <tr><td><strong>Critical</strong></td><td>9.0 – 10.0</td><td>Trivial exploitation; complete system compromise likely</td></tr>
  <tr><td><strong>High</strong></td><td>7.0 – 8.9</td><td>Significant impact; exploitation moderately to highly likely</td></tr>
  <tr><td><strong>Medium</strong></td><td>4.0 – 6.9</td><td>Notable risk; requires specific conditions or user interaction</td></tr>
  <tr><td><strong>Low</strong></td><td>0.1 – 3.9</td><td>Limited impact; typically requires chaining with other issues</td></tr>
  <tr><td><strong>Info</strong></td><td>0.0</td><td>Informational only; not a direct security risk</td></tr>
</table>

<h3>3.2 Exploitability vs. Impact Matrix</h3>
<pre>Impact  │ High   │  Med   │  Low
────────┼────────┼────────┼───────
High    │  CRIT  │  HIGH  │  MED
Med     │  HIGH  │  MED   │  LOW
Low     │  MED   │  LOW   │  INFO
────────┴────────┴────────┴───────
         High     Med      Low     ← Exploitability</pre>

<!-- 4. FINDINGS OVERVIEW -->
<h2 id="s4">4. Findings Overview</h2>

{{if gt .TotalVulns 0}}
<h3>4.1 Severity Breakdown</h3>
<div class="stats">
  <div class="stat-card critical"><div class="count">{{.SeverityBreakdown.Critical}}</div><div class="label">Critical</div></div>
  <div class="stat-card high"><div class="count">{{.SeverityBreakdown.High}}</div><div class="label">High</div></div>
  <div class="stat-card medium"><div class="count">{{.SeverityBreakdown.Medium}}</div><div class="label">Medium</div></div>
  <div class="stat-card low"><div class="count">{{.SeverityBreakdown.Low}}</div><div class="label">Low</div></div>
  <div class="stat-card info"><div class="count">{{.TotalVulns}}</div><div class="label">Total</div></div>
</div>

{{if .OWASPCounts}}
<h3>4.2 OWASP Top 10:2025 Mapping</h3>
<table>
  <tr><th>Finding</th><th>OWASP Category</th></tr>
  {{range .VulnFindings}}{{if .OWASP2025}}<tr><td>{{trimPrefix .Title "Missing "}}</td><td>{{.OWASP2025}}</td></tr>{{end}}{{end}}
</table>
{{else}}
<p>No OWASP categories were mapped in this assessment.</p>
{{end}}

{{if gt .CWECount 0}}
<h3>4.3 CWE Mapping</h3>
<table>
  <tr><th>Finding</th><th>CWE</th></tr>
  {{range .VulnFindings}}{{if .CWE}}<tr><td>{{trimPrefix .Title "Missing "}}</td><td>{{index .CWE 0}}</td></tr>{{end}}{{end}}
</table>
{{else}}
<p>No CWE mappings were established in this assessment.</p>
{{end}}
{{else}}
<p>No vulnerabilities were identified during this assessment.</p>
{{end}}

<!-- 5. DETAILED FINDINGS -->
{{if .VulnFindings}}
<h2 id="s5">5. Detailed Findings</h2>
{{range $i, $f := .VulnFindings}}
<div class="finding">
  <h3><span class="badge badge-{{severityClass $f.Severity}}">{{$f.Severity}}</span> Finding {{add $i 1}} — {{$f.Title}}</h3>
  <table>
    {{if $f.Severity}}<tr><td><strong>Severity</strong></td><td><span class="badge badge-{{severityClass $f.Severity}}">{{$f.Severity}}</span></td></tr>{{end}}
    {{if gt $f.CVSS 0.0}}<tr><td><strong>CVSS v3.1 Score</strong></td><td>{{printf "%.1f" $f.CVSS}}</td></tr>{{end}}
    {{if $f.CVSSVector}}<tr><td><strong>CVSS Vector</strong></td><td><code>{{$f.CVSSVector}}</code></td></tr>{{end}}
    {{if $f.CWE}}<tr><td><strong>CWE</strong></td><td>{{join $f.CWE ", "}}</td></tr>{{end}}
    {{if $f.OWASP2025}}<tr><td><strong>OWASP</strong></td><td>{{$f.OWASP2025}}</td></tr>{{end}}
    {{if $f.AffectedURL}}<tr><td><strong>Affected URL</strong></td><td><code>{{$f.AffectedURL}}</code></td></tr>{{end}}
    <tr><td><strong>Tool Source</strong></td><td>{{$f.ToolSource}}</td></tr>
    {{if $f.Verified}}<tr><td><strong>Verified</strong></td><td>Yes</td></tr>{{end}}
  </table>
  {{if $f.Description}}<p><strong>Description:</strong> {{$f.Description}}</p>{{end}}
  {{if $f.AttackScenario}}<p><strong>Attack Scenario:</strong> {{$f.AttackScenario}}</p>{{end}}
  {{if $f.Evidence}}<pre><code>{{$f.Evidence}}</code></pre>{{end}}
  {{if $f.Remediation}}<p><strong>Remediation:</strong> {{$f.Remediation}}</p>{{end}}
  {{if $f.Verified}}<p><strong>Verification:</strong> After deployment, check header presence at <a href="https://securityheaders.com">securityheaders.com</a>.</p>{{end}}
</div>
{{end}}
{{end}}

<!-- 6. ATTACK SURFACE ANALYSIS -->
<h2 id="s6">6. Attack Surface Analysis</h2>

<h3>6.1 Infrastructure Footprint</h3>
<table>
  <tr><th>Component</th><th>Details</th></tr>
  {{range .InfraFootprint}}<tr><td>{{.Component}}</td><td>{{.Details}}</td></tr>{{end}}
  <tr><td>DNS</td><td>Cloudflare nameservers</td></tr>
</table>

{{if .VulnFindings}}
<h3>6.2 Header Coverage Gap</h3>
<p>The site currently passes <strong>none</strong> of the seven tested security headers.</p>
<table>
  <tr><th>Header</th><th>Status</th><th>Risk If Exploited</th></tr>
  {{range .VulnFindings}}{{if eq .ToolSource "custom-headers"}}<tr><td>{{.Title}}</td><td><span class="badge badge-unavailable">MISSING</span></td><td>{{.Description}}</td></tr>{{end}}{{end}}
</table>
{{end}}

{{if .ChainedAttack}}
<h3>6.3 Chained Attack Scenario</h3>
<p>The combination of missing headers enables a realistic attack chain:</p>
<pre>{{.ChainedAttack}}</pre>
<p>Each missing header is a link in this chain. Fixing all seven breaks the chain at every step.</p>
{{end}}

<!-- 7. REMEDIATION ROADMAP -->
<h2 id="s7">7. Remediation Roadmap</h2>

{{if .RemediationPriority}}
<h3>7.1 Priority Matrix</h3>
<table>
  <tr><th>Priority</th><th>Findings</th><th>Target Timeline</th><th>Effort</th></tr>
  {{range .RemediationPriority}}<tr><td><strong>{{.Priority}}</strong></td><td>{{.Findings}}</td><td>{{.Timeline}}</td><td>{{.Effort}}</td></tr>{{end}}
</table>
{{end}}

{{if .OneFileFix}}
<h3>7.2 One-File Fix (Nginx Example)</h3>
<p>All headers can be added to a single server block or <code>.conf</code> include file:</p>
<pre><code>{{.OneFileFix}}</code></pre>
{{end}}

{{if .CloudflareOption}}
<h3>7.3 Cloudflare Transform Rules (Alternative)</h3>
<p>{{.CloudflareOption}}</p>
{{end}}

{{if .VerificationSteps}}
<h3>7.4 Verification Steps</h3>
<ol>
  {{range .VerificationSteps}}<li>{{.}}</li>{{end}}
</ol>
{{end}}

{{if .NextSteps}}
<h3>7.5 Recommended Next Steps (Beyond Headers)</h3>
<table>
  <tr><th>Action</th><th>Reason</th></tr>
  {{range .NextSteps}}<tr><td>{{.Action}}</td><td>{{.Reason}}</td></tr>{{end}}
</table>
{{end}}

<!-- 8. OBSERVED STRENGTHS -->
<h2 id="s8">8. Observed Strengths</h2>
<ol>
{{range .ObservedStrengths}}<li>{{.}}</li>{{end}}
</ol>

<!-- 9. APPENDICES -->
<h2 id="s9">9. Appendices</h2>

<h3>Appendix A — DNS Records</h3>
<table>
  <tr><th>Record Type</th><th>Value</th></tr>
  {{range .DNSRecords}}<tr><td>{{.Type}}</td><td>{{.Value}}</td></tr>{{end}}
</table>

{{if .DiscoveredURLs}}
<h3>Appendix B — Discovered URLs</h3>
<table>
  <tr><th>URL</th><th>Discovered By</th></tr>
  {{range .DiscoveredURLs}}<tr><td><code>{{.URL}}</code></td><td>{{.FoundBy}}</td></tr>{{end}}
</table>
{{end}}

{{if .EngineStatus}}
<h3>Appendix C — Scanning Engine Status</h3>
<table>
  <tr><th>Engine</th><th>Status</th><th>Notes</th></tr>
  {{range .EngineStatus}}<tr>
    <td>{{.Name}}</td>
    <td>{{if eq .Status "Active"}}<span class="badge badge-active">Active</span>{{else}}<span class="badge badge-unavailable">Not Available</span>{{end}}</td>
    <td>{{.Notes}}</td>
  </tr>{{end}}
</table>
{{if .CoverageWarning}}
<div class="warning"><strong>Coverage Warning:</strong> {{.CoverageWarning}}</div>
{{end}}
{{end}}

{{if .Glossary}}
<h3>Appendix D — Glossary</h3>
<table>
  <tr><th>Term</th><th>Definition</th></tr>
  {{range .Glossary}}<tr><td><strong>{{.Term}}</strong></td><td>{{.Definition}}</td></tr>{{end}}
</table>
{{end}}

<!-- FOOTER -->
<div class="footer">
  <p>Report generated by OmniScan {{.Version}}</p>
  <p>Assessment conducted on {{.ScanDate}}</p>
  <p>Unauthorized distribution is prohibited.</p>
  <p>Powered by OmniScan — <a href="https://github.com/Eliahhango/OmniScan">github.com/Eliahhango/OmniScan</a></p>
</div>

</div>
</body>
</html>`
