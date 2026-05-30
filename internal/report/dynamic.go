package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

type reportContext struct {
	hostname            string
	target              string
	hostIP              string
	dnsServers          []string
	txtRecords          []string
	txtStr              string
	vulns               []types.Finding
	info                []types.Finding
	findingCategories   map[string]int
	data                *ReportData
	isCloudflare        bool
	portSet             map[int]bool
	techNames           []string
	isHeaderMissing     func(string) bool
}

func buildReportContext(target string, vulns, info []types.Finding, data *ReportData, hostIP string, dnsServers, txtRecords []string, txtStr string, portSet map[int]bool, techNames []string) *reportContext {
	ctx := &reportContext{
		target:    target,
		vulns:     vulns,
		info:      info,
		data:      data,
		hostIP:    hostIP,
		dnsServers: dnsServers,
		txtRecords: txtRecords,
		txtStr:    txtStr,
		portSet:   portSet,
		techNames: techNames,
	}

	ctx.hostname = strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	ctx.hostname = strings.Split(ctx.hostname, "/")[0]

	ctx.isHeaderMissing = func(headerName string) bool {
		for _, f := range vulns {
			if f.ToolSource == "custom-headers" && strings.Contains(strings.ToLower(f.Title), strings.ToLower(headerName)) {
				return true
			}
		}
		return false
	}

	ctx.findingCategories = make(map[string]int)
	for _, f := range vulns {
		cat := categorizeFinding(f)
		ctx.findingCategories[cat]++
	}

	for _, dns := range dnsServers {
		if strings.Contains(strings.ToLower(dns), "cloudflare") {
			ctx.isCloudflare = true
			break
		}
	}

	return ctx
}

func categorizeFinding(f types.Finding) string {
	switch f.ToolSource {
	case "custom-headers":
		return "Security Headers"
	case "custom-jssecrets":
		return "Exposed Secrets"
	case "custom-sqli":
		return "SQL Injection"
	case "custom-xss":
		return "Cross-Site Scripting"
	case "custom-ssrf":
		return "Server-Side Request Forgery"
	case "custom-csrf":
		return "Cross-Site Request Forgery"
	case "custom-xxe":
		return "XML External Entity"
	case "custom-cmd-injection":
		return "Command Injection"
	case "custom-path-traversal":
		return "Path Traversal"
	case "custom-open-redirect":
		return "Open Redirect"
	case "custom-http-smuggling":
		return "HTTP Request Smuggling"
	case "custom-deserialization":
		return "Insecure Deserialization"
	case "custom-cors":
		return "CORS Misconfiguration"
	case "custom-ssti":
		return "Server-Side Template Injection"
	case "custom-git":
		return "Git Configuration Exposure"
	case "custom-s3":
		return "Cloud Storage Exposure"
	case "custom-subdomain-takeover":
		return "Subdomain Takeover"
	case "custom-idor":
		return "Insecure Direct Object Reference"
	case "custom-ratelimit", "custom-rate-limiting":
		return "Rate Limiting"
	case "custom-jwt":
		return "JWT Attacks"
	case "custom-error-disc":
		return "Error Disclosure"
	default:
		return strings.Title(strings.ReplaceAll(strings.TrimPrefix(f.ToolSource, "custom-"), "-", " "))
	}
}

func buildDynamicExecutiveSummary(ctx *reportContext) string {
	totalVulnCount := len(ctx.vulns)
	critCount := ctx.data.SeverityBreakdown.Critical
	highCount := ctx.data.SeverityBreakdown.High
	medCount := ctx.data.SeverityBreakdown.Medium
	lowCount := ctx.data.SeverityBreakdown.Low

	parts := []string{
		fmt.Sprintf("The assessment discovered %d security issues spanning %d distinct vulnerability categories. ", totalVulnCount, len(ctx.findingCategories)),
	}
	if critCount > 0 {
		parts = append(parts, fmt.Sprintf("%d findings are Critical severity, representing an immediate risk. ", critCount))
	}
	if highCount > 0 {
		parts = append(parts, fmt.Sprintf("%d High-severity issues could lead to significant data exposure or system compromise. ", highCount))
	}
	if medCount > 0 {
		parts = append(parts, fmt.Sprintf("%d Medium-severity findings require scheduled remediation. ", medCount))
	}
	if lowCount > 0 {
		parts = append(parts, fmt.Sprintf("%d Low-severity observations noted for completeness. ", lowCount))
	}
	if len(ctx.findingCategories) > 0 {
		cats := make([]string, 0, len(ctx.findingCategories))
		for cat := range ctx.findingCategories {
			cats = append(cats, cat)
		}
		sort.Strings(cats)
		if len(cats) > 3 {
			parts = append(parts, fmt.Sprintf("Categories include: %s. ", strings.Join(cats[:len(cats)-1], ", ")+", and "+cats[len(cats)-1]))
		} else if len(cats) > 0 {
			parts = append(parts, fmt.Sprintf("Categories include: %s. ", strings.Join(cats, " and ")))
		}
	}

	return strings.Join(parts, "")
}

func buildDynamicBusinessImpact(ctx *reportContext) []string {
	var impacts []string
	if ctx.isHeaderMissing("HSTS") || ctx.isHeaderMissing("Strict-Transport-Security") {
		impacts = append(impacts, fmt.Sprintf("%s lacks HSTS enforcement, allowing unencrypted connections that can be intercepted by network attackers to steal credentials or inject malicious content.", ctx.hostname))
	}
	if ctx.isHeaderMissing("Content-Security-Policy") || ctx.isHeaderMissing("CSP") {
		impacts = append(impacts, "Without a Content Security Policy, the site cannot restrict which scripts execute in users' browsers — any injected JavaScript runs with full access to the application's data and functionality.")
	}
	if ctx.isHeaderMissing("X-Frame-Options") {
		impacts = append(impacts, "Missing clickjacking protection means attackers can overlay the site with invisible UI elements, tricking authenticated users into performing unintended actions.")
	}
	if ctx.findingCategories["Exposed Secrets"] > 0 {
		impacts = append(impacts, "Exposed API keys and credentials were detected in client-side JavaScript — these secrets can be used to access backend services, databases, and third-party APIs, potentially exposing customer data or incurring financial charges.")
	}
	if ctx.findingCategories["SQL Injection"] > 0 {
		impacts = append(impacts, "SQL injection vulnerabilities allow attackers to extract, modify, or destroy database contents — potentially accessing user credentials, personal information, or business-critical data.")
	}
	if ctx.findingCategories["Cross-Site Scripting"] > 0 {
		impacts = append(impacts, "Cross-site scripting vulnerabilities enable attackers to execute arbitrary JavaScript in victims' browsers, leading to session hijacking, credential theft, or full account compromise.")
	}
	if ctx.findingCategories["Command Injection"] > 0 {
		impacts = append(impacts, "Command injection vulnerabilities grant attackers arbitrary code execution on the server, enabling complete system compromise and lateral movement within the network.")
	}
	if ctx.findingCategories["Server-Side Request Forgery"] > 0 {
		impacts = append(impacts, "SSRF vulnerabilities expose internal services and cloud metadata to external attackers, potentially leading to IAM credential theft and full cloud account takeover.")
	}
	if len(impacts) == 0 {
		impacts = append(impacts, fmt.Sprintf("While no high-severity exploitable issues were found, %s should be continuously monitored as new attack techniques and vulnerabilities emerge.", ctx.hostname))
	}
	return impacts
}

func buildDynamicChainedAttack(ctx *reportContext) string {
	var steps []string
	if ctx.isHeaderMissing("HSTS") || ctx.isHeaderMissing("Strict-Transport-Security") {
		steps = append(steps, fmt.Sprintf("1. Attacker on the same network performs ARP spoofing to intercept traffic to %s", ctx.hostname))
	}
	if ctx.isHeaderMissing("Content-Security-Policy") || ctx.isHeaderMissing("CSP") {
		steps = append(steps, "2. Without CSP restrictions, the attacker injects a malicious script that loads an external keylogger")
	}
	if ctx.isHeaderMissing("X-Frame-Options") {
		steps = append(steps, "3. The site can be embedded in an invisible iframe — victim's clicks go to attacker's hidden form fields")
	}
	if ctx.isHeaderMissing("Referrer-Policy") || ctx.isHeaderMissing("Referrer Policy") {
		steps = append(steps, "4. When navigation occurs, the full URL with session tokens is leaked via the Referer header to third-party sites")
	}
	if ctx.isHeaderMissing("X-Content-Type-Options") {
		steps = append(steps, "5. Uploaded files masquerading as images are interpreted as executable scripts due to MIME type sniffing")
	}
	if ctx.isHeaderMissing("Permissions-Policy") {
		steps = append(steps, "6. The browser's microphone, camera, and geolocation APIs are accessible to any script in the page context")
	}
	if len(steps) == 0 {
		steps = append(steps, "No header-level attack chain was identified. Review detailed findings for application-layer attack chains.")
	}
	if len(steps) > 0 {
		steps = append(steps, fmt.Sprintf("Result: Full account compromise of any %s user who browses from an untrusted network.", ctx.hostname))
	}
	return strings.Join(steps, "\n")
}

func buildDynamicRemediationPriority(ctx *reportContext) []RemediationEntry {
	var remediations []RemediationEntry
	if ctx.findingCategories["Exposed Secrets"] > 0 {
		remediations = append(remediations, RemediationEntry{"P1 — Critical", "Rotate exposed secrets", "Within 24 hours", "~30 min"})
	}
	if ctx.findingCategories["SQL Injection"] > 0 {
		remediations = append(remediations, RemediationEntry{"P1 — Critical", "Parameterize all SQL queries", "Within 24 hours", "~4 hours"})
	}
	if ctx.findingCategories["Command Injection"] > 0 {
		remediations = append(remediations, RemediationEntry{"P1 — Critical", "Remove shell exec from user input paths", "Within 24 hours", "~2 hours"})
	}
	if ctx.findingCategories["Cross-Site Scripting"] > 0 {
		remediations = append(remediations, RemediationEntry{"P2 — High", "Implement output encoding + CSP", "Within 1 week", "~8 hours"})
	}
	if (ctx.isHeaderMissing("CSP") || ctx.isHeaderMissing("Content-Security-Policy")) && (ctx.isHeaderMissing("HSTS") || ctx.isHeaderMissing("Strict-Transport-Security")) {
		remediations = append(remediations, RemediationEntry{"P2 — High", "CSP + HSTS deployment", "Within 48 hours", "~30 min"})
	}
	if ctx.findingCategories["Cross-Site Request Forgery"] > 0 {
		remediations = append(remediations, RemediationEntry{"P2 — High", "Implement CSRF tokens", "Within 1 week", "~4 hours"})
	}
	if ctx.findingCategories["CORS Misconfiguration"] > 0 {
		remediations = append(remediations, RemediationEntry{"P2 — High", "Restrict CORS to trusted origins", "Within 1 week", "~1 hour"})
	}
	if ctx.findingCategories["Server-Side Request Forgery"] > 0 {
		remediations = append(remediations, RemediationEntry{"P1 — Critical", "SSRF hardening (URL allowlist)", "Within 24 hours", "~2 hours"})
	}
	if len(remediations) == 0 {
		remediations = append(remediations, RemediationEntry{"P3 — Routine", "Address all identified findings", "Next maintenance window", "Varies"})
	}
	return remediations
}

func buildDynamicOneFileFix(ctx *reportContext) string {
	var lines []string
	if ctx.isHeaderMissing("Content-Security-Policy") || ctx.isHeaderMissing("CSP") {
		lines = append(lines, `add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';" always;`)
	}
	if ctx.isHeaderMissing("HSTS") || ctx.isHeaderMissing("Strict-Transport-Security") {
		lines = append(lines, `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`)
	}
	if ctx.isHeaderMissing("X-Content-Type-Options") {
		lines = append(lines, `add_header X-Content-Type-Options "nosniff" always;`)
	}
	if ctx.isHeaderMissing("X-Frame-Options") {
		lines = append(lines, `add_header X-Frame-Options "SAMEORIGIN" always;`)
	}
	if ctx.isHeaderMissing("Referrer-Policy") || ctx.isHeaderMissing("Referrer Policy") {
		lines = append(lines, `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`)
	}
	if ctx.isHeaderMissing("Permissions-Policy") {
		lines = append(lines, `add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;`)
	}
	if ctx.isHeaderMissing("X-XSS-Protection") {
		lines = append(lines, `add_header X-XSS-Protection "1; mode=block" always;`)
	}
	return strings.Join(lines, "\n")
}

func buildCloudflareOption(ctx *reportContext) string {
	if ctx.isCloudflare && (ctx.isHeaderMissing("HSTS") || ctx.isHeaderMissing("CSP") || ctx.isHeaderMissing("Content-Security-Policy") || ctx.isHeaderMissing("Strict-Transport-Security")) {
		return fmt.Sprintf("Since %s uses Cloudflare, all security headers can be configured via Cloudflare Dashboard → Rules → Transform Rules → Modify Response Header. This deploys headers at the edge without requiring origin server changes. Documentation: https://developers.cloudflare.com/rules/transform/response-headers/", ctx.hostname)
	}
	if ctx.isCloudflare {
		return fmt.Sprintf("%s uses Cloudflare CDN. Transform Rules can apply security policies at the edge. Consider enabling Cloudflare's Managed Ruleset for additional WAF protection.", ctx.hostname)
	}
	return ""
}

func buildDynamicVerificationSteps(ctx *reportContext) []string {
	var steps []string
	hasHeaders := ctx.isHeaderMissing("HSTS") || ctx.isHeaderMissing("CSP") || ctx.isHeaderMissing("Content-Security-Policy") || ctx.isHeaderMissing("Strict-Transport-Security") || ctx.isHeaderMissing("X-Frame-Options")
	if hasHeaders {
		steps = append(steps, fmt.Sprintf("1. After applying headers, test at https://securityheaders.com/?q=%s — confirm grade A or A+", ctx.hostname))
		steps = append(steps, fmt.Sprintf("2. Verify via: curl -I https://%s | grep -iE 'content-security|strict-transport|x-frame|x-content|referrer-policy|permissions-policy|x-xss'", ctx.hostname))
	}
	if ctx.findingCategories["Exposed Secrets"] > 0 {
		steps = append(steps, "3. After rotating keys, verify old keys are revoked in the respective service consoles (Google Cloud Console, AWS IAM, GitHub Settings)")
		steps = append(steps, "4. Rescan with OmniScan to confirm zero secret findings")
	}
	if ctx.findingCategories["SQL Injection"] > 0 || ctx.findingCategories["Cross-Site Scripting"] > 0 {
		steps = append(steps, "5. After parameterizing queries and encoding output, retest each affected endpoint with the same payloads to confirm sanitization")
	}
	if ctx.portSet[443] {
		steps = append(steps, fmt.Sprintf("6. Test SSL/TLS at https://www.ssllabs.com/ssltest/analyze.html?d=%s", ctx.hostname))
	}
	if len(steps) == 0 {
		steps = append(steps, "Re-run OmniScan after applying fixes to verify all findings have been resolved.")
	}
	return steps
}

func buildDynamicNextSteps(ctx *reportContext) []NextStepEntry {
	var steps []NextStepEntry
	if ctx.data.EnginesActive < ctx.data.EnginesTotal {
		steps = append(steps, NextStepEntry{fmt.Sprintf("Re-run with full tooling (%d/%d engines active)", ctx.data.EnginesActive, ctx.data.EnginesTotal), fmt.Sprintf("Only %d of %d engines were available — additional findings likely with complete coverage", ctx.data.EnginesActive, ctx.data.EnginesTotal)})
	}
	steps = append(steps, NextStepEntry{"Authenticated application scan", "Login-protected areas were not tested — these often contain the most critical vulnerabilities"})
	if ctx.findingCategories["Exposed Secrets"] == 0 {
		steps = append(steps, NextStepEntry{"Secret scanning on source repositories", "Scan repos for hardcoded credentials, API keys, and tokens committed to version control"})
	}
	steps = append(steps, NextStepEntry{"Dependency vulnerability audit", "Check npm/pip/composer/gem dependencies against known CVE databases"})
	if len(ctx.techNames) > 0 {
		steps = append(steps, NextStepEntry{fmt.Sprintf("Targeted %s security assessment", ctx.techNames[0]), fmt.Sprintf("%s detected as primary stack — version-specific assessment recommended", ctx.techNames[0])})
	}
	return steps
}

func buildDynamicStrengths(ctx *reportContext) []string {
	var strengths []string
	switch {
	case ctx.isCloudflare:
		strengths = append(strengths, fmt.Sprintf("Cloudflare CDN/proxy detected — %s benefits from built-in DDoS mitigation, global CDN caching, and a platform for rapid security policy deployment.", ctx.hostname))
	case len(ctx.dnsServers) > 0 && ctx.dnsServers[0] != "" && !strings.Contains(strings.ToLower(ctx.dnsServers[0]), "unknown"):
		strengths = append(strengths, fmt.Sprintf("Third-party DNS management detected — DNS configuration is centralized and manageable through provider infrastructure (%s).", ctx.dnsServers[0]))
	}
	if ctx.portSet[443] {
		strengths = append(strengths, "HTTPS is properly enabled on port 443 — all traffic can be encrypted in transit, establishing the foundation for secure communications.")
	}
	hasSensitive := false
	for port := range ctx.portSet {
		if port == 22 || port == 3306 || port == 3389 || port == 5432 || port == 1433 {
			hasSensitive = true
			break
		}
	}
	if !hasSensitive && len(ctx.portSet) > 0 {
		strengths = append(strengths, "No sensitive management ports are exposed to the public internet — minimizing the external attack surface.")
	}
	if ctx.txtStr != "" && strings.Contains(strings.ToLower(ctx.txtStr), "google-site-verification") {
		strengths = append(strengths, fmt.Sprintf("Google Search Console verification is configured for %s, indicating active site ownership management.", ctx.hostname))
	}
	presentHeaders := 0
	for _, f := range ctx.info {
		if f.ToolSource == "custom-headers" && strings.Contains(strings.ToLower(f.Title), "summary") {
			fmt.Sscanf(f.Description, "%d", &presentHeaders)
		}
	}
	if presentHeaders > 0 {
		if presentHeaders >= 5 {
			strengths = append(strengths, fmt.Sprintf("Strong security header posture: %d of 7 critical headers are already deployed, demonstrating security awareness.", presentHeaders))
		} else if presentHeaders >= 3 {
			strengths = append(strengths, fmt.Sprintf("Partial security header deployment: %d of 7 headers in place. Remaining headers can be added with minimal effort.", presentHeaders))
		} else {
			strengths = append(strengths, fmt.Sprintf("%d security headers present, providing a foundation to build upon.", presentHeaders))
		}
	}
	if ctx.findingCategories["Exposed Secrets"] > 0 && ctx.findingCategories["Exposed Secrets"] <= 2 {
		strengths = append(strengths, fmt.Sprintf("Limited secret exposure: only %d type(s) detected. The low count suggests most secrets are properly managed server-side.", ctx.findingCategories["Exposed Secrets"]))
	}
	if ctx.data.SeverityBreakdown.Critical == 0 && ctx.data.SeverityBreakdown.High == 0 {
		strengths = append(strengths, "No Critical or High severity vulnerabilities identified, suggesting a generally sound security baseline.")
	}
	if len(strengths) == 0 {
		strengths = append(strengths, "The site is accessible and operational. A baseline security posture has been established for ongoing monitoring.")
	}
	return strengths
}

func buildDynamicGlossary(ctx *reportContext) []GlossaryEntry {
	var glossary []GlossaryEntry
	if ctx.isHeaderMissing("CSP") || ctx.isHeaderMissing("Content-Security-Policy") {
		glossary = append(glossary, GlossaryEntry{"CSP", "Content Security Policy — HTTP header controlling which resources a browser may load and execute"})
	}
	if ctx.isHeaderMissing("HSTS") || ctx.isHeaderMissing("Strict-Transport-Security") {
		glossary = append(glossary, GlossaryEntry{"HSTS", "HTTP Strict Transport Security — forces browsers to use HTTPS for all future connections"})
	}
	if ctx.findingCategories["Cross-Site Scripting"] > 0 {
		glossary = append(glossary, GlossaryEntry{"XSS", "Cross-Site Scripting — injection of malicious scripts into trusted web pages"})
	}
	if ctx.isHeaderMissing("X-Frame-Options") {
		glossary = append(glossary, GlossaryEntry{"Clickjacking", "UI redress attack — tricking users into clicking hidden elements via transparent iframes"})
	}
	if ctx.isHeaderMissing("HSTS") || ctx.isHeaderMissing("Strict-Transport-Security") {
		glossary = append(glossary, GlossaryEntry{"MITM", "Man-in-the-Middle attack — intercepting and modifying communications without knowledge"})
	}
	if ctx.isHeaderMissing("X-Content-Type-Options") {
		glossary = append(glossary, GlossaryEntry{"MIME Sniffing", "Browser behavior guessing content type by inspecting file bytes"})
	}
	if ctx.data.CVSSAvg > 0 {
		glossary = append(glossary, GlossaryEntry{"CVSS", "Common Vulnerability Scoring System — industry-standard 0-10 severity scoring"})
	}
	if ctx.data.CWECount > 0 {
		glossary = append(glossary, GlossaryEntry{"CWE", "Common Weakness Enumeration — catalog of software weakness types"})
	}
	if ctx.data.OWASPCoverage > 0 {
		glossary = append(glossary, GlossaryEntry{"OWASP", "Open Web Application Security Project — maintainer of the OWASP Top 10"})
	}
	if ctx.findingCategories["Server-Side Request Forgery"] > 0 {
		glossary = append(glossary, GlossaryEntry{"SSRF", "Server-Side Request Forgery — exploiting server URL fetching to access internal resources"})
	}
	if ctx.findingCategories["SQL Injection"] > 0 {
		glossary = append(glossary, GlossaryEntry{"SQLi", "SQL Injection — inserting malicious SQL statements into application queries"})
	}
	if ctx.findingCategories["Command Injection"] > 0 {
		glossary = append(glossary, GlossaryEntry{"Command Injection", "OS command execution through unsanitized user input"})
	}
	if ctx.findingCategories["Cross-Site Request Forgery"] > 0 {
		glossary = append(glossary, GlossaryEntry{"CSRF", "Cross-Site Request Forgery — forcing authenticated users to execute unwanted actions"})
	}
	if ctx.findingCategories["XML External Entity"] > 0 {
		glossary = append(glossary, GlossaryEntry{"XXE", "XML External Entity — processing external entities in XML parsers"})
	}
	if ctx.findingCategories["HTTP Request Smuggling"] > 0 {
		glossary = append(glossary, GlossaryEntry{"HTTP Smuggling", "Exploiting HTTP parsing discrepancies between front-end and back-end servers"})
	}
	if ctx.findingCategories["Exposed Secrets"] > 0 {
		glossary = append(glossary, GlossaryEntry{"Secret Exposure", "Credentials/API keys inadvertently included in client-side code"})
	}
	if ctx.findingCategories["CORS Misconfiguration"] > 0 {
		glossary = append(glossary, GlossaryEntry{"CORS", "Cross-Origin Resource Sharing — browser mechanism for cross-origin access"})
	}
	if ctx.findingCategories["Insecure Deserialization"] > 0 {
		glossary = append(glossary, GlossaryEntry{"Deserialization", "Reconstructing objects from serialized data — unsafe deserialization enables RCE"})
	}
	if ctx.findingCategories["JWT Attacks"] > 0 {
		glossary = append(glossary, GlossaryEntry{"JWT", "JSON Web Token — misconfigurations allow signature bypass or algorithm confusion"})
	}
	return glossary
}
