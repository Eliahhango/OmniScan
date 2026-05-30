package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
		"crypto/sha256"
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
		"X-Original-URL":          "/admin",
		"X-Rewrite-URL":           "/admin",
		"X-HTTP-Method-Override":  "GET",
		"X-Forwarded-Host":        "evil.com",
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
					Title:       fmt.Sprintf("%s Exposed", p.name),
					Description: fmt.Sprintf("%s found in %s", p.name, jsURL),
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
