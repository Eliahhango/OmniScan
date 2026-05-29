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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

type CustomScanner struct {
	Target  string
	Results chan<- types.Finding
}

func NewCustomScanner(target string) *CustomScanner {
	return &CustomScanner{Target: target}
}

func (cs *CustomScanner) Run(ctx context.Context) {
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
}

func checkIDOR(target string) ([]types.Finding, error) {
	var findings []types.Finding
	client := &http.Client{Timeout: 10 * time.Second}

	endpoints := []string{
		"/api/users/1", "/api/users/2", "/api/users/3",
		"/api/profile/1", "/api/account/1",
		"/api/v1/users/1", "/api/v2/users/1",
		"/api/admin/users/1",
	}

	for _, ep := range endpoints {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), ep)
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

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
			resp, err := client.Get(u)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

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

	client := &http.Client{Timeout: 10 * time.Second}
	concurrency := 20

	for _, ep := range endpoints {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), ep)

		var wg sync.WaitGroup
		responses := make(chan int, concurrency)

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := client.Post(u, "application/json", bytes.NewReader([]byte(`{}`)))
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
	client := &http.Client{Timeout: 10 * time.Second}

	sensitiveEndpoints := []string{
		"/api/admin", "/api/settings", "/api/security",
		"/api/change-password", "/api/2fa/verify",
	}

	for _, ep := range sensitiveEndpoints {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), ep)

		req, _ := http.NewRequest("GET", u, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

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
			req2, _ := http.NewRequest("POST", u, bytes.NewReader([]byte(payload)))
			req2.Header.Set("Content-Type", "application/json")
			resp2, err := client.Do(req2)
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
	client := &http.Client{Timeout: 10 * time.Second}

	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	nonePayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","role":"admin","iat":1516239022}`))
	noneToken := fmt.Sprintf("%s.%s.", noneHeader, nonePayload)

	endpoints := []string{
		"/api/admin", "/api/users", "/api/profile",
		"/api/protected", "/api/dashboard",
	}

	for _, ep := range endpoints {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), ep)

		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("Authorization", "Bearer "+noneToken)

		resp, err := client.Do(req)
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

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	pemBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	pemData := pem.EncodeToMemory(pemBlock)

	for _, ep := range endpoints {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), ep)
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("X-Public-Key", string(pemData))
		req.Header.Set("Authorization", "Bearer test-key-confusion-token")

		resp, err := client.Do(req)
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
	client := &http.Client{Timeout: 10 * time.Second}

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
			resp, err := client.Get(u)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

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
	client := &http.Client{Timeout: 10 * time.Second}

	introspectionQuery := `{"query":"query { __schema { types { name fields { name } } } }"}`
	endpoints := []string{"/graphql", "/api/graphql", "/graph", "/query", "/v1/graphql"}

	for _, ep := range endpoints {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), ep)

		resp, err := client.Post(u, "application/json", strings.NewReader(introspectionQuery))
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

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

			req, _ := http.NewRequest("GET", httpURL, nil)
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
	client := &http.Client{Timeout: 10 * time.Second}

	maliciousHost := "evil.com"

	req, _ := http.NewRequest("GET", target, nil)
	req.Header.Set("X-Forwarded-Host", maliciousHost)
	req.Header.Set("X-Forwarded-Scheme", "https")

	resp, err := client.Do(req)
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

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
		req2, _ := http.NewRequest("GET", target, nil)
		req2.Header.Set(header, value)
		resp2, err := client.Do(req2)
		if err != nil {
			continue
		}
		body2, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()

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
	client := &http.Client{Timeout: 10 * time.Second}

	payloads := []string{
		"?__proto__[test]=true",
		"?constructor[prototype][test]=true",
		"?__proto__.test=true",
	}

	for _, payload := range payloads {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), payload)
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

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
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	maliciousHosts := []string{"evil.com", "127.0.0.1", "localhost", "0.0.0.0"}

	for _, host := range maliciousHosts {
		req, _ := http.NewRequest("GET", target, nil)
		req.Host = host

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

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
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), payload)
		req, _ := http.NewRequest("GET", u, nil)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

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
	client := &http.Client{Timeout: 10 * time.Second}

	resetEndpoints := []string{
		"/api/reset-password", "/api/forgot-password",
		"/api/auth/reset", "/password-reset",
	}

	for _, ep := range resetEndpoints {
		u := fmt.Sprintf("%s%s", strings.TrimRight(target, "/"), ep)

		for _, token := range []string{"123456", "000000", "111111", "token=1", "token=admin"} {
			req, _ := http.NewRequest("POST", u,
				bytes.NewReader([]byte(fmt.Sprintf(`{"token":"%s","email":"test@test.com"}`, token))))
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

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
		req, _ := http.NewRequest("POST", u, bytes.NewReader([]byte(emailChangePayload)))
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
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
