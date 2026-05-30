package scanner

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Eliahhango/OmniScan/pkg/types"
	"crypto/sha256"
)

var subdomainWordlist = []string{
	"www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "webdisk",
	"ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
	"ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
	"mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
	"docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "media",
	"files", "app", "api", "apps", "portal", "stage", "staging", "cdn", "cloud",
	"dashboard", "auth", "login", "sso", "status", "cdn2", "assets", "git",
	"jenkins", "grafana", "kibana", "prometheus", "docker", "registry", "monitor",
	"metrics", "logs", "backup", "db", "database", "redis", "memcache",
	"elastic", "search", "smtp2", "mail3", "owa", "chat",
	"jira", "confluence", "wiki", "help", "kb",
	"payment", "pay", "billing", "checkout", "order", "orders", "store",
	"partner", "partners", "clients", "customer",
	"host", "hosting", "web", "site", "sites",
	"intranet", "internal", "private", "corp",
	"remote", "rdp", "terminal",
	"ftp2", "sftp", "ssh",
	"office", "hr", "finance", "legal", "it",
}

func CheckSubdomainEnum(target string) ([]types.Finding, error) {
	var findings []types.Finding
	host := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	host = strings.Split(host, "/")[0]
	host = strings.Split(host, ":")[0]

	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return findings, nil
	}
	baseDomain := host
	sld := parts[len(parts)-2]
	tld := parts[len(parts)-1]
	if len(parts) > 2 {
		baseDomain = sld + "." + tld
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 30)
	var mu sync.Mutex
	discovered := make(map[string][]string)

	for _, sub := range subdomainWordlist {
		wg.Add(1)
		sem <- struct{}{}
		go func(subdomain string) {
			defer wg.Done()
			defer func() { <-sem }()

			fullHost := subdomain + "." + baseDomain
			if fullHost == host {
				return
			}

			ips, err := net.LookupHost(fullHost)
			if err != nil || len(ips) == 0 {
				return
			}

			mu.Lock()
			discovered[fullHost] = ips
			mu.Unlock()
		}(sub)
	}
	wg.Wait()

	if len(discovered) > 0 {
		names := make([]string, 0, len(discovered))
		for d := range discovered {
			names = append(names, d)
		}
		sort.Strings(names)

		summary := fmt.Sprintf("Discovered %d subdomains of %s: %s", len(names), baseDomain, strings.Join(names, ", "))
		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("subdomains-%x", sha256.Sum256([]byte(host+baseDomain)))[:24],
			Title:       "Subdomains Discovered",
			Description: summary,
			Severity:    types.SeverityInfo,
			AffectedURL: target,
			ToolSource:  "custom-subdomain-enum",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

var htmlLinkRe = regexp.MustCompile(`(?i)(?:href|src|action|content)\s*=\s*["']([^"'\s>]+)["']`)

func CheckURLCrawler(target string) ([]types.Finding, error) {
	var findings []types.Finding

	baseURL := target
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "https://" + baseURL
	}

	resp, err := sharedClient.Get(baseURL)
	if err != nil {
		return findings, nil
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return findings, nil
	}
	bodyStr := string(body)

	matches := htmlLinkRe.FindAllStringSubmatch(bodyStr, -1)
	seen := make(map[string]bool)
	for _, m := range matches {
		raw := strings.TrimRight(strings.TrimSpace(m[1]), "\\")
		if raw == "" || raw == "#" || raw == "/" {
			continue
		}
		resolved := resolveURL(raw, baseURL)
		if strings.HasPrefix(resolved, "http") && strings.Contains(resolved, "://") {
			if !seen[resolved] {
				seen[resolved] = true
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("url-%x", sha256.Sum256([]byte(resolved)))[:24],
					Title:       "Discovered URL",
					Description: fmt.Sprintf("URL extracted from HTML: %s", resolved),
					Severity:    types.SeverityInfo,
					AffectedURL: resolved,
					ToolSource:  "custom-url-crawler",
					Timestamp:   time.Now(),
				})
			}
		}
	}

	// Try sitemap.xml and robots.txt for more URLs
	extraPaths := []string{"/sitemap.xml", "/robots.txt"}
	for _, path := range extraPaths {
		u := strings.TrimRight(baseURL, "/") + path
		r, err := sharedClient.Get(u)
		if err != nil {
			continue
		}
		b, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			continue
		}
		for _, m := range htmlLinkRe.FindAllStringSubmatch(string(b), -1) {
			raw := strings.TrimRight(strings.TrimSpace(m[1]), "\\")
			if raw == "" || raw == "#" || raw == "/" {
				continue
			}
			resolved := resolveURL(raw, baseURL)
			if strings.HasPrefix(resolved, "http") && !seen[resolved] {
				seen[resolved] = true
				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("url-%x", sha256.Sum256([]byte(resolved)))[:24],
					Title:       "Discovered URL (from " + path + ")",
					Description: fmt.Sprintf("URL from %s: %s", path, resolved),
					Severity:    types.SeverityInfo,
					AffectedURL: resolved,
					ToolSource:  "custom-url-crawler",
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return findings, nil
}

func resolveURL(raw, base string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	if strings.HasPrefix(raw, "//") {
		parsed, err := url.Parse(base)
		if err != nil {
			return ""
		}
		return parsed.Scheme + ":" + raw
	}
	if strings.HasPrefix(raw, "/") {
		parsed, err := url.Parse(base)
		if err != nil {
			return ""
		}
		return parsed.Scheme + "://" + parsed.Host + raw
	}
	if strings.HasSuffix(base, "/") {
		return base + raw
	}
	return base + "/" + raw
}
