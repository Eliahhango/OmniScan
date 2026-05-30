package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Eliahhango/OmniScan/pkg/types"
	"crypto/sha256"
)

var techFingerprints = []struct {
	pattern  *regexp.Regexp
	name     string
	category string
}{
	{regexp.MustCompile(`(?i)wp-content|wp-includes|wordpress`), "WordPress", "CMS"},
	{regexp.MustCompile(`(?i)joomla|com_content|mosConfig`), "Joomla", "CMS"},
	{regexp.MustCompile(`(?i)drupal|sites/default|Drupal\.settings`), "Drupal", "CMS"},
	{regexp.MustCompile(`(?i)magento|Mage\.|skin/frontend`), "Magento", "CMS"},
	{regexp.MustCompile(`(?i)shopify|Shopify\.shop`), "Shopify", "CMS"},
	{regexp.MustCompile(`(?i)laravel|Laravel|csrf-token.*XSRF-TOKEN`), "Laravel", "Framework"},
	{regexp.MustCompile(`(?i)django|csrftoken.*csrfmiddlewaretoken`), "Django", "Framework"},
	{regexp.MustCompile(`(?i)rails|rails-ujs|action_cable`), "Ruby on Rails", "Framework"},
	{regexp.MustCompile(`(?i)asp\.net|__VIEWSTATE|__EVENTVALIDATION`), "ASP.NET", "Framework"},
	{regexp.MustCompile(`(?i)express|express-session`), "Express.js", "Framework"},
	{regexp.MustCompile(`(?i)next\.js|__NEXT_DATA__|_next/static`), "Next.js", "Framework"},
	{regexp.MustCompile(`(?i)nuxt\.js|__NUXT__`), "Nuxt.js", "Framework"},
	{regexp.MustCompile(`(?i)react\.(createElement|dom|propTypes)`), "React", "Framework"},
	{regexp.MustCompile(`(?i)vue\.js|vue@|\bv-app\b`), "Vue.js", "Framework"},
	{regexp.MustCompile(`(?i)angular|ng-version|ng-app`), "Angular", "Framework"},
	{regexp.MustCompile(`(?i)nginx`), "Nginx", "Server"},
	{regexp.MustCompile(`(?i)apache`), "Apache", "Server"},
	{regexp.MustCompile(`(?i)microsoft-iis|iis`), "IIS", "Server"},
	{regexp.MustCompile(`(?i)cloudflare|cf-ray|__cf_bm`), "Cloudflare CDN", "CDN/WAF"},
	{regexp.MustCompile(`(?i)akamai|akamai-edgesuite`), "Akamai CDN", "CDN/WAF"},
	{regexp.MustCompile(`(?i)fastly|fastly-cdn`), "Fastly CDN", "CDN/WAF"},
	{regexp.MustCompile(`(?i)aws|x-amz-|amazonaws`), "AWS", "Cloud Provider"},
	{regexp.MustCompile(`(?i)google|gstatic|firebase`), "Google Cloud", "Cloud Provider"},
	{regexp.MustCompile(`(?i)azure|azureedge|azurewebsites`), "Azure", "Cloud Provider"},
	{regexp.MustCompile(`(?i)jquery|jQuery\s+v?(\d+\.\d+\.\d+)`), "jQuery", "JS Library"},
	{regexp.MustCompile(`(?i)bootstrap|bootstrap\.min`), "Bootstrap", "JS Library"},
	{regexp.MustCompile(`(?i)font[-_]?awesome`), "Font Awesome", "JS Library"},
	{regexp.MustCompile(`(?i)google[-_]?analytics|gtag|ga\.js`), "Google Analytics", "Analytics"},
	{regexp.MustCompile(`(?i)googletagmanager|GTM-|gtm\.js`), "Google Tag Manager", "Analytics"},
}

func checkTechFingerprint(target string) ([]types.Finding, error) {
	var findings []types.Finding

	resp, err := sharedClient.Get(target)
	if err != nil {
		return findings, nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return findings, nil
	}
	bodyStr := string(body)

	found := make(map[string]bool)
	for _, fp := range techFingerprints {
		if found[fp.name] {
			continue
		}
		if fp.pattern.MatchString(bodyStr) {
			found[fp.name] = true
			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("tech-%s-%x", fp.name, sha256.Sum256([]byte(fp.name+target)))[:24],
				Title:       fmt.Sprintf("Technology Detected: %s (%s)", fp.name, fp.category),
				Severity:    types.SeverityInfo,
				AffectedURL: target,
				Description: fmt.Sprintf("%s (%s) detected on %s via response body fingerprinting.", fp.name, fp.category, target),
				ToolSource:  "custom-tech-fingerprint",
				Timestamp:   time.Now(),
			})
		}
	}

	server := resp.Header.Get("Server")
	if server != "" {
		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("tech-server-%x", sha256.Sum256([]byte(server)))[:24],
			Title:       fmt.Sprintf("Server Header Disclosure: %s", server),
			Severity:    types.SeverityLow,
			AffectedURL: target,
			CWE:         []string{"CWE-200"},
			OWASP2025:   "Security Misconfiguration",
			Description: fmt.Sprintf("The Server header reveals: %s", server),
			Evidence:    fmt.Sprintf("Server: %s", server),
			Remediation: "Configure web server to suppress or obfuscate the Server header.",
			ToolSource:  "custom-tech-fingerprint",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

var kevCache []string
var kevMu sync.Mutex
var kevLastFetch time.Time

func fetchCisaKEV() ([]string, error) {
	kevMu.Lock()
	defer kevMu.Unlock()

	if len(kevCache) > 0 && time.Since(kevLastFetch) < 24*time.Hour {
		return kevCache, nil
	}

	resp, err := http.Get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	if err != nil {
		return kevCache, nil
	}
	defer resp.Body.Close()

	var data struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return kevCache, nil
	}

	kevCache = make([]string, 0, len(data.Vulnerabilities))
	for _, v := range data.Vulnerabilities {
		kevCache = append(kevCache, v.CVEID)
	}
	kevLastFetch = time.Now()

	return kevCache, nil
}

func checkCisaKEV(target string) ([]types.Finding, error) {
	var findings []types.Finding

	kevCVEs, err := fetchCisaKEV()
	if err != nil || len(kevCVEs) == 0 {
		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("kev-status-%x", sha256.Sum256([]byte(target)))[:24],
			Title:       "CISA KEV Status: Database Unavailable",
			Severity:    types.SeverityInfo,
			Description: "CISA Known Exploited Vulnerabilities database could not be fetched.",
			ToolSource:  "custom-cisa-kev",
			Timestamp:   time.Now(),
		})
		return findings, nil
	}

	findings = append(findings, types.Finding{
		ID:          fmt.Sprintf("kev-loaded-%x", sha256.Sum256([]byte(target)))[:24],
		Title:       "CISA KEV Database Loaded",
		Severity:    types.SeverityInfo,
		AffectedURL: target,
		Description: fmt.Sprintf("Loaded %d actively exploited vulnerabilities from CISA KEV database.", len(kevCVEs)),
		Evidence:    fmt.Sprintf("KEV entries: %d | Fetched: %s", len(kevCVEs), kevLastFetch.Format("2006-01-02 15:04:05")),
		ToolSource:  "custom-cisa-kev",
		Timestamp:   time.Now(),
	})

	return findings, nil
}

func IsCISAKEV(cve string) bool {
	kevCVEs, err := fetchCisaKEV()
	if err != nil {
		return false
	}
	for _, k := range kevCVEs {
		if strings.EqualFold(k, cve) {
			return true
		}
	}
	return false
}

func checkEPSS(target string) ([]types.Finding, error) {
	var findings []types.Finding

	resp, err := http.Get("https://api.first.org/data/v1/epss?cve=CVE-2021-44228&scope=public")
	if err != nil {
		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("epss-status-%x", sha256.Sum256([]byte(target)))[:24],
			Title:       "EPSS Scoring: API Unavailable",
			Severity:    types.SeverityInfo,
			Description: "EPSS API is unreachable. CVE exploit probability scoring unavailable.",
			ToolSource:  "custom-epss",
			Timestamp:   time.Now(),
		})
		return findings, nil
	}
	defer resp.Body.Close()

	var result struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
			Date       string `json:"date"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return findings, nil
	}

	if len(result.Data) > 0 {
		d := result.Data[0]
		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("epss-api-%x", sha256.Sum256([]byte("epss"+target)))[:24],
			Title:       "EPSS Scoring API Available",
			Severity:    types.SeverityInfo,
			AffectedURL: target,
			Description: fmt.Sprintf("EPSS API operational. Sample: %s score=%s percentile=%s", d.CVE, d.EPSS, d.Percentile),
			Evidence:    fmt.Sprintf("EPSS: %s score=%s percentile=%s (date: %s)", d.CVE, d.EPSS, d.Percentile, d.Date),
			ToolSource:  "custom-epss",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

func LookupEPSS(cve string) (score float64, percentile float64, found bool) {
	resp, err := http.Get(fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s&scope=public", cve))
	if err != nil {
		return 0, 0, false
	}
	defer resp.Body.Close()

	var result struct {
		Data []struct {
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, 0, false
	}

	if len(result.Data) > 0 {
		var s, p float64
		fmt.Sscanf(result.Data[0].EPSS, "%f", &s)
		fmt.Sscanf(result.Data[0].Percentile, "%f", &p)
		return s, p, true
	}
	return 0, 0, false
}
