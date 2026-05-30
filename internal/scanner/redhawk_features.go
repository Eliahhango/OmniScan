package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

func init() {
	checks := []CustomCheck{
		{
			Name:        "whois-lookup",
			Description: "WHOIS lookup for domain registration info",
			Check:       checkWhois,
		},
		{
			Name:        "geo-ip-lookup",
			Description: "Geo-IP location lookup via ip-api.com",
			Check:       checkGeoIP,
		},
		{
			Name:        "social-links",
			Description: "Extract social media links from page source",
			Check:       checkSocialLinks,
		},
		{
			Name:        "cms-detection",
			Description: "Enhanced CMS detection (WordPress, Joomla, Drupal, Magento, etc.)",
			Check:       checkCMS,
		},
	}
	CustomChecks = append(CustomChecks, checks...)
}

var whoisServers = map[string]string{
	"com":  "whois.verisign-grs.com",
	"net":  "whois.verisign-grs.com",
	"org":  "whois.pir.org",
	"info": "whois.afilias.net",
	"io":   "whois.nic.io",
	"co":   "whois.nic.co",
}

func checkWhois(target string) ([]types.Finding, error) {
	host := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	host = strings.Split(host, "/")[0]
	host = strings.Split(host, ":")[0]
	host = strings.TrimPrefix(host, "www.")

	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid domain")
	}
	tld := parts[len(parts)-1]

	server, ok := whoisServers[tld]
	if !ok {
		return nil, nil
	}

	conn, err := net.DialTimeout("tcp", server+":43", 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "%s\r\n", host)

	data, err := io.ReadAll(conn)
	if err != nil {
		return nil, err
	}

	body := string(data)
	if len(body) > 2000 {
		body = body[:2000]
	}

	findings := []types.Finding{
		{
			ID:          fmt.Sprintf("whois-%s", host),
			Title:       "WHOIS Lookup",
			Description: fmt.Sprintf("WHOIS data for %s:\n%s", host, body),
			Severity:    types.SeverityInfo,
			AffectedURL: target,
			ToolSource:  "custom-whois",
			Timestamp:   time.Now(),
		},
	}
	return findings, nil
}

type geoIPResult struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Query       string  `json:"query"`
}

func checkGeoIP(target string) ([]types.Finding, error) {
	host := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	host = strings.Split(host, "/")[0]
	host = strings.Split(host, ":")[0]

	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("cannot resolve host: %v", err)
	}
	ip := ips[0]

	resp, err := http.Get("http://ip-api.com/json/" + ip)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var geo geoIPResult
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		return nil, err
	}

	if geo.Status != "success" {
		return nil, fmt.Errorf("geo-ip lookup failed for %s", ip)
	}

	desc := fmt.Sprintf("IP: %s\nCountry: %s (%s)\nRegion: %s\nCity: %s\nZIP: %s\nLat/Lon: %.4f, %.4f\nTimezone: %s\nISP: %s\nOrg: %s\nAS: %s",
		geo.Query, geo.Country, geo.CountryCode, geo.RegionName, geo.City, geo.Zip, geo.Lat, geo.Lon, geo.Timezone, geo.ISP, geo.Org, geo.AS)

	findings := []types.Finding{
		{
			ID:          fmt.Sprintf("geoip-%s", host),
			Title:       "Geo-IP Location",
			Description: desc,
			Severity:    types.SeverityInfo,
			AffectedURL: target,
			ToolSource:  "custom-geoip",
			Timestamp:   time.Now(),
		},
	}
	return findings, nil
}

var socialPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"Facebook", regexp.MustCompile(`(?i)(?:https?://)?(?:www\.)?facebook\.com/[a-zA-Z0-9._-]+`)},
	{"Twitter/X", regexp.MustCompile(`(?i)(?:https?://)?(?:www\.)?twitter\.com/[a-zA-Z0-9_]+`)},
	{"Instagram", regexp.MustCompile(`(?i)(?:https?://)?(?:www\.)?instagram\.com/[a-zA-Z0-9._-]+`)},
	{"YouTube", regexp.MustCompile(`(?i)(?:https?://)?(?:www\.)?youtube\.com/(?:c|channel|user|@)/[a-zA-Z0-9_-]+`)},
	{"LinkedIn", regexp.MustCompile(`(?i)(?:https?://)?(?:www\.)?linkedin\.com/(?:company|in)/[a-zA-Z0-9._-]+`)},
	{"GitHub", regexp.MustCompile(`(?i)(?:https?://)?(?:www\.)?github\.com/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+`)},
	{"Pinterest", regexp.MustCompile(`(?i)(?:https?://)?(?:www\.)?pinterest\.[a-z]{2,6}/[a-zA-Z0-9._-]+`)},
	{"TikTok", regexp.MustCompile(`(?i)(?:https?://)?(?:www\.)?tiktok\.com/@[a-zA-Z0-9._-]+`)},
}

func checkSocialLinks(target string) ([]types.Finding, error) {
	target = ensureURL(target)
	resp, err := sharedClient.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	src := string(body)

	var links []string
	seen := make(map[string]bool)

	for _, sp := range socialPatterns {
		matches := sp.re.FindAllString(src, -1)
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				links = append(links, fmt.Sprintf("%s: %s", sp.name, m))
			}
		}
	}

	if len(links) == 0 {
		return nil, nil
	}

	findings := []types.Finding{
		{
			ID:          fmt.Sprintf("social-%s", extractHost(target)),
			Title:       "Social Media Links Found",
			Description: fmt.Sprintf("Found %d social media links:\n%s", len(links), strings.Join(links, "\n")),
			Severity:    types.SeverityInfo,
			AffectedURL: target,
			ToolSource:  "custom-social",
			Timestamp:   time.Now(),
		},
	}
	return findings, nil
}

var cmsPatterns = []struct {
	name    string
	markers []string
	probe   func(host string) bool
}{
	{
		name:    "WordPress",
		markers: []string{"/wp-content/", "/wp-includes/", "wp-json", "WordPress"},
	},
	{
		name:    "Joomla",
		markers: []string{"/media/system/js/", "Joomla!", "com_content", "/components/"},
	},
	{
		name:    "Drupal",
		markers: []string{"Drupal", "/sites/default/", "/core/misc/drupal.js", "drupal.js"},
	},
	{
		name:    "Magento",
		markers: []string{"/skin/frontend/", "Magento", "mage/"},
	},
	{
		name:    "Shopify",
		markers: []string{"cdn.shopify.com", "/shopify/", "Shopify"},
	},
	{
		name:    "Wix",
		markers: []string{"wix.com", "Wix", "X-Wix-Published-Version"},
	},
}

func checkCMS(target string) ([]types.Finding, error) {
	target = ensureURL(target)
	resp, err := sharedClient.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	src := string(body)

	headers := resp.Header

	var detected []string
	for _, cms := range cmsPatterns {
		for _, marker := range cms.markers {
			if strings.Contains(src, marker) {
				detected = append(detected, cms.name)
				break
			}
		}
		if len(detected) > 0 && detected[len(detected)-1] == cms.name {
			continue
		}
		for k, v := range headers {
			if strings.Contains(strings.ToLower(k), "x-powered-by") || strings.Contains(strings.ToLower(k), "x-generator") {
				for _, vv := range v {
					for _, marker := range cms.markers {
						if strings.Contains(vv, marker) {
							detected = append(detected, cms.name)
							break
						}
					}
				}
			}
		}
	}

	if len(detected) == 0 {
		return nil, nil
	}

	host := extractHost(target)
	findings := []types.Finding{
		{
			ID:          fmt.Sprintf("cms-%s", host),
			Title:       "CMS Detection",
			Description: fmt.Sprintf("Detected CMS: %s", strings.Join(detected, ", ")),
			Severity:    types.SeverityInfo,
			AffectedURL: target,
			ToolSource:  "custom-cms",
			Timestamp:   time.Now(),
		},
	}
	return findings, nil
}

func extractHost(target string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	h = strings.Split(h, "/")[0]
	h = strings.Split(h, ":")[0]
	return h
}
