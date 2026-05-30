package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type EPSSClient struct {
	httpClient *http.Client
	baseURL    string
	mu         sync.Mutex
	lastCall   time.Time
	cache      map[string]float64
}

type epssResponse struct {
	Data []epssData `json:"data"`
}

type epssData struct {
	CVE  string `json:"cve"`
	EPSS string `json:"epss"`
}

func NewEPSSClient() *EPSSClient {
	return &EPSSClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://api.first.org/data/v1/epss",
		cache:      make(map[string]float64),
	}
}

func (c *EPSSClient) GetEPSS(cve string) (float64, error) {
	c.mu.Lock()
	if score, ok := c.cache[cve]; ok {
		c.mu.Unlock()
		return score, nil
	}
	elapsed := time.Since(c.lastCall)
	if elapsed < 200*time.Millisecond {
		time.Sleep(200*time.Millisecond - elapsed)
	}
	c.lastCall = time.Now()
	c.mu.Unlock()

	url := fmt.Sprintf("%s?cve=%s", c.baseURL, cve)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return 0.0, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		time.Sleep(5 * time.Second)
		return c.GetEPSS(cve)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0.0, nil
	}

	var result epssResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return 0.0, nil
	}

	if len(result.Data) == 0 {
		return 0.0, nil
	}

	var score float64
	if _, err := fmt.Sscanf(result.Data[0].EPSS, "%f", &score); err != nil {
		return 0.0, nil
	}

	c.mu.Lock()
	c.cache[cve] = score
	c.mu.Unlock()

	return score, nil
}

func (c *EPSSClient) GetCachedEPSS(cve string) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cache[cve]
}

func (c *EPSSClient) GetEPSSBatch(cves []string) (map[string]float64, error) {
	if len(cves) == 0 {
		return nil, nil
	}

	const batchSize = 100
	scores := make(map[string]float64, len(cves))

	for i := 0; i < len(cves); i += batchSize {
		end := i + batchSize
		if end > len(cves) {
			end = len(cves)
		}
		batch := cves[i:end]

		url := fmt.Sprintf("%s?cve=%s", c.baseURL, strings.Join(batch, ","))
		c.rateLimit()

		resp, err := c.httpClient.Get(url)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		if resp.StatusCode == 429 {
			time.Sleep(5 * time.Second)
			i -= batchSize
			continue
		}

		var result epssResponse
		if err := json.Unmarshal(body, &result); err != nil {
			continue
		}

		for _, d := range result.Data {
			var score float64
			if _, err := fmt.Sscanf(d.EPSS, "%f", &score); err == nil {
				scores[d.CVE] = score
			}
		}
	}

	return scores, nil
}

func (c *EPSSClient) rateLimit() {
	c.mu.Lock()
	defer c.mu.Unlock()
	elapsed := time.Since(c.lastCall)
	if elapsed < 500*time.Millisecond {
		time.Sleep(500*time.Millisecond - elapsed)
	}
	c.lastCall = time.Now()
}
