package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type EPSSClient struct {
	httpClient *http.Client
	baseURL    string
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
		httpClient: &http.Client{Timeout: 10 * time.Second},
		baseURL:    "https://api.first.org/data/v1/epss",
	}
}

func GetEPSS(cve string) (float64, error) {
	client := NewEPSSClient()
	return client.GetEPSS(cve)
}

func (c *EPSSClient) GetEPSS(cve string) (float64, error) {
	url := fmt.Sprintf("%s?cve=%s", c.baseURL, cve)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return 0.0, nil
	}
	defer resp.Body.Close()

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

	return score, nil
}
