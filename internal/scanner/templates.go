package scanner

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type TemplateManager struct {
	TemplateDir string
	HTTPClient  *http.Client
	mu          sync.Mutex
	tagCache    map[string]tagInfo
}

type TemplateInfo struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Severity   string   `json:"severity"`
	Tags       []string `json:"tags"`
	CVE        string   `json:"cve,omitempty"`
	CWE        string   `json:"cwe,omitempty"`
	Technology string   `json:"technology,omitempty"`
}

func NewTemplateManager(templateDir string) *TemplateManager {
	return &TemplateManager{
		TemplateDir: templateDir,
		HTTPClient:  &http.Client{Timeout: 2 * time.Minute},
	}
}

func (tm *TemplateManager) UpdateTemplates() error {
	url := "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	resp, err := tm.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("download templates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "nuclei-templates-*.zip")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	tmpFile.Close()

	if err := os.RemoveAll(tm.TemplateDir); err != nil {
		os.Remove(tmpPath)
		return err
	}

	reader, err := zip.OpenReader(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return err
	}

	extractDir := tm.TemplateDir
	absExtractDir, err := filepath.Abs(filepath.Clean(extractDir))
	if err != nil {
		reader.Close()
		os.Remove(tmpPath)
		return err
	}
	for _, f := range reader.File {
		parts := strings.SplitN(f.Name, "/", 2)
		if len(parts) < 2 {
			continue
		}
		targetPath := filepath.Join(extractDir, parts[1])
		absTarget, err := filepath.Abs(filepath.Clean(targetPath))
		if err != nil {
			continue
		}
		if !strings.HasPrefix(absTarget, absExtractDir+string(filepath.Separator)) && absTarget != absExtractDir {
			continue
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(targetPath, 0755)
			continue
		}

		os.MkdirAll(filepath.Dir(targetPath), 0755)
		rc, err := f.Open()
		if err != nil {
			continue
		}

		dst, err := os.Create(targetPath)
		if err != nil {
			rc.Close()
			continue
		}

		io.Copy(dst, rc)
		dst.Close()
		rc.Close()

		tm.applyFileMode(targetPath, f.Mode())
	}

	reader.Close()
	os.Remove(tmpPath)
	tm.mu.Lock()
	tm.tagCache = nil
	tm.mu.Unlock()
	return nil
}

func (tm *TemplateManager) applyFileMode(path string, mode os.FileMode) {
	safe := mode & os.ModePerm
	if safe&0022 != 0 {
		safe &^= 0022
	}
	os.Chmod(path, safe)
}

type tagInfo struct {
	CVE        string `json:"cve"`
	CWE        string `json:"cwe"`
	OWASP      string `json:"owasp"`
	Technology string `json:"technology"`
	BugBounty  string `json:"bugbounty"`
}

func (tm *TemplateManager) TagTemplates() (map[string]tagInfo, error) {
	tm.mu.Lock()
	if tm.tagCache != nil {
		cache := tm.tagCache
		tm.mu.Unlock()
		return cache, nil
	}
	tm.mu.Unlock()

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.tagCache != nil {
		return tm.tagCache, nil
	}

	tags := make(map[string]tagInfo)
	err := filepath.Walk(tm.TemplateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		id := tm.extractTemplateID(data)
		if id == "" {
			return nil
		}

		tags[id] = tagInfo{
			CVE:        tm.extractTag(data, "cve"),
			CWE:        tm.extractTag(data, "cwe"),
			OWASP:      tm.extractTag(data, "owasp"),
			Technology: tm.extractTag(data, "technology"),
			BugBounty:  tm.extractTag(data, "bugbounty"),
		}

		return nil
	})
	if err == nil {
		tm.tagCache = tags
	}
	return tags, err
}

func (tm *TemplateManager) extractTemplateID(data []byte) string {
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return ""
	}
	if id, ok := parsed["id"].(string); ok {
		return id
	}
	return ""
}

func (tm *TemplateManager) extractTag(data []byte, tag string) string {
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return ""
	}
	info, ok := parsed["info"].(map[string]interface{})
	if !ok {
		return ""
	}
	tags, ok := info["tags"].(string)
	if !ok {
		return ""
	}
	for _, t := range strings.Split(tags, ",") {
		t = strings.TrimSpace(t)
		if strings.HasPrefix(t, tag+":") {
			return strings.TrimPrefix(t, tag+":")
		}
	}
	return ""
}

func (tm *TemplateManager) PriorityScore(templateID string) int {
	score := 5

	tags, err := tm.TagTemplates()
	if err != nil {
		return score
	}

	info, ok := tags[templateID]
	if !ok {
		return score
	}

	if info.CVE != "" {
		score += 3
	}

	if info.CWE != "" {
		score += 2
	}

	if info.OWASP != "" {
		score += 1
	}

	if info.Technology != "" {
		score += 1
	}

	if info.BugBounty != "" {
		score += 3
	}

	return score
}
