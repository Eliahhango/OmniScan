package recon

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Gospider struct {
	Target string
}

func NewGospider(target string) *Gospider {
	return &Gospider{Target: target}
}

func (g *Gospider) Run(ctx context.Context) ([]string, error) {
	outputDir, err := os.MkdirTemp("", "gospider-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(outputDir)

	cmd := exec.CommandContext(ctx, "gospider", "-s", g.Target, "-o", outputDir)
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	var urls []string
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(outputDir, entry.Name()))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "[url] ") {
				url := strings.TrimPrefix(line, "[url] ")
				if url != "" {
					urls = append(urls, url)
				}
			}
		}
	}
	return urls, nil
}
