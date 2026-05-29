package recon

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type Katana struct {
	Targets []string
}

func NewKatana(targets []string) *Katana {
	return &Katana{Targets: targets}
}

func (k *Katana) Run(ctx context.Context) ([]string, error) {
	input := strings.Join(k.Targets, "\n")
	cmd := exec.CommandContext(ctx, "katana", "-silent")
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return k.Targets, nil
	}

	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}
	if len(urls) == 0 {
		return k.Targets, nil
	}
	return urls, nil
}

type GAU struct {
	Target string
}

func NewGAU(target string) *GAU {
	return &GAU{Target: target}
}

func (g *GAU) Run(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, "gau", g.Target)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("gau: %w", err)
	}

	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}
	return urls, nil
}
