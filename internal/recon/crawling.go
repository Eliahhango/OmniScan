package recon

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type Katana struct {
	Targets   []string
	RateLimit int
}

func NewKatana(targets []string) *Katana {
	return &Katana{Targets: targets}
}

func (k *Katana) Run(ctx context.Context) ([]string, error) {
	if len(k.Targets) == 0 {
		return nil, nil
	}
	args := []string{"-silent"}
	if k.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", k.RateLimit))
	}
	input := strings.Join(k.Targets, "\n")
	cmd := exec.CommandContext(ctx, "katana", args...)
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("katana: %w", err)
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

type GAU struct {
	Target string
}

func NewGAU(target string) *GAU {
	return &GAU{Target: target}
}

func (g *GAU) Run(ctx context.Context) ([]string, error) {
	if err := ValidateTarget(g.Target); err != nil {
		return nil, err
	}
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
