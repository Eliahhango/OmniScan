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
	Cache     *ResultCache
}

func NewKatana(targets []string) *Katana {
	return &Katana{Targets: targets}
}

func (k *Katana) Run(ctx context.Context) ([]string, error) {
	if len(k.Targets) == 0 {
		return nil, nil
	}

	cacheKey := "katana:" + strings.Join(k.Targets, ",")
	if k.Cache != nil {
		if cached, ok := k.Cache.Get(cacheKey); ok {
			return cached, nil
		}
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

	if k.Cache != nil {
		k.Cache.Set(cacheKey, urls)
	}
	return urls, nil
}

type GAU struct {
	Target string
	Cache  *ResultCache
}

func NewGAU(target string) *GAU {
	return &GAU{Target: target}
}

func (g *GAU) Run(ctx context.Context) ([]string, error) {
	if err := ValidateTarget(g.Target); err != nil {
		return nil, err
	}

	cacheKey := "gau:" + g.Target
	if g.Cache != nil {
		if cached, ok := g.Cache.Get(cacheKey); ok {
			return cached, nil
		}
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

	if g.Cache != nil {
		g.Cache.Set(cacheKey, urls)
	}
	return urls, nil
}
