package recon

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type Subfinder struct {
	Target    string
	RateLimit int
}

func NewSubfinder(target string) *Subfinder {
	return &Subfinder{Target: target}
}

func (s *Subfinder) Run(ctx context.Context) ([]string, error) {
	if err := ValidateTarget(s.Target); err != nil {
		return nil, err
	}
	args := []string{"-d", s.Target, "-silent"}
	if s.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", s.RateLimit))
	}
	cmd := exec.CommandContext(ctx, "subfinder", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("subfinder: %w", err)
	}

	var subdomains []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subdomains = append(subdomains, line)
		}
	}
	return subdomains, nil
}

type Httpx struct {
	Targets []string
}

func NewHttpx(targets []string) *Httpx {
	return &Httpx{Targets: targets}
}

func (h *Httpx) Run(ctx context.Context) ([]string, error) {
	if len(h.Targets) == 0 {
		return nil, nil
	}
	input := strings.Join(h.Targets, "\n")
	cmd := exec.CommandContext(ctx, "httpx", "-silent", "-status-code", "-title", "-tech-detect")
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("httpx: %w", err)
	}

	var alive []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.Split(line, " ")
		if len(parts) > 0 {
			alive = append(alive, parts[0])
		} else if line != "" {
			alive = append(alive, line)
		}
	}
	return alive, nil
}

func (h *Httpx) RunWithTech(ctx context.Context) ([]ProbingResult, error) {
	if len(h.Targets) == 0 {
		return nil, nil
	}
	input := strings.Join(h.Targets, "\n")
	cmd := exec.CommandContext(ctx, "httpx", "-silent", "-status-code", "-title", "-tech-detect")
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("httpx tech: %w", err)
	}

	var results []ProbingResult
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		pr := ProbingResult{URL: line}
		parts := strings.Split(line, " ")

		if len(parts) >= 1 {
			pr.URL = parts[0]
		}

		for i, p := range parts {
			if p == "" {
				continue
			}
			if p[0] == '[' && p[len(p)-1] == ']' {
				inner := p[1 : len(p)-1]
				if i > 0 {
					prev := strings.TrimSpace(parts[i-1])
					if isNumeric(prev) {
						pr.StatusCode = parseInt(prev)
					}
				}
				if strings.Contains(inner, ",") || inner == "" {
					continue
				}
				if !isNumeric(inner) {
					pr.Title = inner
				}
			}
			if strings.HasPrefix(p, "[") && strings.Contains(p, ",") {
				continue
			}
		}

		techStart := -1
		for i, p := range parts {
			if strings.HasPrefix(p, "[") && strings.Contains(p, ",") {
				techStart = i
				break
			}
		}

		if techStart >= 0 {
			techPart := strings.Join(parts[techStart:], " ")
			techPart = strings.Trim(techPart, "[]")
			techNames := strings.Split(techPart, ",")
			for _, t := range techNames {
				name := strings.TrimSpace(t)
				if name != "" {
					pr.Tech = append(pr.Tech, name)
				}
			}
		}

		results = append(results, pr)
	}

	return results, nil
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}
