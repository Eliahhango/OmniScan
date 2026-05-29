package recon

import (
	"fmt"
	"regexp"
	"strings"
)

var safeTarget = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.\-:/_]*[a-zA-Z0-9])?$`)

func ValidateTarget(target string) error {
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("target %q looks like a flag, not a host", target)
	}
	if !safeTarget.MatchString(target) {
		return fmt.Errorf("target %q contains unsafe characters", target)
	}
	return nil
}

func ValidateTargets(targets []string) error {
	for _, t := range targets {
		if err := ValidateTarget(t); err != nil {
			return err
		}
	}
	return nil
}
