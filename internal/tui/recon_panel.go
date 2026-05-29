package tui

import (
	"fmt"
	"strings"
)

type ReconPanel struct {
	activeTools []string
	completed   []string
	results     []string
}

func NewReconPanel() *ReconPanel {
	return &ReconPanel{}
}

func (r *ReconPanel) AddActive(tool string) {
	r.activeTools = append(r.activeTools, tool)
}

func (r *ReconPanel) Complete(tool string) {
	r.activeTools = removeString(r.activeTools, tool)
	r.completed = append(r.completed, tool)
}

func (r *ReconPanel) AddResult(result string) {
	r.results = append(r.results, result)
}

func (r *ReconPanel) View() string {
	var lines []string
	for _, tool := range r.activeTools {
		lines = append(lines, fmt.Sprintf("> %s [RUNNING]", tool))
	}
	for _, tool := range r.completed {
		lines = append(lines, fmt.Sprintf("+ %s [DONE]", tool))
	}
	if len(lines) == 0 {
		return "   Waiting for scan..."
	}
	return strings.Join(lines, "\n")
}

func removeString(slice []string, s string) []string {
	for i, v := range slice {
		if v == s {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}
