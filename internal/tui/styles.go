package tui

import (
	"github.com/charmbracelet/lipgloss"
)

type Styles struct {
	Title      lipgloss.Style
	Panel      lipgloss.Style
	ActiveTab  lipgloss.Style
	InactiveTab lipgloss.Style
	Status     lipgloss.Style
	Log        lipgloss.Style
	Footer     lipgloss.Style
	Key        lipgloss.Style
	Critical   lipgloss.Style
	High       lipgloss.Style
	Medium     lipgloss.Style
	Low        lipgloss.Style
	Info       lipgloss.Style
}

var DefaultStyles = Styles{
	Title: lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#58a6ff")).
		Padding(0, 1),
	Panel: lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#30363d")).
		Padding(1, 2),
	ActiveTab: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#58a6ff")).
		Bold(true).
		Underline(true),
	InactiveTab: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#484f58")),
	Status: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#3fb950")),
	Log: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#8b949e")),
	Footer: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#484f58")).
		Padding(0, 1),
	Key: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#58a6ff")).
		Bold(true),
	Critical: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#f85149")).
		Bold(true),
	High: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#d29922")).
		Bold(true),
	Medium: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#58a6ff")),
	Low: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#3fb950")),
	Info: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#8b949e")),
}
