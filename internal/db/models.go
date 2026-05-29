package db

import "github.com/Eliahhango/OmniScan/pkg/types"

type Scan struct {
	ID         int64     `json:"id"`
	Target     string    `json:"target"`
	Scope      string    `json:"scope"`
	Stage      int       `json:"stage"`
	Progress   float64   `json:"progress"`
	Status     string    `json:"status"`
	StartedAt  string    `json:"started_at"`
	FinishedAt string    `json:"finished_at"`
	CreatedAt  string    `json:"created_at"`
}

type ScanCheckpoint struct {
	ID              int    `json:"id"`
	ScanID          int64  `json:"scan_id"`
	Stage           int    `json:"stage"`
	CompletedTools  string `json:"completed_tools"`
	CompletedTargets string `json:"completed_targets"`
}

type FindingModel = types.Finding
