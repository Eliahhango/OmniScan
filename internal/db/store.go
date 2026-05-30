package db

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/Eliahhango/OmniScan/pkg/types"
)

type Store struct {
	db  *sql.DB
	key []byte
}

func New(path string, passphrase string) (*Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	var key []byte
	if passphrase != "" {
		key, err = deriveKey(passphrase, path)
	} else {
		key, err = loadOrCreateKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("load encryption key: %w", err)
	}
	store := &Store{db: db, key: key}
	if err := store.migrate(); err != nil {
		return nil, fmt.Errorf("migrate db: %w", err)
	}
	if fi, err := os.Stat(path); err == nil {
		os.Chmod(path, fi.Mode()|0600)
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target TEXT NOT NULL,
			scope TEXT,
			stage INTEGER DEFAULT 0,
			progress REAL DEFAULT 0,
			status TEXT DEFAULT 'pending',
			started_at DATETIME,
			finished_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS findings (
			id TEXT PRIMARY KEY,
			scan_id INTEGER NOT NULL,
			title TEXT,
			description TEXT,
			severity TEXT,
			cvss REAL DEFAULT 0,
			cve TEXT,
			cwe TEXT,
			owasp2025 TEXT,
			affected_url TEXT,
			affected_param TEXT,
			payload TEXT,
			proof TEXT,
			remediation TEXT,
			tool_source TEXT,
			timestamp DATETIME,
			cvss_vector TEXT,
			epss REAL DEFAULT 0,
			false_positive INTEGER DEFAULT 0,
			bounty_platforms TEXT,
			FOREIGN KEY (scan_id) REFERENCES scans(id)
		)`,
		`CREATE TABLE IF NOT EXISTS scan_checkpoints (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			stage INTEGER DEFAULT 0,
			completed_tools TEXT,
			completed_targets TEXT,
			state_data BLOB,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans(id)
		)`,
		`CREATE TABLE IF NOT EXISTS scan_states (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL UNIQUE,
			state_json TEXT NOT NULL,
			completed_tools TEXT,
			findings_count INTEGER DEFAULT 0,
			duration_seconds REAL DEFAULT 0,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (scan_id) REFERENCES scans(id)
		)`,
	}
	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate query: %w", err)
		}
	}
	return nil
}

const maxTargetLen = 1024
const maxFieldLen = 4096

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

func (s *Store) CreateScan(target string, scope []string) (int64, error) {
	target = truncate(target, maxTargetLen)
	for i := range scope {
		scope[i] = truncate(scope[i], maxTargetLen)
	}
	result, err := s.db.Exec(
		`INSERT INTO scans (target, scope, status, started_at) VALUES (?, ?, 'running', ?)`,
		target, joinStrings(scope), time.Now(),
	)
	if err != nil {
		return 0, fmt.Errorf("create scan: %w", err)
	}
	return result.LastInsertId()
}

func (s *Store) SaveFinding(scanID int64, f *types.Finding) error {
	f.ID = truncate(f.ID, maxFieldLen)
	f.Title = truncate(f.Title, maxFieldLen)
	f.Description = truncate(f.Description, maxFieldLen)
	f.CVE = truncate(f.CVE, maxFieldLen)
	f.OWASP2025 = truncate(f.OWASP2025, maxFieldLen)
	f.AffectedURL = truncate(f.AffectedURL, maxTargetLen)
	f.AffectedParam = truncate(f.AffectedParam, maxFieldLen)
	f.Remediation = truncate(f.Remediation, maxFieldLen)
	f.ToolSource = truncate(f.ToolSource, maxFieldLen)
	f.CVSSVector = truncate(f.CVSSVector, maxFieldLen)
	for i := range f.CWE {
		f.CWE[i] = truncate(f.CWE[i], maxFieldLen)
	}
	for i := range f.BountyPlatforms {
		f.BountyPlatforms[i] = truncate(f.BountyPlatforms[i], maxFieldLen)
	}
	encPayload, err := encrypt(f.Payload, s.key)
	if err != nil {
		return fmt.Errorf("encrypt payload: %w", err)
	}
	encProof, err := encrypt(f.Proof, s.key)
	if err != nil {
		return fmt.Errorf("encrypt proof: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO findings (
			id, scan_id, title, description, severity, cvss, cve, cwe,
			owasp2025, affected_url, affected_param, payload, proof,
			remediation, tool_source, timestamp, cvss_vector, epss,
			false_positive, bounty_platforms
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, scanID, f.Title, f.Description, string(f.Severity), f.CVSS,
		f.CVE, joinStrings(f.CWE), f.OWASP2025, f.AffectedURL, f.AffectedParam,
		encPayload, encProof, f.Remediation, f.ToolSource, f.Timestamp,
		f.CVSSVector, f.EPSS, boolToInt(f.FalsePositive), joinStrings(f.BountyPlatforms),
	)
	return err
}

func (s *Store) GetFindings(scanID int64) ([]types.Finding, error) {
	rows, err := s.db.Query(
		`SELECT id, title, description, severity, cvss, cve, cwe,
		owasp2025, affected_url, affected_param, payload, proof,
		remediation, tool_source, timestamp, cvss_vector, epss,
		false_positive, bounty_platforms
		FROM findings WHERE scan_id = ? ORDER BY cvss DESC`, scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []types.Finding
	for rows.Next() {
		var f types.Finding
		var cwe, bountyPlatforms string
		var falsePositive int
		err := rows.Scan(
			&f.ID, &f.Title, &f.Description, &f.Severity, &f.CVSS,
			&f.CVE, &cwe, &f.OWASP2025, &f.AffectedURL, &f.AffectedParam,
			&f.Payload, &f.Proof, &f.Remediation, &f.ToolSource,
			&f.Timestamp, &f.CVSSVector, &f.EPSS,
			&falsePositive, &bountyPlatforms,
		)
		if err != nil {
			return nil, err
		}
		f.FalsePositive = falsePositive != 0
		f.CWE = splitStrings(cwe)
		f.BountyPlatforms = splitStrings(bountyPlatforms)
		decPayload, err := decrypt(f.Payload, s.key)
		if err == nil {
			f.Payload = decPayload
		}
		decProof, err := decrypt(f.Proof, s.key)
		if err == nil {
			f.Proof = decProof
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

func (s *Store) SaveCheckpoint(scanID int64, stage int, completedTools, completedTargets string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO scan_checkpoints
		(scan_id, stage, completed_tools, completed_targets, updated_at)
		VALUES (?, ?, ?, ?, ?)`,
		scanID, stage, completedTools, completedTargets, time.Now(),
	)
	return err
}

func (s *Store) GetCheckpoint(scanID int64) (stage int, completedTools string, err error) {
	err = s.db.QueryRow(
		`SELECT stage, completed_tools FROM scan_checkpoints WHERE scan_id = ?`,
		scanID,
	).Scan(&stage, &completedTools)
	return
}

func (s *Store) UpdateScanStatus(scanID int64, status string) error {
	_, err := s.db.Exec(
		`UPDATE scans SET status = ?, finished_at = ? WHERE id = ?`,
		status, time.Now(), scanID,
	)
	return err
}

type ScanRecord struct {
	ID        int64     `json:"id"`
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	Findings  int       `json:"findings,omitempty"`
}

func (s *Store) ListScans() ([]ScanRecord, error) {
	rows, err := s.db.Query(`
		SELECT s.id, s.target, s.status, s.created_at,
			(SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) as findings_count
		FROM scans s ORDER BY s.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []ScanRecord
	for rows.Next() {
		var r ScanRecord
		if err := rows.Scan(&r.ID, &r.Target, &r.Status, &r.CreatedAt, &r.Findings); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func (s *Store) GetScan(scanID int64) (*ScanRecord, error) {
	var r ScanRecord
	err := s.db.QueryRow(`
		SELECT s.id, s.target, s.status, s.created_at,
			(SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) as findings_count
		FROM scans s WHERE s.id = ?`, scanID,
	).Scan(&r.ID, &r.Target, &r.Status, &r.CreatedAt, &r.Findings)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func joinStrings(s []string) string {
	result := ""
	for i, v := range s {
		if i > 0 {
			result += ","
		}
		result += v
	}
	return result
}

func splitStrings(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

type ScanState struct {
	CompletedTools []string `json:"completed_tools"`
	FindingsCount  int      `json:"findings_count"`
	Duration       float64  `json:"duration_seconds"`
	Stage          int      `json:"stage"`
}

func (s *Store) SaveScanState(scanID int64, state ScanState) error {
	toolsStr := joinStrings(state.CompletedTools)
	_, err := s.db.Exec(
		`INSERT INTO scan_states (scan_id, state_json, completed_tools, findings_count, duration_seconds, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id) DO UPDATE SET
			state_json = excluded.state_json,
			completed_tools = excluded.completed_tools,
			findings_count = excluded.findings_count,
			duration_seconds = excluded.duration_seconds,
			updated_at = excluded.updated_at`,
		scanID, fmt.Sprintf(`{"stage":%d}`, state.Stage), toolsStr,
		state.FindingsCount, state.Duration, time.Now(),
	)
	return err
}

func (s *Store) LoadScanState(scanID int64) (*ScanState, error) {
	var stateJSON, completedTools string
	var findingsCount int
	var duration float64

	err := s.db.QueryRow(
		`SELECT state_json, completed_tools, findings_count, duration_seconds
		FROM scan_states WHERE scan_id = ?`, scanID,
	).Scan(&stateJSON, &completedTools, &findingsCount, &duration)
	if err != nil {
		return nil, err
	}

	state := &ScanState{
		FindingsCount: findingsCount,
		Duration:      duration,
		CompletedTools: splitStrings(completedTools),
	}
	return state, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
