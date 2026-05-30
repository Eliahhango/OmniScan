package scanner

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/Eliahhango/OmniScan/pkg/types"
)

type DuplicateDetector struct {
	db     *sql.DB
	mu     sync.Mutex
	seen   map[string]bool
}

func NewDuplicateDetector(dbPath string) (*DuplicateDetector, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open dedup db: %w", err)
	}

	detector := &DuplicateDetector{
		db:   db,
		seen: make(map[string]bool),
	}

	if err := detector.migrate(); err != nil {
		return nil, err
	}

	if err := detector.loadSeen(); err != nil {
		return nil, err
	}

	return detector, nil
}

func (d *DuplicateDetector) migrate() error {
	_, err := d.db.Exec(`CREATE TABLE IF NOT EXISTS seen_cves (
		cve TEXT PRIMARY KEY,
		first_seen DATETIME,
		program TEXT,
		status TEXT DEFAULT 'pending'
	)`)
	return err
}

func (d *DuplicateDetector) loadSeen() error {
	rows, err := d.db.Query("SELECT cve FROM seen_cves")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			return err
		}
		d.seen[cve] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return nil
}

func (d *DuplicateDetector) IsDuplicate(cve string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.seen[cve]
}

func (d *DuplicateDetector) MarkSeen(cve, program string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.seen[cve] {
		return nil
	}

	_, err := d.db.Exec(
		"INSERT INTO seen_cves (cve, first_seen, program) VALUES (?, ?, ?)",
		cve, time.Now(), program,
	)
	if err != nil {
		return err
	}
	d.seen[cve] = true
	return nil
}

func (d *DuplicateDetector) Close() error {
	return d.db.Close()
}

type ProgramScopeLoader struct {
	program string
}

func NewProgramScopeLoader(program string) *ProgramScopeLoader {
	return &ProgramScopeLoader{program: program}
}

func (p *ProgramScopeLoader) LoadScope() ([]string, error) {
	switch p.program {
	case "hackerone":
		return p.loadHackerOne()
	case "bugcrowd":
		return p.loadBugcrowd()
	default:
		return p.loadGeneric()
	}
}

func (p *ProgramScopeLoader) loadHackerOne() ([]string, error) {
	return nil, fmt.Errorf("hackerone API integration: placeholder - implement with HackerOne GraphQL API")
}

func (p *ProgramScopeLoader) loadBugcrowd() ([]string, error) {
	return nil, fmt.Errorf("bugcrowd API integration: placeholder - implement with Bugcrowd API")
}

func (p *ProgramScopeLoader) loadGeneric() ([]string, error) {
	return nil, nil
}

type WeaponizationCheck struct{}

func NewWeaponizationCheck() *WeaponizationCheck {
	return &WeaponizationCheck{}
}

func (w *WeaponizationCheck) HasPublicPoC(finding *types.Finding) bool {
	return false
}

func (w *WeaponizationCheck) CheckExploitDB(cve string) bool {
	return false
}

type RateLimiter struct {
	mu       sync.Mutex
	limits   map[string]*programRate
	defaultRPS float64
}

type programRate struct {
	rps      float64
	lastCall time.Time
	tokens   float64
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limits:    make(map[string]*programRate),
		defaultRPS: 5.0,
	}
}

func (r *RateLimiter) SetRate(program string, requestsPerSecond float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.limits[program] = &programRate{
		rps:    requestsPerSecond,
		tokens: requestsPerSecond,
	}
}

func (r *RateLimiter) Wait(program string) {
	r.mu.Lock()
	rate, ok := r.limits[program]
	if !ok {
		rate = &programRate{
			rps:    r.defaultRPS,
			tokens: r.defaultRPS,
		}
		r.limits[program] = rate
	}

	now := time.Now()
	elapsed := now.Sub(rate.lastCall).Seconds()
	rate.lastCall = now
	rate.tokens += elapsed * rate.rps
	if rate.tokens > rate.rps {
		rate.tokens = rate.rps
	}

	if rate.tokens < 1 {
		sleepTime := time.Duration((1 - rate.tokens) / rate.rps * float64(time.Second))
		r.mu.Unlock()
		time.Sleep(sleepTime)
		return
	}

	rate.tokens--
	r.mu.Unlock()
}
