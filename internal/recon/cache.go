package recon

import (
	"database/sql"
	"encoding/json"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type DNSCache struct {
	mu   sync.RWMutex
	data map[string][]string
	db   *sql.DB
}

func NewDNSCache(dbPath string) (*DNSCache, error) {
	c := &DNSCache{
		data: make(map[string][]string),
	}

	if dbPath != "" {
		db, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			return nil, err
		}
		c.db = db
		if err := c.migrate(); err != nil {
			return nil, err
		}
		if err := c.load(); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (c *DNSCache) migrate() error {
	_, err := c.db.Exec(`CREATE TABLE IF NOT EXISTS dns_cache (
		domain TEXT PRIMARY KEY,
		results TEXT,
		cached_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	return err
}

func (c *DNSCache) load() error {
	rows, err := c.db.Query("SELECT domain, results FROM dns_cache")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var domain, resultsJSON string
		if err := rows.Scan(&domain, &resultsJSON); err != nil {
			return err
		}
		var results []string
		if err := json.Unmarshal([]byte(resultsJSON), &results); err != nil {
			continue
		}
		c.mu.Lock()
		c.data[domain] = results
		c.mu.Unlock()
	}
	return nil
}

func (c *DNSCache) Get(domain string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	results, ok := c.data[domain]
	return results, ok
}

func (c *DNSCache) Set(domain string, results []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[domain] = results

	if c.db != nil {
		resultsJSON, _ := json.Marshal(results)
		c.db.Exec(
			"INSERT OR REPLACE INTO dns_cache (domain, results, cached_at) VALUES (?, ?, ?)",
			domain, string(resultsJSON), time.Now(),
		)
	}
}

func (c *DNSCache) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}
