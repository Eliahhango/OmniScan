package recon

import (
	"database/sql"
	"encoding/json"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type ResultCache struct {
	mu   sync.RWMutex
	data map[string][]string
	db   *sql.DB
}

func NewResultCache(dbPath string) (*ResultCache, error) {
	c := &ResultCache{
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

func (c *ResultCache) migrate() error {
	_, err := c.db.Exec(`CREATE TABLE IF NOT EXISTS result_cache (
		cache_key TEXT PRIMARY KEY,
		results TEXT,
		cached_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	return err
}

func (c *ResultCache) load() error {
	rows, err := c.db.Query("SELECT cache_key, results FROM result_cache")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var key, resultsJSON string
		if err := rows.Scan(&key, &resultsJSON); err != nil {
			return err
		}
		var results []string
		if err := json.Unmarshal([]byte(resultsJSON), &results); err != nil {
			continue
		}
		c.mu.Lock()
		c.data[key] = results
		c.mu.Unlock()
	}
	return nil
}

func (c *ResultCache) Get(key string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	results, ok := c.data[key]
	return results, ok
}

func (c *ResultCache) Set(key string, results []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = results

	if c.db != nil {
		resultsJSON, _ := json.Marshal(results)
		c.db.Exec(
			"INSERT OR REPLACE INTO result_cache (cache_key, results, cached_at) VALUES (?, ?, ?)",
			key, string(resultsJSON), time.Now(),
		)
	}
}

func (c *ResultCache) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}
