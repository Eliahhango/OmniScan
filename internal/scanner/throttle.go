package scanner

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"
)

type SmartThrottler struct {
	mu      sync.RWMutex
	domains map[string]*domainLimiter
	rps     float64
}

type domainLimiter struct {
	mu         sync.Mutex
	timestamps []time.Time
	backoff    time.Duration
}

func NewSmartThrottler(rps float64) *SmartThrottler {
	if rps <= 0 {
		rps = 10
	}
	return &SmartThrottler{
		domains: make(map[string]*domainLimiter),
		rps:     rps,
	}
}

func (st *SmartThrottler) Wait(ctx context.Context, domain string) error {
	st.mu.Lock()
	dl, ok := st.domains[domain]
	if !ok {
		dl = &domainLimiter{}
		st.domains[domain] = dl
	}
	st.mu.Unlock()

	dl.mu.Lock()

	now := time.Now()

	if dl.backoff > 0 && len(dl.timestamps) > 0 {
		lastTime := dl.timestamps[len(dl.timestamps)-1]
		if now.Sub(lastTime) < dl.backoff {
			sleepTime := dl.backoff - now.Sub(lastTime)
			dl.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(sleepTime):
			}
			dl.mu.Lock()
		}
		dl.backoff = 0
	}

	windowStart := now.Add(-1 * time.Second)
	var valid []time.Time
	for _, t := range dl.timestamps {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}
	dl.timestamps = valid

	if len(dl.timestamps) >= int(st.rps) {
		waitTime := time.Until(dl.timestamps[0].Add(1 * time.Second))
		dl.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
		}
		dl.mu.Lock()
	}

	dl.timestamps = append(dl.timestamps, time.Now())
	dl.mu.Unlock()
	return nil
}

func (st *SmartThrottler) DetectWAF(domain string, statusCode int) {
	if statusCode != http.StatusTooManyRequests && statusCode != http.StatusServiceUnavailable {
		return
	}

	st.mu.RLock()
	dl, ok := st.domains[domain]
	st.mu.RUnlock()

	if !ok {
		st.mu.Lock()
		dl = &domainLimiter{}
		st.domains[domain] = dl
		st.mu.Unlock()
	}

	dl.mu.Lock()
	defer dl.mu.Unlock()
	if dl.backoff == 0 {
		dl.backoff = 1 * time.Second
	} else {
		dl.backoff *= 2
		if dl.backoff > 60*time.Second {
			dl.backoff = 60 * time.Second
		}
	}
}

func ExtractDomain(targetURL string) string {
	targetURL = strings.TrimPrefix(targetURL, "https://")
	targetURL = strings.TrimPrefix(targetURL, "http://")
	parts := strings.Split(targetURL, "/")
	return parts[0]
}
