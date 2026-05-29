package recon

import "fmt"

type ProbingResult struct {
	URL       string
	StatusCode int
	Title     string
	Tech      []string
}

func (r *ProbingResult) String() string {
	return fmt.Sprintf("%s [%d] %s", r.URL, r.StatusCode, r.Title)
}
