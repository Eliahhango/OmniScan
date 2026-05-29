package scanner

import (
	"github.com/Eliahhango/OmniScan/pkg/types"
)

type DistributedScanner struct {
	NodeID string
	Nodes  int
}

func NewDistributedScanner(nodeID string, nodes int) *DistributedScanner {
	if nodes < 1 {
		nodes = 1
	}
	return &DistributedScanner{
		NodeID: nodeID,
		Nodes:  nodes,
	}
}

func (d *DistributedScanner) SplitTargets(targets []string, nodes int) [][]string {
	if nodes <= 0 {
		nodes = 1
	}

	chunks := make([][]string, nodes)
	for i, t := range targets {
		idx := i % nodes
		chunks[idx] = append(chunks[idx], t)
	}

	return chunks
}

func (d *DistributedScanner) MergeResults(results [][]types.Finding) []types.Finding {
	seen := make(map[string]bool)
	var merged []types.Finding

	for _, batch := range results {
		for _, f := range batch {
			if !seen[f.ID] {
				seen[f.ID] = true
				merged = append(merged, f)
			}
		}
	}

	return merged
}
