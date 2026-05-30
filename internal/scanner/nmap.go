package scanner

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Eliahhango/OmniScan/pkg/types"
)

type NmapScanner struct {
	Target   string
	ToolsDir string
	Results  chan types.Finding
}

func NewNmapScanner(target string, toolsDir string) *NmapScanner {
	return &NmapScanner{
		Target:   target,
		ToolsDir: toolsDir,
	}
}

func (n *NmapScanner) Run(ctx context.Context) error {
	if n.Results != nil {
		defer close(n.Results)
	}
	outputFile := filepath.Join(os.TempDir(), fmt.Sprintf("nmap-%d.xml", time.Now().UnixMilli()))
	defer os.Remove(outputFile)

	nmapPath := findTool("nmap", filepath.Join(n.ToolsDir, "nmap"))
	args := []string{
		"-sV", "-sC",
		"--script", "vuln",
		"-oX", outputFile,
		n.Target,
	}

	cmd := exec.CommandContext(ctx, nmapPath, args...)
	if err := cmd.Run(); err != nil {
		if n.Results != nil {
			n.Results <- types.Finding{
				ID:          "nmap-skip",
				Title:       "Nmap not available",
				Description: "Nmap scanner encountered an error and was skipped",
				Severity:    types.SeverityInfo,
				ToolSource:  "nmap",
				Timestamp:   time.Now(),
			}
		}
		return nil
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return nil
	}

	if n.Results != nil {
		parseNmapXML(data, n.Results)
	}
	return nil
}

type nmapPort struct {
	PortID   string `xml:"portid,attr"`
	Protocol string `xml:"protocol,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name    string `xml:"name,attr"`
		Product string `xml:"product,attr"`
		Version string `xml:"version,attr"`
	} `xml:"service"`
}

type nmapHost struct {
	Address struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames struct {
		Hostname []struct {
			Name string `xml:"name,attr"`
			Type string `xml:"type,attr"`
		} `xml:"hostname"`
	} `xml:"hostnames"`
	Ports struct {
		Port []nmapPort `xml:"port"`
	} `xml:"ports"`
}

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Host    []nmapHost `xml:"host"`
}

func parseNmapXML(data []byte, results chan<- types.Finding) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return
	}

	for _, h := range run.Host {
		hostname := h.Address.Addr
		if len(h.Hostnames.Hostname) > 0 {
			hostname = h.Hostnames.Hostname[0].Name
		}

		for _, p := range h.Ports.Port {
			if p.State.State != "open" {
				continue
			}
			results <- types.Finding{
				ID:          fmt.Sprintf("nmap-%s-%s", h.Address.Addr, p.PortID),
				Title:       fmt.Sprintf("Open Port %s/%s - %s", p.PortID, p.Protocol, p.Service.Name),
				Description: fmt.Sprintf("Port %s/%s is open on %s (%s) running %s %s", p.PortID, p.Protocol, h.Address.Addr, hostname, p.Service.Product, p.Service.Version),
				Severity:    types.SeverityMedium,
				AffectedURL: fmt.Sprintf("%s:%s", h.Address.Addr, p.PortID),
				ToolSource:  "nmap",
				Timestamp:   time.Now(),
			}
		}
	}
}
