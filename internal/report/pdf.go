package report

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type PDFGenerator struct {
	OutputDir string
}

func NewPDFGenerator(outputDir string) *PDFGenerator {
	return &PDFGenerator{OutputDir: outputDir}
}

func findChrome() string {
	candidates := []string{
		"google-chrome",
		"google-chrome-stable",
		"chromium",
		"chromium-browser",
		"chrome",
		"google-chrome.exe",
		"chrome.exe",
		"MicrosoftEdge.exe",
		"msedge.exe",
	}
	for _, name := range candidates {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	winPaths := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("LocalAppData"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
	}
	for _, p := range winPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func findWkhtmltopdf() string {
	candidates := []string{
		"wkhtmltopdf",
		"wkhtmltopdf.exe",
	}
	for _, name := range candidates {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	winPaths := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "wkhtmltopdf", "bin", "wkhtmltopdf.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "wkhtmltopdf", "bin", "wkhtmltopdf.exe"),
	}
	for _, p := range winPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func (p *PDFGenerator) Generate(htmlPath string) (string, string, error) {
	pdfPath := filepath.Join(p.OutputDir, strings.TrimSuffix(filepath.Base(htmlPath), ".html")+".pdf")
	result, err := GeneratePDFFromHTML(htmlPath, pdfPath)
	return result, "wkhtmltopdf/chrome", err
}

func GeneratePDFFromHTML(htmlPath string, outputPath string) (string, error) {
	if wk := findWkhtmltopdf(); wk != "" {
		cmd := exec.Command(wk, "--enable-local-file-access", htmlPath, outputPath)
		if output, err := cmd.CombinedOutput(); err == nil {
			return outputPath, nil
		} else {
			return "", fmt.Errorf("wkhtmltopdf failed: %w\nOutput: %s", err, string(output))
		}
	}

	if ch := findChrome(); ch != "" {
		absHTML, _ := filepath.Abs(htmlPath)
		absPDF, _ := filepath.Abs(outputPath)
		cmd := exec.Command(ch,
			"--headless",
			"--disable-gpu",
			"--disable-software-rasterizer",
			"--print-to-pdf="+absPDF,
			absHTML,
		)
		if output, err := cmd.CombinedOutput(); err == nil {
			return outputPath, nil
		} else {
			return "", fmt.Errorf("chrome headless failed: %w\nOutput: %s", err, string(output))
		}
	}

	return "", fmt.Errorf("PDF generation requires wkhtmltopdf or chrome/chromium/edge headless: convert %s to %s", htmlPath, outputPath)
}
