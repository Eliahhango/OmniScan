# OmniScan - Windows Installation Script

Write-Host "OmniScan - Unified Vulnerability Hunting Platform" -ForegroundColor Cyan
Write-Host "Installing..." -ForegroundColor Cyan

# Check for Go
$goVersion = go version 2>$null
if (-not $goVersion) {
    Write-Host "Error: Go is not installed. Download from https://go.dev/dl/" -ForegroundColor Red
    exit 1
}

# Parse Go version
if ($goVersion -match 'go(\d+\.\d+)') {
    $ver = [version]($matches[1] + ".0")
    if ($ver -lt [version]"1.26.0") {
        Write-Host "Error: Go 1.26+ required (found $($matches[1])). Please upgrade." -ForegroundColor Red
        exit 1
    }
}

# Install omniscan
Write-Host "Installing omniscan..." -ForegroundColor Yellow
go install github.com/Eliahhango/OmniScan/cmd/omniscan@latest
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: go install failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "OmniScan installed successfully!" -ForegroundColor Green
Write-Host "Run 'omniscan tui' to launch the interactive TUI" -ForegroundColor Green
Write-Host "Run 'omniscan version' to check the installed version" -ForegroundColor Green
Write-Host "Run 'omniscan update' to update OmniScan and all tools" -ForegroundColor Green
Write-Host ""
Write-Host "Note: Scanning tools (nuclei, nmap, etc.) must be installed separately." -ForegroundColor Yellow
Write-Host "Run 'omniscan setup' to attempt automatic installation of Go-based tools." -ForegroundColor Yellow
