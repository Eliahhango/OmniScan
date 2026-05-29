# OmniScan cross-platform build script (Windows)
param([string]$Version = "dev")

$Binary = "omniscan"
$BuildDir = "build"
$Platforms = @(
    @{OS="linux"; Arch="amd64"; Name="omniscan-linux"}
    @{OS="darwin"; Arch="amd64"; Name="omniscan-darwin"}
    @{OS="darwin"; Arch="arm64"; Name="omniscan-darwin-arm64"}
    @{OS="windows"; Arch="amd64"; Name="omniscan-windows.exe"}
)

Write-Host "Building OmniScan $Version for all platforms..." -ForegroundColor Cyan

if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
New-Item -ItemType Directory -Path $BuildDir | Out-Null

foreach ($p in $Platforms) {
    $output = Join-Path $BuildDir $p.Name
    Write-Host "  Building for $($p.OS)/$($p.Arch)..." -ForegroundColor Yellow
    $env:GOOS = $p.OS
    $env:GOARCH = $p.Arch
    $env:CGO_ENABLED = "0"
    $outputPath = if ($p.OS -eq "windows") { "$output.exe" } else { $output }
    go build -ldflags="-s -w -X main.Version=$Version" -o $outputPath ./cmd/omniscan
    if ($LASTEXITCODE -eq 0 -and (Test-Path $outputPath)) {
        $len = (Get-Item $outputPath).Length
        Write-Host "    -> $outputPath ($([math]::Round($len/1KB)) KB)" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Build complete. Binaries in $BuildDir/" -ForegroundColor Cyan
