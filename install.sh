#!/bin/bash
# OmniScan - One-command installation
set -e

echo "OmniScan - Unified Vulnerability Hunting Platform"
echo "Installing..."

# Check for Go
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go 1.26+ first."
    exit 1
fi

# Check Go version (minimum 1.26)
GO_VERSION=$(go version | sed -n 's/.*go\([0-9]\+\.[0-9]\+\).*/\1/p')
GO_MAJOR=$(echo "$GO_VERSION" | cut -d. -f1)
GO_MINOR=$(echo "$GO_VERSION" | cut -d. -f2)
if [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 26 ]; }; then
    echo "Error: Go 1.26+ required (found $GO_VERSION). Please upgrade."
    exit 1
fi

# Install omniscan
go install github.com/Eliahhango/OmniScan/cmd/omniscan@latest

# Install all 13 tools
omniscan setup

echo ""
echo "OmniScan installed successfully!"
echo "Run 'omniscan tui' to launch the interactive TUI"
