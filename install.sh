#!/bin/bash
# OmniScan - One-command installation
set -e

echo "OmniScan - Unified Vulnerability Hunting Platform"
echo "Installing..."

# Check for Go
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go first."
    exit 1
fi

# Install omniscan
go install github.com/Eliahhango/OmniScan/cmd/omniscan@latest

# Install all 13 tools
omniscan setup

echo ""
echo "OmniScan installed successfully!"
echo "Run 'omniscan tui' to launch the interactive TUI"
