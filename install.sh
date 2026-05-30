#!/bin/bash
# OmniScan - One-command installer (Ubuntu/Debian)

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}OmniScan - Unified Vulnerability Hunting Platform${NC}"
echo ""

# --- Install Go 1.26 if missing ---
if ! command -v go &> /dev/null; then
    echo -e "${CYAN}[1/6] Installing Go 1.26...${NC}"
    wget -q https://go.dev/dl/go1.26.3.linux-amd64.tar.gz -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
else
    GO_VER=$(go version | sed -n 's/.*go\([0-9]\+\.[0-9]\+\).*/\1/p')
    echo -e "${GREEN}[1/6] Go $GO_VER already installed${NC}"
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
fi

# --- System packages ---
echo -e "${CYAN}[2/6] Installing system packages (nmap, nikto, python3)...${NC}"
sudo apt update -qq 2>/dev/null || true
sudo apt install -y -qq nmap nikto python3-pip git pipx 2>/dev/null || echo -e "${RED}Warning: some apt packages failed (nmap/nikto may need manual install)${NC}"

# --- pipx tools (pipx sidesteps Ubuntu's PEP 668 externally-managed-environment) ---
echo -e "${CYAN}[3/6] Installing semgrep via pipx...${NC}"
pipx install semgrep -q 2>/dev/null || echo -e "${RED}Warning: semgrep install failed (try: pipx install semgrep)${NC}"

# --- Go tools ---
echo -e "${CYAN}[4/6] Installing security tools (nuclei, subfinder, httpx, katana, ffuf, trufflehog, gau, gospider, gobuster)...${NC}"
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || echo -e "${RED}Warning: nuclei install failed${NC}"
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || echo -e "${RED}Warning: subfinder install failed${NC}"
go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || echo -e "${RED}Warning: httpx install failed${NC}"
go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || echo -e "${RED}Warning: katana install failed${NC}"
go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || echo -e "${RED}Warning: ffuf install failed${NC}"
go install github.com/trufflesecurity/trufflehog/v3@latest 2>/dev/null || echo -e "${RED}Warning: trufflehog install failed${NC}"
go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || echo -e "${RED}Warning: gau install failed${NC}"
go install github.com/jaeles-project/gospider@latest 2>/dev/null || echo -e "${RED}Warning: gospider install failed${NC}"
go install github.com/OJ/gobuster/v3@latest 2>/dev/null || echo -e "${RED}Warning: gobuster install failed${NC}"

# --- Build OmniScan ---
echo -e "${CYAN}[5/6] Building OmniScan...${NC}"
if [ ! -d "$HOME/OmniScan" ]; then
    git clone https://github.com/Eliahhango/OmniScan.git "$HOME/OmniScan" 2>/dev/null
fi
cd "$HOME/OmniScan" && git pull 2>/dev/null
go build -o "$HOME/go/bin/omniscan" ./cmd/omniscan/ 2>/dev/null || { echo -e "${RED}OmniScan build failed${NC}"; exit 1; }

# --- Verify ---
echo -e "${CYAN}[6/6] Verifying installation...${NC}"
TOOLS="omniscan nuclei subfinder httpx katana ffuf nmap nikto semgrep trufflehog gau gospider gobuster"
MISSING=0
for tool in $TOOLS; do
    if command -v "$tool" &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${RED}✗${NC} $tool (not found — may need manual install)"
        MISSING=$((MISSING+1))
    fi
done

echo ""
if [ "$MISSING" -eq 0 ]; then
    echo -e "${GREEN}All tools installed successfully!${NC}"
else
    echo -e "${RED}$MISSING tool(s) missing — see above for details${NC}"
fi
echo ""
echo -e "${CYAN}Quick test:${NC} omniscan scan -t elitechwiz.com"
echo -e "${CYAN}Daemon:${NC}   omniscan daemon --listen :9090"
echo -e "${CYAN}Help:${NC}     omniscan"
