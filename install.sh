#!/bin/bash
# OmniScan - One-command installer (Ubuntu/Debian)
set -e

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
sudo apt update -qq
sudo apt install -y -qq nmap nikto python3-pip git

# --- pip tools ---
echo -e "${CYAN}[3/6] Installing semgrep...${NC}"
pip3 install semgrep -q

# --- Go tools ---
echo -e "${CYAN}[4/6] Installing security tools (nuclei, subfinder, httpx, katana, ffuf, trufflehog, gau, gospider, gobuster)...${NC}"
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/trufflesecurity/trufflehog/v3@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/OJ/gobuster/v3@latest

# --- Build OmniScan ---
echo -e "${CYAN}[5/6] Building OmniScan...${NC}"
if [ ! -d "$HOME/OmniScan" ]; then
    git clone https://github.com/Eliahhango/OmniScan.git $HOME/OmniScan
fi
cd $HOME/OmniScan && git pull
go build -o $HOME/go/bin/omniscan ./cmd/omniscan/

# --- Verify ---
echo -e "${CYAN}[6/6] Verifying installation...${NC}"
TOOLS="omniscan nuclei subfinder httpx katana ffuf nmap nikto semgrep trufflehog gau gospider gobuster"
MISSING=0
for tool in $TOOLS; do
    if command -v $tool &> /dev/null; then
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
