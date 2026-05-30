#!/bin/bash
# OmniScan - One-command installer (Ubuntu/Debian/Kali)

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
STEP=0

# --- Spinner + elapsed time for long-running commands ---
run_spinner() {
    local label="$1"; shift
    STEP=$((STEP+1))
    echo -e "${CYAN}[$STEP/6]${NC} $label"
    local start=$SECONDS
    "$@" >/dev/null 2>&1 &
    local pid=$!
    local spin='-\|/'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${spin:i++%4:1}  %ds" $((SECONDS - start))
        sleep 0.2
    done
    wait "$pid"
    local rc=$?
    if [ $rc -eq 0 ]; then
        printf "\r  ${GREEN}OK${NC}  %ds\n" $((SECONDS - start))
    else
        printf "\r  ${RED}FAIL${NC} %ds\n" $((SECONDS - start))
    fi
    return $rc
}

echo -e "${CYAN}OmniScan - Unified Vulnerability Hunting Platform${NC}"
echo ""

# --- Step 1: Go ---
if ! command -v go &> /dev/null; then
    echo -e "${CYAN}[$((++STEP))/6]${NC} Installing Go 1.26..."
    local start=$SECONDS
    wget -q https://go.dev/dl/go1.26.3.linux-amd64.tar.gz -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    printf "  ${GREEN}OK${NC}  %ds\n" $((SECONDS - start))
else
    GO_VER=$(go version | sed -n 's/.*go\([0-9]\+\.[0-9]\+\).*/\1/p')
    echo -e "${GREEN}[$((++STEP))/6] Go $GO_VER already installed${NC}"
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
fi

# --- Step 2: apt packages (show real-time apt progress) ---
echo -e "${CYAN}[$((++STEP))/6]${NC} Installing system packages (nmap, nikto, python3, pipx)..."
sudo apt update -qq 2>/dev/null || true
sudo apt install -y nmap nikto python3-pip git pipx 2>&1 | tail -n 1

# --- Step 3: semgrep via pipx ---
run_spinner "Installing semgrep via pipx..." pipx install semgrep -q || \
    echo -e "  ${YELLOW}semgrep install had warnings${NC}"

# --- Step 4: Go tools ---
echo -e "${CYAN}[$((++STEP))/6]${NC} Installing security tools (nuclei, subfinder, httpx, katana, ffuf, trufflehog, gau, gospider, gobuster)..."
GO_TOOLS=(
    "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
    "ffuf:github.com/ffuf/ffuf/v2@latest"
    "trufflehog:github.com/trufflesecurity/trufflehog/v3@latest"
    "gau:github.com/lc/gau/v2/cmd/gau@latest"
    "gospider:github.com/jaeles-project/gospider@latest"
    "gobuster:github.com/OJ/gobuster/v3@latest"
)
for entry in "${GO_TOOLS[@]}"; do
    name="${entry%%:*}"
    pkg="${entry#*:}"
    start=$SECONDS
    go install "$pkg" >/dev/null 2>&1 &
    pid=$!
    spin='-\|/'
    i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${spin:i++%4:1}  %-20s %ds" "$name" $((SECONDS - start))
        sleep 0.2
    done
    wait "$pid"
    if [ $? -eq 0 ]; then
        printf "\r  ${GREEN}OK${NC}  %-20s %ds\n" "$name" $((SECONDS - start))
    else
        printf "\r  ${RED}FAIL${NC} %-20s %ds\n" "$name" $((SECONDS - start))
    fi
done

# --- Step 5: Build OmniScan ---
echo -e "${CYAN}[$((++STEP))/6]${NC} Building OmniScan..."
if [ ! -d "$HOME/OmniScan" ]; then
    git clone https://github.com/Eliahhango/OmniScan.git "$HOME/OmniScan" >/dev/null 2>&1
fi
cd "$HOME/OmniScan" && git pull >/dev/null 2>&1
run_spinner "Compiling binary..." go build -o "$HOME/go/bin/omniscan" ./cmd/omniscan/ || \
    { echo -e "  ${RED}OmniScan build failed${NC}"; exit 1; }

# --- Step 6: Verify ---
echo -e "${CYAN}[$((++STEP))/6]${NC} Verifying installation..."
TOOLS="omniscan nuclei subfinder httpx katana ffuf nmap nikto semgrep trufflehog gau gospider gobuster"
MISSING=0
for tool in $TOOLS; do
    if command -v "$tool" &> /dev/null; then
        echo -e "  ${GREEN}OK${NC}  $tool"
    else
        echo -e "  ${RED}MISS${NC} $tool"
        MISSING=$((MISSING+1))
    fi
done

echo ""
if [ "$MISSING" -eq 0 ]; then
    echo -e "${GREEN}All tools installed successfully!${NC}"
else
    echo -e "${RED}$MISSING tool(s) missing — see above${NC}"
fi
echo ""
echo -e "${CYAN}Quick test:${NC} omniscan scan -t elitechwiz.com"
echo -e "${CYAN}Daemon:${NC}   omniscan daemon --listen :9090"
echo -e "${CYAN}Help:${NC}     omniscan"
