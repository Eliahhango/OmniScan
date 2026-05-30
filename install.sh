#!/bin/bash
# OmniScan - One-command installer (Ubuntu/Debian/Kali)

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
GLOBAL_START=$SECONDS
STEP=0

fmt_time() { local s=$1; printf "%dm%02ds" $((s/60)) $((s%60)); }

# Monitor Go module cache to estimate download speed + size
cache_start=0
init_cache_monitor() {
    local dir="$(go env GOMODCACHE 2>/dev/null)/cache/download"
    if [ -d "$dir" ]; then
        cache_start=$(du -sb "$dir" 2>/dev/null | cut -f1)
    else
        cache_start=0
    fi
}

read_cache() {
    local dir="$(go env GOMODCACHE 2>/dev/null)/cache/download"
    if [ -d "$dir" ]; then
        du -sb "$dir" 2>/dev/null | cut -f1
    else
        echo "$cache_start"
    fi
}

echo -e "${CYAN}OmniScan - Unified Vulnerability Hunting Platform${NC}"
echo ""

# ────────────────────────────────────────────── Step 1: Go ──────────────────────────────────────────────
if ! command -v go &> /dev/null; then
    echo -e "${CYAN}[$((++STEP))/6]${NC} Installing Go 1.26..."
    start=$SECONDS
    wget -q https://go.dev/dl/go1.26.3.linux-amd64.tar.gz -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    printf "  ${GREEN}OK${NC}  %s\n" "$(fmt_time $((SECONDS - start)))"
else
    GO_VER=$(go version | sed -n 's/.*go\([0-9]\+\.[0-9]\+\).*/\1/p')
    echo -e "${GREEN}[$((++STEP))/6] Go $GO_VER already installed${NC}"
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
fi

# ────────────────────────────────────────── Step 2: apt packages ──────────────────────────────────────────
echo -e "${CYAN}[$((++STEP))/6]${NC} Installing system packages (nmap, nikto, python3, pipx)..."
sudo apt update -qq 2>/dev/null || true
sudo apt install -y nmap nikto python3-pip git pipx 2>&1 | tail -n 1

# ───────────────────────────────────────────── Step 3: semgrep ─────────────────────────────────────────────
echo -e "${CYAN}[$((++STEP))/6]${NC} Installing semgrep via pipx..."
sem_start=$SECONDS
pipx install semgrep -q >/dev/null 2>&1 &
pid=$!; spin='-\|/'; i=0
while kill -0 "$pid" 2>/dev/null; do
    printf "\r  \033[K${spin:i++%4:1}  semgrep  %s" "$(fmt_time $((SECONDS - sem_start)))"
    sleep 0.2
done
wait "$pid"; rc=$?
if [ $rc -eq 0 ]; then
    # Symlink semgrep into global PATH (pipx installs to ~/.local/bin which may not be in root's PATH)
    SEMGREP_BIN="$(find /root/.local/bin /home -name semgrep -type f 2>/dev/null | head -1)"
    [ -z "$SEMGREP_BIN" ] && SEMGREP_BIN="$HOME/.local/bin/semgrep"
    [ -f "$SEMGREP_BIN" ] && sudo ln -sf "$SEMGREP_BIN" /usr/local/bin/semgrep 2>/dev/null
    printf "\r  \033[K${GREEN}OK${NC}   semgrep  %s  elapsed:%s\n" "$(fmt_time $((SECONDS - sem_start)))" "$(fmt_time $((SECONDS - GLOBAL_START)))"
else
    printf "\r  \033[K${YELLOW}WARN${NC}  semgrep  %s  (pipx install semgrep manually)\n" "$(fmt_time $((SECONDS - sem_start)))"
fi

# ─────────────────────────────────────────── Step 4: Go tools ────────────────────────────────────────────
echo -e "${CYAN}[$((++STEP))/6]${NC} Installing 8 security tools via go install..."
GO_TOOLS=(
    "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
    "ffuf:github.com/ffuf/ffuf/v2@latest"
    "gau:github.com/lc/gau/v2/cmd/gau@latest"
    "gospider:github.com/jaeles-project/gospider@latest"
    "gobuster:github.com/OJ/gobuster/v3@latest"
)

init_cache_monitor
TOTAL=${#GO_TOOLS[@]}
COMPLETED=0
cache_prev=$cache_start

for entry in "${GO_TOOLS[@]}"; do
    name="${entry%%:*}"
    pkg="${entry#*:}"
    start=$SECONDS
    errf="/tmp/omniscan_${name}_err.txt"

    go install "$pkg" >/dev/null 2>"$errf" &
    pid=$!

    spin='-\|/'
    i=0
    peak_speed=0
    while kill -0 "$pid" 2>/dev/null; do
        e=$((SECONDS - start))
        cmp=$((COMPLETED + 1))

        # Check cache every ~1s for download tracking
        if [ $((i % 5)) -eq 0 ]; then
            cur=$(read_cache)
            dl=$(( (cur - cache_start) / 1048576 ))
            dl_this=$(( (cur - cache_prev) / 1048576 ))
            speed=$dl_this
            [ "$speed" -gt "$peak_speed" ] 2>/dev/null && peak_speed=$speed
            cache_prev=$cur
        fi

        # Running average ETA
        total_sec=$((SECONDS - GLOBAL_START))
        avg=$(( COMPLETED > 0 ? (total_sec - e) / COMPLETED : total_sec / (cmp) ))
        rem=$(( (TOTAL - cmp) * (avg > 0 ? avg : 30) ))

        printf "\r  \033[K${spin:i++%4:1}  %-12s %s  +%dM" "$name" "$(fmt_time $e)" "$dl"
        printf "  %dM/s" "$peak_speed"
        printf "  [%d/%d]  eta %s  total %s" "$cmp" "$TOTAL" "$(fmt_time $rem)" "$(fmt_time $total_sec)"
        sleep 0.2
    done

    wait "$pid"
    rc=$?
    e=$((SECONDS - start))
    COMPLETED=$((COMPLETED + 1))

    # Final cache read
    cur=$(read_cache)
    dl=$(( (cur - cache_start) / 1048576 ))

    if [ $rc -eq 0 ]; then
        printf "\r  \033[K${GREEN}OK${NC}  %-12s %s  +%dM  [%d/%d]  elapsed %s\n" \
            "$name" "$(fmt_time $e)" "$dl" "$COMPLETED" "$TOTAL" "$(fmt_time $((SECONDS - GLOBAL_START)))"
        rm -f "$errf"
    else
        # Print error
        err=$(head -8 "$errf" 2>/dev/null | tail -5 | tr '\n' ';')
        [ -z "$err" ] && err="unknown error (check $errf)"
        printf "\r  \033[K${RED}FAIL${NC} %-12s %s  [%d/%d]\n  \033[K${RED}→${NC} %s\n" \
            "$name" "$(fmt_time $e)" "$COMPLETED" "$TOTAL" "$err"

        rm -f "$errf"
    fi
done

# ─────────────────── trufflehog (pre-built binary — avoids OOM from compiling 500+ deps) ───────────────────
printf "  trufflehog  (downloading...)"
th_start=$SECONDS
# Get download URL from GitHub API (asset filename includes version, e.g. trufflehog_3.95.3_linux_amd64.tar.gz)
th_url=$(curl -sL https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest \
    | grep -o '"browser_download_url": "[^"]*linux_amd64.tar.gz"' | head -1 | cut -d'"' -f4)
if [ -n "$th_url" ]; then
    curl -sL "$th_url" -o /tmp/th.tar.gz 2>/dev/null
    if [ $? -eq 0 ] && tar xzf /tmp/th.tar.gz -C /tmp/ 2>/dev/null; then
        if sudo mv /tmp/trufflehog /usr/local/bin/ 2>/dev/null && command -v trufflehog &>/dev/null; then
            printf "\r  \033[K${GREEN}OK${NC}  trufflehog  %s  elapsed %s\n" \
                "$(fmt_time $((SECONDS - th_start)))" "$(fmt_time $((SECONDS - GLOBAL_START)))"
        else
            printf "\r  \033[K${RED}FAIL${NC} trufflehog  (mv or PATH issue)\n"
        fi
    else
        printf "\r  \033[K${RED}FAIL${NC} trufflehog  (download or extract failed)\n"
    fi
else
    printf "\r  \033[K${RED}FAIL${NC} trufflehog  (could not fetch release URL from GitHub API)\n"
fi
rm -f /tmp/th.tar.gz /tmp/trufflehog

# ────────────────────────────────────────── Step 5: Build OmniScan ──────────────────────────────────────────
echo -e "${CYAN}[$((++STEP))/6]${NC} Building OmniScan..."
if [ ! -d "$HOME/OmniScan" ]; then
    git clone https://github.com/Eliahhango/OmniScan.git "$HOME/OmniScan" >/dev/null 2>&1
fi
cd "$HOME/OmniScan" && git pull >/dev/null 2>&1

build_start=$SECONDS
go build -o "$HOME/go/bin/omniscan" ./cmd/omniscan/ >/dev/null 2>&1 &
pid=$!; spin='-\|/'; i=0
while kill -0 "$pid" 2>/dev/null; do
    printf "\r  \033[K${spin:i++%4:1}  Compiling  %s  elapsed %s" \
        "$(fmt_time $((SECONDS - build_start)))" "$(fmt_time $((SECONDS - GLOBAL_START)))"
    sleep 0.2
done
wait "$pid"; rc=$?
if [ $rc -eq 0 ]; then
    printf "\r  \033[K${GREEN}OK${NC}   Compiling  %s  elapsed %s\n" "$(fmt_time $((SECONDS - build_start)))" "$(fmt_time $((SECONDS - GLOBAL_START)))"
else
    printf "\r  \033[K${RED}FAIL${NC} Compiling  %s\n" "$(fmt_time $((SECONDS - build_start)))"
    exit 1
fi

# ────────────────────────────────────────────── Step 6: Verify ──────────────────────────────────────────────
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

# ────────────────────────────────────────────── Summary ──────────────────────────────────────────────
echo ""
total_elapsed=$((SECONDS - GLOBAL_START))
if [ "$MISSING" -eq 0 ]; then
    echo -e "${GREEN}All tools installed successfully!${NC}  elapsed:$(fmt_time $total_elapsed)"
else
    echo -e "${RED}$MISSING tool(s) missing — see above${NC}  elapsed:$(fmt_time $total_elapsed)"
fi
echo ""
echo -e "${CYAN}Quick test:${NC} omniscan scan -t elitechwiz.com"
echo -e "${CYAN}Daemon:${NC}   omniscan daemon --listen :9090"
echo -e "${CYAN}Help:${NC}     omniscan"
