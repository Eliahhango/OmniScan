FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git make
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/Eliahhango/OmniScan/internal/version.Version=$(git describe --tags --always 2>/dev/null || echo dev)" -o build/omniscan ./cmd/omniscan

FROM golang:1.26-alpine AS tool-builder
RUN apk add --no-cache git
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    curl -sL "https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest" | grep -o '"browser_download_url": "[^"]*linux_amd64.tar.gz"' | head -1 | cut -d'"' -f4 | xargs curl -sL | tar xz -C /go/bin/ && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/OJ/gobuster/v3@latest

FROM alpine:latest
RUN apk add --no-cache ca-certificates nmap nikto python3 py3-pip && \
    pip3 install semgrep --break-system-packages

COPY --from=builder /app/build/omniscan /usr/local/bin/
COPY --from=tool-builder /go/bin/nuclei /usr/local/bin/
COPY --from=tool-builder /go/bin/subfinder /usr/local/bin/
COPY --from=tool-builder /go/bin/httpx /usr/local/bin/
COPY --from=tool-builder /go/bin/katana /usr/local/bin/
COPY --from=tool-builder /go/bin/ffuf /usr/local/bin/
COPY --from=tool-builder /go/bin/trufflehog /usr/local/bin/
COPY --from=tool-builder /go/bin/gau /usr/local/bin/
COPY --from=tool-builder /go/bin/gospider /usr/local/bin/
COPY --from=tool-builder /go/bin/gobuster /usr/local/bin/
COPY --from=builder /app/templates /etc/omniscan/templates

# Create a default wordlist for FFUF/Gobuster so they work out of the box
RUN mkdir -p /usr/share/wordlists/dirb && \
    echo "admin" > /usr/share/wordlists/dirb/common.txt && \
    echo "api" >> /usr/share/wordlists/dirb/common.txt && \
    echo "backup" >> /usr/share/wordlists/dirb/common.txt && \
    echo "config" >> /usr/share/wordlists/dirb/common.txt && \
    echo "css" >> /usr/share/wordlists/dirb/common.txt && \
    echo "dev" >> /usr/share/wordlists/dirb/common.txt && \
    echo "download" >> /usr/share/wordlists/dirb/common.txt && \
    echo "ftp" >> /usr/share/wordlists/dirb/common.txt && \
    echo "img" >> /usr/share/wordlists/dirb/common.txt && \
    echo "includes" >> /usr/share/wordlists/dirb/common.txt && \
    echo "index" >> /usr/share/wordlists/dirb/common.txt && \
    echo "js" >> /usr/share/wordlists/dirb/common.txt && \
    echo "login" >> /usr/share/wordlists/dirb/common.txt && \
    echo "logout" >> /usr/share/wordlists/dirb/common.txt && \
    echo "robots.txt" >> /usr/share/wordlists/dirb/common.txt && \
    echo "sitemap.xml" >> /usr/share/wordlists/dirb/common.txt && \
    echo "static" >> /usr/share/wordlists/dirb/common.txt && \
    echo "upload" >> /usr/share/wordlists/dirb/common.txt && \
    echo "vendor" >> /usr/share/wordlists/dirb/common.txt && \
    echo "wp-admin" >> /usr/share/wordlists/dirb/common.txt && \
    echo "wp-content" >> /usr/share/wordlists/dirb/common.txt && \
    echo "wp-includes" >> /usr/share/wordlists/dirb/common.txt

# Default config
RUN mkdir -p /etc/omniscan
RUN echo 'db_path: /data/omniscan.db' > /etc/omniscan/omniscan.yaml && \
    echo 'output_dir: /data/reports' >> /etc/omniscan/omniscan.yaml && \
    echo 'tools_dir: /usr/local/bin' >> /etc/omniscan/omniscan.yaml && \
    echo 'concurrency: 5' >> /etc/omniscan/omniscan.yaml && \
    echo 'rate_limit: 150' >> /etc/omniscan/omniscan.yaml && \
    echo 'template_dir: /etc/omniscan/templates' >> /etc/omniscan/omniscan.yaml

VOLUME /data
WORKDIR /data

# ZAP and OpenVAS require separate containers:
#   docker run -d -p 8080:8080 --name zap ghcr.io/zaproxy/zaproxy:stable
#   docker run -d -p 9392:9392 --name openvas mikesplain/openvas
# Then configure omniscan.yaml to point at their hosts.

ENTRYPOINT ["omniscan"]
CMD ["tui"]
