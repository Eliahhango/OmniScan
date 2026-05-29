FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git make
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o build/omniscan ./cmd/omniscan

FROM golang:1.26-alpine AS tool-builder
RUN apk add --no-cache git
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/trufflesecurity/trufflehog/v3@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/jaeles-project/gospider@latest

FROM alpine:latest
RUN apk add --no-cache ca-certificates nmap nikto python3 py3-pip && \
    pip3 install semgrep

COPY --from=builder /app/build/omniscan /usr/local/bin/
COPY --from=tool-builder /go/bin/nuclei /usr/local/bin/
COPY --from=tool-builder /go/bin/subfinder /usr/local/bin/
COPY --from=tool-builder /go/bin/httpx /usr/local/bin/
COPY --from=tool-builder /go/bin/katana /usr/local/bin/
COPY --from=tool-builder /go/bin/ffuf /usr/local/bin/
COPY --from=tool-builder /go/bin/trufflehog /usr/local/bin/
COPY --from=tool-builder /go/bin/gau /usr/local/bin/
COPY --from=tool-builder /go/bin/gospider /usr/local/bin/
COPY --from=builder /app/templates /etc/omniscan/templates

# OpenVAS and ZAP require Docker containers:
#   docker run -d -p 9392:9392 --name openvas mikesplain/openvas
#   docker run -d -p 8080:8080 --name zap softchecks/zap-stable
# Install omniscan config to reference them
RUN mkdir -p /etc/omniscan

ENTRYPOINT ["omniscan"]
CMD ["tui"]
