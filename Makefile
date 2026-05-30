.PHONY: build run clean test setup update version help

BINARY=omniscan
BUILD_DIR=build
VERSION=$(shell git describe --tags --always 2>/dev/null || echo "dev")
LDFLAGS=-s -w -X github.com/Eliahhango/OmniScan/internal/version.Version=$(VERSION)

build:
	go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/omniscan

update:
	go install -ldflags="$(LDFLAGS)" github.com/Eliahhango/OmniScan/cmd/omniscan@latest; \
	omniscan setup

version:
	@omniscan version

run:
	go run ./cmd/omniscan

tui:
	go run ./cmd/omniscan tui

setup:
	go run ./cmd/omniscan setup

test:
	go test ./...

clean:
	go clean -cache
	go clean -i ./...
	go clean ./...

lint:
	go vet ./...

deps:
	go mod tidy
	go mod verify

all: deps lint build

install:
	go install ./cmd/omniscan

quick:
	go run ./cmd/omniscan tui

docker:
	docker build -t omniscan:latest .
