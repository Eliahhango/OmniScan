.PHONY: build run clean test setup

BINARY=omniscan
BUILD_DIR=build

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/omniscan

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
