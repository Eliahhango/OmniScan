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
	rm -rf $(BUILD_DIR)
	rm -f *.db
	rm -rf reports/

lint:
	go vet ./...

deps:
	go mod tidy
	go mod verify

all: deps lint build

install:
	go install ./cmd/omniscan

quick:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/omniscan
	./$(BUILD_DIR)/$(BINARY) tui

docker:
	docker build -t omniscan:latest .
