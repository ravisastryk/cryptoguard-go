.PHONY: build test lint clean install

BINARY_NAME=cryptoguard
VERSION=0.1.0
BUILD_DIR=build
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/cryptoguard

test:
	go test -v -count=1 ./...

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

install:
	go install $(LDFLAGS) ./cmd/cryptoguard

clean:
	rm -rf $(BUILD_DIR) coverage.out coverage.html

test-vulnerable:
	go run ./cmd/cryptoguard ./testdata/vulnerable/...

test-secure:
	go run ./cmd/cryptoguard ./testdata/secure/...

sarif:
	go run ./cmd/cryptoguard -format sarif ./testdata/vulnerable/... > results.sarif

all: lint test build
