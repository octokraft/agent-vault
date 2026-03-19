.PHONY: build install clean test

BINARY := agent-vault
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X github.com/octokraft/agent-vault/internal/cli.Version=$(VERSION)"

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/agent-vault

install:
	go install $(LDFLAGS) ./cmd/agent-vault

clean:
	rm -f $(BINARY)

test:
	go test ./...
