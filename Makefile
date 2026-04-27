BINARY ?= subby
VERSION ?= 0.1.0
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X github.com/Jvr2022/subby/pkg/version.Version=$(VERSION) -X github.com/Jvr2022/subby/pkg/version.Commit=$(COMMIT) -X github.com/Jvr2022/subby/pkg/version.Date=$(DATE)

.PHONY: build test fmt tidy install clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/subby

test:
	go test ./...

fmt:
	gofmt -w cmd pkg signatures

tidy:
	go mod tidy

install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/subby

clean:
	rm -rf bin dist
