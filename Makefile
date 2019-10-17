DEFAULT_TARGET: build

VERSION := $(shell git describe --tags $(git rev-parse HEAD) 2>/dev/null || git rev-parse --short HEAD)
LDFLAGS := -X "github.com/makkes/services.makk.es/auth/server.version=${VERSION}"

CURRENT_DIR=$(shell pwd)
BUILD_DIR=build
BINARY_NAME=auth
SRCS := $(shell find . -type f -name '*.go')

.PHONY: build
build:
	mkdir -p $(BUILD_DIR)
	go build -v -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test:
	go test ./...

.PHONY: integration
integration:
	go test -tags=integration ./...

.PHONY: integration-postgres
integration-postgres:
	go test -tags=postgres ./...

.PHONY: clean
clean:
	rm -rf ./$(BUILD_DIR)

.PHONY: image
image:
	docker build -t auth.services.makk.es:latest --build-arg VERSION="${VERSION}" .
