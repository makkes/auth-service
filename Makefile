DEFAULT_TARGET: build

VERSION := $(shell git describe --tags $(git rev-parse HEAD) 2>/dev/null || git rev-parse --short HEAD)
LDFLAGS := -X "github.com/makkes/services.makk.es/auth/server.version=${VERSION}"

CURRENT_DIR = $(shell pwd)
BUILD_DIR = build
BINARY_NAME = auth
DOCKER_IMAGE = makkes/auth-service:latest

.PHONY: build
build:
	mkdir -p $(BUILD_DIR)
	go build -v -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test: lint
	go test -race ./...

.PHONY: integration
integration:
	go test -race -tags=integration ./...

.PHONY: integration-postgres
integration-postgres:
	go test -count=1 -race -tags=postgres ./...

.PHONY: integration-postgres-clean
integration-postgres-clean:
	go test -race -count=1 -tags=postgres ./persistence/postgres -args -bootstrap-database

.PHONY: clean
clean:
	rm -rf ./$(BUILD_DIR)

.PHONY: image-build
image-build:
	docker build -t $(DOCKER_IMAGE) --build-arg VERSION="${VERSION}" .

.PHONY: image-push
image-push:
	docker push $(DOCKER_IMAGE)
