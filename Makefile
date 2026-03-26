BINARY := kenv
PACKAGE := ./cmd/kenv
OUTPUT := ./bin/$(BINARY)
VERSION ?= dev

.PHONY: build build-dev build-release

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(OUTPUT) $(PACKAGE)

build-dev:
	$(MAKE) build VERSION=dev

build-release:
	@if [ "$(VERSION)" = "dev" ]; then \
		echo "VERSION must be set, e.g. make build-release VERSION=0.1.0"; \
		exit 1; \
	fi
	$(MAKE) build VERSION=$(VERSION)
