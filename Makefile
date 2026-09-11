.PHONY: all help build build-static cross-compile test test-race test-coverage vet fmt verify clean run

GO ?= $(shell which go 2>/dev/null || echo /usr/local/go/bin/go)
BINARY_NAME=talaria
DIST_DIR=dist
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-s -w -buildid= -X main.Version=$(VERSION)

all: build

help: ## Display this help message
	@echo "Talaria — Build & Development Targets"
	@echo "Usage: make [target]"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## Compile standard binary for current architecture
	@echo "=> Compiling Talaria (Standard)..."
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) main.go
	@echo "=> Build complete: ./$(BINARY_NAME)"

build-static: ## Compile statically linked binary (CGO_ENABLED=0)
	@echo "=> Compiling Talaria (Statically Linked, CGO Disabled)..."
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS) -extldflags '-static'" -o $(BINARY_NAME) main.go
	@echo "=> Static build complete: ./$(BINARY_NAME)"

cross-compile: ## Cross-compile static binaries for Linux amd64, arm64, and 386
	@echo "=> Cross-compiling release binaries into $(DIST_DIR)/..."
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS) -extldflags '-static'" -o $(DIST_DIR)/$(BINARY_NAME)_linux_amd64 main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags="$(LDFLAGS) -extldflags '-static'" -o $(DIST_DIR)/$(BINARY_NAME)_linux_arm64 main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=386   $(GO) build -trimpath -ldflags="$(LDFLAGS) -extldflags '-static'" -o $(DIST_DIR)/$(BINARY_NAME)_linux_386 main.go
	@cd $(DIST_DIR) && sha256sum $(BINARY_NAME)_* > checksums.sha256
	@echo "=> Cross-compile complete. Checksums generated in $(DIST_DIR)/checksums.sha256"

test: ## Execute unit test suite
	@echo "=> Running test suite..."
	$(GO) test -v ./...

test-race: ## Execute unit test suite with Go race detector
	@echo "=> Running test suite with race detector..."
	$(GO) test -count=1 -race ./...

test-coverage: ## Generate test coverage profile and report
	@echo "=> Running test coverage analysis..."
	$(GO) test -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -func=coverage.out | tail -n 1
	@echo "=> Coverage report saved to coverage.out (view with: go tool cover -html=coverage.out)"

vet: ## Run canonical go vet static analysis
	@echo "=> Running go vet..."
	$(GO) vet ./...

fmt: ## Format source files according to Go standard
	@echo "=> Formatting Go code..."
	$(GO) fmt ./...

verify-standards: ## Run AST-level security & architectural standards gatekeeper
	@echo "=> Enforcing security & architectural standards..."
	$(GO) run scripts/enforce_standards.go

verify: verify-standards fmt vet test-race ## Run full quality verification pipeline
	@echo "=> All quality checks and security invariants passed successfully."

clean: ## Clean compiled binaries, test artifacts, and distribution packages
	@echo "=> Cleaning up build and test artifacts..."
	rm -rf $(BINARY_NAME) $(BINARY_NAME).gz $(DIST_DIR) coverage.* *.test *.out profile.cov
	@echo "=> Clean complete."

run: build ## Compile and execute a local scan
	./$(BINARY_NAME) --scan all
