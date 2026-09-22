.PHONY: all build test bench lint vet proto clean docker-build mockplatform fuzz chaos bench-load profile

VERSION ?= 0.1.0-dev
BIN_DIR = bin
BINARY = $(BIN_DIR)/gateway-data
GO ?= /usr/local/go/bin/go
PROTOC ?= protoc

all: vet test build

build:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BINARY) ./cmd/gateway-data

mockplatform:
	$(GO) run ./test/mockplatform

test:
	$(GO) test -v -race ./...

bench:
	$(GO) test -bench=. -benchmem -count=1 ./...

bench-load:
	$(GO) test -bench=. -benchmem -count=3 -timeout 300s ./test/bench/...

profile:
	$(GO) test -run TestProfile -count=1 -timeout 120s ./test/bench/...

fuzz:
	@echo "Fuzzing router..."
	$(GO) test -fuzz=FuzzRouterMatch -fuzztime=30s ./test/fuzz/
	@echo "Fuzzing CEL compiler..."
	$(GO) test -fuzz=FuzzCELCompile -fuzztime=30s ./test/fuzz/
	@echo "Fuzzing JWT parser..."
	$(GO) test -fuzz=FuzzJWTValidateToken -fuzztime=30s ./test/fuzz/
	@echo "Fuzzing MCP JSON-RPC parser..."
	$(GO) test -fuzz=FuzzMCPParseRequest -fuzztime=30s ./test/fuzz/

chaos:
	$(GO) test -v -race -timeout 120s ./test/chaos/...

vet:
	$(GO) vet ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, running go vet..."; \
		$(GO) vet ./...; \
	fi

proto:
	@mkdir -p api/proto/controlplane/v1 api/proto/plugin/v1
	@if command -v $(PROTOC) >/dev/null 2>&1 && command -v protoc-gen-go >/dev/null 2>&1; then \
		$(PROTOC) --go_out=. --go_opt=paths=source_relative \
			--go-grpc_out=. --go-grpc_opt=paths=source_relative \
			api/proto/controlplane/v1/controlplane.proto \
			api/proto/plugin/v1/plugin.proto; \
		echo "Protobuf code generated successfully."; \
	else \
		echo "protoc / protoc-gen-go not in PATH; proto contracts are stored in api/proto/"; \
	fi

clean:
	rm -rf $(BIN_DIR)
	rm -rf test/bench/out

docker-build:
	docker build -t gateway-data:$(VERSION) -t gateway-data:latest .
