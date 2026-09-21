.PHONY: all run build test bench vet clean docker-build

VERSION ?= 0.1.0-dev
BIN_DIR = bin
BINARY = $(BIN_DIR)/gateway-data
GO ?= /usr/local/go/bin/go

all: vet test build

run:
	$(GO) run ./cmd/gateway

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "-X main.Version=$(VERSION)" -o $(BINARY) ./cmd/gateway

test:
	$(GO) test -v -race ./...

bench:
	$(GO) test -bench=. -benchmem ./...

vet:
	$(GO) vet ./...

clean:
	rm -rf $(BIN_DIR)

docker-build:
	docker build -t gateway-data:$(VERSION) -t gateway-data:latest .
