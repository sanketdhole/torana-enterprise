# Torana Enterprise AI Gateway (`gateway-data`)

High-performance, stateless data plane for the Torana Enterprise AI Gateway written in Go (1.25+).

## Architecture Highlights

- **Stateless Container**: Zero local storage dependencies. Bootstrapped with flags/env only.
- **Dynamic Atomic Snapshots**: Configuration (routes, policies, upstreams) arrives as signed snapshots and is swapped at runtime via `atomic.Pointer` with zero downtime and zero locks on the hot path.
- **Data Privacy by Design**: Customer payloads (prompts, embeddings, completions) never leave the local customer deployment. Only sanitized metadata is streamed to the platform control plane.
- **Streaming First**: Native streaming chunks with zero body buffering unless explicit `BodyModeBuffered` is declared by a filter.
- **Multi-Protocol**: Ingress (HTTP, gRPC, WebSocket, MCP, A2A) and Egress (HTTP, gRPC, Postgres, internal LLMs, MCP) behind small, clean Go interfaces.

## Getting Started

### Running Locally

```bash
# Run data plane
go run ./cmd/gateway

# Or using Makefile
make run
```

### Running Tests & Benchmarks

```bash
# Run unit tests with race detection
go test -v -race ./...

# Run hot-path benchmarks
go test -bench=. -benchmem ./...
```

### Docker

```bash
# Build Docker image
make docker-build

# Run container
docker run -p 8080:8080 gateway-data:latest
```
