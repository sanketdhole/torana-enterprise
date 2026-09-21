# DESIGN.md: Torana Data Plane (`gateway-data`)

## 1. System Overview

`gateway-data` is the high-performance, stateless data plane of the Torana Enterprise AI Gateway written in Go (1.25+). It runs as a single stateless container per deployment namespace, handling multi-protocol ingress and egress for enterprise AI workloads.

### Core Tenets
1. **Stateless & Resilient**: Bootstrap requires only local flags/env (control plane endpoint, TLS certs, namespace identity).
2. **Zero Local Configuration Storage**: All routing, policies, and plugin configurations arrive dynamically as cryptographically signed, versioned snapshots over a gRPC control-plane stream and are applied atomically at runtime with zero downtime or restarts.
3. **Data Privacy by Design**: Customer payloads (prompts, embeddings, completions, tools data) never leave the local customer boundary/network. Only telemetry metadata (token counts, latency, status codes, route IDs, policy verdicts) is streamed to the platform service.
4. **Streaming First**: Default pipeline operates on raw byte streams (`io.Reader`/`io.Writer` or protocol chunks) with zero buffering unless explicitly requested by a filter (`BodyModeBuffered`).

---

## 2. Repository Layout

```
.
├── cmd/
│   └── gateway/
│       └── main.go                 # Process lifecycle, bootstrap args, supervisor
├── api/
│   └── proto/                      # gRPC & Protobuf schemas (control plane, MCP, etc.)
│       └── v1/
├── internal/
│   ├── config/                     # Immutable snapshot models & atomic snapshot holder
│   ├── controlplane/               # gRPC client for snapshot sync & signature verification
│   ├── router/                     # Lock-free route matcher (radix tree / pre-compiled index)
│   ├── pipeline/                   # Filter chain executor with streaming & buffered modes
│   │   ├── filter.go               # Filter interfaces & lifecycle
│   │   ├── chain.go                # Ordered filter evaluation
│   │   └── context.go              # Request execution context & metadata container
│   ├── ingress/                    # Multi-protocol ingress listeners
│   │   ├── ingress.go              # Ingress listener interface & factory
│   │   ├── http/                   # HTTP/1.1 & HTTP/2 ingress
│   │   ├── grpc/                   # gRPC ingress
│   │   ├── ws/                     # WebSocket bidirectional ingress
│   │   ├── mcp/                    # Model Context Protocol (MCP) ingress
│   │   └── a2a/                    # Agent-to-Agent (A2A) protocol ingress
│   ├── egress/                     # Multi-protocol egress clients & connection pools
│   │   ├── egress.go               # Egress client interface & factory
│   │   ├── http/                   # Upstream HTTP/REST client (LLM providers)
│   │   ├── grpc/                   # Upstream gRPC client
│   │   ├── postgres/               # Vector / DB egress connector
│   │   ├── llm/                    # Native optimized internal LLM client
│   │   └── mcp/                    # Upstream MCP server client
│   ├── secret/                     # Secret reference resolver (vault, k8s, env)
│   ├── telemetry/                  # Metadata-only emitter with bounded, non-blocking ring buffers
│   └── supervisor/                 # Coordinates listener lifecycle, health checks, graceful drain
├── Makefile
├── Dockerfile
├── README.md
└── DESIGN.md
```

---

## 3. Hot-Path Performance Architecture

To achieve sub-millisecond overhead and ultra-high throughput:

1. **Zero Locks on Hot Path**:
   - Active configuration is held as an immutable snapshot in `sync/atomic.Pointer[Snapshot]`.
   - Each incoming request performs a single `atomic.LoadPointer` at request start, anchoring a consistent snapshot for the entire request lifecycle.
2. **Pre-Compiled & Pre-Allocated Structures**:
   - Route tables (radix trees), headers, policies, and regexes/matchers are compiled strictly when a new configuration snapshot is received, never per-request.
   - Zero reflection-based dynamic JSON marshalling on the hot path.
3. **Memory & Allocations**:
   - Reusable buffer pools (`sync.Pool`) for streaming chunks and headers.
   - Bounded struct allocations.
4. **Streaming Execution**:
   - `Filter` interface declares `BodyMode()`:
     - `BodyModeNone`: Inspects / mutates headers and metadata only. Zero body overhead.
     - `BodyModeStreaming`: Wraps reader/writer stream for inline token inspection / transformation.
     - `BodyModeBuffered`: Explicitly buffers payload up to a declared max size only when required (e.g. signature verification or schema validation).

---

## 4. Control Plane & Dynamic Configuration

```mermaid
flowchart LR
    CP[Platform Service Control Plane] -- gRPC Stream (Signed Snapshot) --> CPClient[internal/controlplane]
    CPClient -- Verify Sig & Compile --> Builder[Snapshot Compiler]
    Builder -- atomic.Store --> AtomicPtr[atomic.Pointer[Snapshot]]
    AtomicPtr -. atomic.Load .-> HotPath[Hot Path Request Handlers]
```

1. **Snapshot Delivery**: `controlplane.Client` maintains an open gRPC bi-directional stream with automatic backoff reconnection and keep-alives.
2. **Signature & Version Verification**: Every snapshot payload is cryptographically validated (e.g. Ed25519) before compilation. Stale versions are discarded.
3. **Compilation**: Routes, matchers, policies, and plugins are compiled into immutable lookup tables. If compilation fails, the active snapshot remains untouched (fail-safe).
4. **Atomic Swap**: `atomicPtr.Store(newCompiledSnapshot)`. Existing in-flight requests complete on the prior snapshot; new requests immediately receive the new snapshot.

---

## 5. Security & Isolation Defaults

- **Fail-Closed**: Any authentication or authorization evaluation error immediately halts the request and returns an unauthorized status.
- **No Secrets in Logs or Snapshots**: Snapshots contain only secret references (e.g. `secret://vault/api-key-1`). Values are resolved locally via `internal/secret` and never logged or exposed via inspection endpoints.
- **No Customer Data Exfiltration**: Telemetry workers strip request/response bodies and only publish anonymized metadata (token usage, latency distributions, status codes, route ID, tenant ID).

---

## 6. Concurrency, Goroutine Ownership, and Draining

- Every goroutine spawned is owned by a structured lifecycle (using `context.Context` and `sync.WaitGroup` or errgroup).
- No unbounded channels or queues: telemetry and logging queues use bounded ring buffers with explicit metric counters on dropped items under load.
- Graceful shutdown handles `SIGINT`/`SIGTERM`:
  1. Mark `/readyz` as unready.
  2. Stop accepting new ingress connections.
  3. Allow in-flight requests up to a configurable drain deadline (e.g. 30s).
  4. Flush bounded telemetry queue to platform.
  5. Close egress connection pools and exit.
