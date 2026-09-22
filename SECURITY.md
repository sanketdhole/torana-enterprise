# Security Threat Model — Torana Data Plane

> **Document Version**: 1.0  
> **Last Updated**: 2026-09-23  
> **Scope**: `gateway-data` process — the stateless data plane of Torana Enterprise AI Gateway

---

## 1. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    Customer Network                         │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │  Client   │───▶│  gateway-data │───▶│  Upstream LLM /  │  │
│  │ (Caller)  │◀───│  (Data Plane) │◀───│  MCP / gRPC Svc │  │
│  └──────────┘    └──────┬───────┘    └──────────────────┘   │
│                         │                                    │
│                         │ gRPC + mTLS                        │
│                         ▼                                    │
│  ┌──────────────────────────────┐                            │
│  │  Peer Data Plane (optional)  │                            │
│  └──────────────────────────────┘                            │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ gRPC + TLS (metadata only)
                          ▼
              ┌──────────────────────┐
              │  Platform Service     │
              │  (Control Plane)      │
              └──────────────────────┘
```

**Trust boundaries crossed:**
1. Client → Data Plane (untrusted input)
2. Data Plane → Upstream (semi-trusted; credentials injected)
3. Data Plane → Platform (metadata only; TLS required)
4. Data Plane → Peer (mTLS required)
5. Platform → Data Plane (signed configuration)
6. Plugin sandbox → Data Plane (isolated execution)

---

## 2. Threat Catalog

### T1: Malicious Plugin Execution

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | A WASM or process plugin with attacker-controlled code is installed via a compromised snapshot or supply chain attack. The plugin attempts to: exfiltrate data, consume unbounded CPU/memory, access host filesystem, or interfere with other plugins. |
| **Impact** | Data exfiltration, denial of service, lateral movement |
| **Likelihood** | Medium (requires control plane compromise or poisoned plugin registry) |

**Mitigations:**
- **WASM sandbox isolation** (`wazero`): No filesystem, network, or host syscall access by default. Only explicitly allowed imports are bridged.
- **Process plugin isolation**: Separate OS process with restricted capabilities (`no_new_privs`, `seccomp` profile). Communication via gRPC over Unix socket with bounded message sizes.
- **Resource limits**: Per-plugin CPU time budget (enforced by `context.WithTimeout` on `Process()`), memory limits (WASM linear memory cap), and goroutine limits.
- **Capability allowlist**: Plugins declare required capabilities in manifest; denied capabilities cause install rejection.
- **Canary validation**: New plugin versions are smoke-tested with synthetic traffic before atomic swap to production. Rollback on failure.
- **Signature verification**: Plugin binaries are signed; signature is verified at install time.

---

### T2: Forged Configuration Snapshot

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | An attacker intercepts or replays a gRPC control plane stream to inject a malicious configuration snapshot: reroute traffic, disable authentication, install attacker-controlled plugins. |
| **Impact** | Complete bypass of security policies, traffic interception |
| **Likelihood** | Medium (requires network position or control plane compromise) |

**Mitigations:**
- **Ed25519 signature verification**: Every snapshot carries a cryptographic signature verified against a pinned public key before compilation. Unsigned or invalid snapshots are rejected (NACKed) and logged.
- **Mutual TLS**: Control plane stream uses mTLS with certificate pinning. No plaintext fallback.
- **Version monotonicity**: Snapshot versions are strictly monotonically increasing. Stale/replayed versions are discarded. Rollback requires explicit platform action with a new signed snapshot.
- **Compilation fail-safe**: If a new snapshot fails validation or compilation, the active snapshot remains untouched. The data plane continues serving on the last-known-good (LKG) configuration.

---

### T3: Stolen Enrollment Token

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | The one-time enrollment token (used for initial data plane registration with the platform) is leaked from disk, environment variables, or container image layers. An attacker uses it to register a rogue data plane and receive valid configuration snapshots. |
| **Impact** | Rogue data plane receives production config (routes, secrets references, policies) |
| **Likelihood** | Low-Medium (requires host access or image layer inspection) |

**Mitigations:**
- **File permissions**: Enrollment token file is created with `0600` permissions, readable only by the gateway process user.
- **Single-use exchange**: The token is exchanged for a short-lived mTLS certificate on first registration. The token is invalidated immediately after use.
- **Short TTL**: Enrollment tokens have a platform-enforced TTL (default: 1 hour). Expired tokens are rejected.
- **Token rotation**: The platform can revoke and rotate enrollment tokens without redeploying the data plane.
- **No secrets in snapshots**: Configuration snapshots contain only secret _references_ (e.g., `secret://vault/api-key-1`). Actual secret values are resolved locally via `internal/secret` and never transmitted over the control plane stream.
- **Audit logging**: All enrollment attempts (success and failure) are logged with source IP and timestamp.

---

### T4: Peer Data Plane Compromise

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | A compromised peer gateway in a multi-gateway mesh receives snapshot state via peer sync, or sends poisoned state to healthy peers. The attacker uses the compromised peer to: intercept inter-gateway traffic, inject malicious configuration, or amplify denial-of-service. |
| **Impact** | Lateral movement within the mesh, configuration poisoning |
| **Likelihood** | Low (requires host-level compromise of a peer node) |

**Mitigations:**
- **Mutual TLS between peers**: All peer-to-peer communication uses mTLS with per-instance certificates issued by the platform. No plaintext or anonymous connections.
- **Signed snapshot propagation**: Peers do not blindly accept configuration from other peers. All configuration must carry a valid platform signature, verified independently.
- **Isolated failure domains**: Each peer operates independently. A compromised peer's traffic is isolated; it cannot modify other peers' routing tables or policies.
- **Health check exclusion**: A peer that fails health checks is automatically removed from the peer ring.

---

### T5: Data Exfiltration via Telemetry / Audit

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | A misconfigured or compromised telemetry pipeline leaks customer payload data (prompts, completions, embeddings) to the platform or an external sink. |
| **Impact** | Violation of data privacy guarantees, regulatory non-compliance |
| **Likelihood** | Low (mitigated by code-level enforcement) |

**Mitigations:**
- **Payload never sent to platform**: The audit `Shipper.drain()` method explicitly sets `event.Payload = nil` before forwarding to the platform sink. This is enforced by `TestPlatformSinkNeverReceivesPayload` in the test suite.
- **Metadata-only by default**: Telemetry events contain only: route ID, upstream ID, status code, latency, token count, tenant ID. No request/response bodies.
- **Opt-in payload capture**: Payload data is captured to customer sinks _only_ when explicitly enabled per route in the configuration snapshot. This is a customer-controlled knob.
- **Log redaction**: The structured logger's `redactingHandler` replaces 15+ sensitive field names (`authorization`, `token`, `password`, `secret`, `cookie`, `api_key`, etc.) with `[REDACTED]` at the handler level, before any sink sees the data.
- **Non-blocking pipeline**: The audit pipeline (ring buffer → disk spool → shipper) is non-blocking on the request path. A stalled or malicious sink cannot cause back-pressure that exposes data through alternative channels.

---

### T6: JWT Authentication Bypass

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | An attacker crafts a JWT to bypass authentication: algorithm confusion (`alg: none`), expired token replay, audience mismatch, JWKS endpoint poisoning, or key confusion between RSA/EC/EdDSA. |
| **Impact** | Unauthorized access to protected routes |
| **Likelihood** | Medium (JWT attacks are well-documented) |

**Mitigations:**
- **Strict algorithm allowlist**: Each issuer configuration specifies `AllowedAlgorithms`. Tokens with unlisted algorithms (including `none`, `HS256` symmetric) are rejected.
- **Per-issuer key binding**: Keys are resolved from the issuer's JWKS cache, pinned by `kid`. Cross-issuer key confusion is not possible.
- **JWKS fetch cooldown**: JWKS endpoint is fetched at most once per second (cooldown) to prevent poisoning via rapid key rotation. Only HTTPS JWKS URLs are allowed.
- **Clock skew bounds**: `exp` and `nbf` checks include a configurable clock skew (default: 1 minute). Tokens beyond skew are rejected.
- **Revocation list**: A real-time revocation list (populated by the control plane) checks both `jti` claim and token hash. Revoked tokens are rejected in O(1).
- **Signature verification**: Full cryptographic verification for RS256/384/512, ES256/384/512, EdDSA. No implicit trust.

---

### T7: CEL Policy Denial of Service

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | A malicious or negligent administrator deploys a CEL policy expression that is computationally expensive (e.g., deeply nested loops, expensive string operations), causing CPU exhaustion during policy evaluation on every request. |
| **Impact** | Denial of service, latency degradation |
| **Likelihood** | Low-Medium (requires control plane access to deploy policies) |

**Mitigations:**
- **Cost limit**: CEL programs are compiled with a cost limit (default: 10,000 units). Expressions exceeding the limit fail at compilation time, not at runtime.
- **Boolean return type enforcement**: All policy expressions must return `bool`. Non-boolean expressions are rejected at compile time.
- **Compilation-time validation**: Policies are compiled when a new snapshot is received, not per-request. Invalid expressions cause the snapshot to be NACKed.
- **Context timeout**: Policy evaluation runs within the request's `context.Context` timeout. Runaway evaluation is killed by context cancellation.

---

### T8: Configuration Storm / Resource Exhaustion

| Attribute | Detail |
|-----------|--------|
| **Attack Vector** | A compromised or malfunctioning control plane sends rapid configuration updates (hundreds per second), causing CPU exhaustion from repeated route compilation, regex compilation, and memory churn from old snapshot garbage. |
| **Impact** | Denial of service, GC pressure, latency spikes |
| **Likelihood** | Low (requires control plane compromise) |

**Mitigations:**
- **Atomic pointer swap**: Configuration is swapped via `atomic.Pointer[Snapshot]`. In-flight requests continue on the old snapshot; new requests use the new one. No locks on the hot path.
- **Compilation off hot path**: Route tables, regex patterns, and CEL programs are compiled in a background goroutine, not in the request path.
- **Rate limiting**: The control plane client can rate-limit incoming snapshots (e.g., max 10/s). Excess updates are coalesced.
- **GOMEMLIMIT**: The container entrypoint auto-sets `GOMEMLIMIT` to 90% of the cgroup memory limit, ensuring GC runs proactively under memory pressure rather than triggering OOM kills.
- **Chaos tested**: `TestChaos_ConfigStorm` fires 100 snapshots/s for 3 seconds under concurrent load and verifies zero failed matches.

---

## 3. Data Flow Security Matrix

| Data Type | Client → DP | DP → Upstream | DP → Platform | DP → Audit Sink | DP Logs |
|-----------|:-----------:|:-------------:|:-------------:|:---------------:|:-------:|
| Request/Response Bodies | ✅ Processed | ✅ Forwarded | ❌ Never | ⚙️ Opt-in per route | ❌ Never |
| HTTP Headers | ✅ Processed | ✅ Forwarded (filtered) | ❌ Never | ⚙️ Metadata only | 🔒 Redacted |
| JWT Tokens | ✅ Validated | ❌ Stripped | ❌ Never | ❌ Never | 🔒 Redacted |
| API Keys | ✅ Validated | ✅ Injected from vault | ❌ Never | ❌ Never | 🔒 Redacted |
| Route/Status Metadata | — | — | ✅ Sent | ✅ Sent | ✅ Logged |
| Token Counts | — | — | ✅ Sent | ✅ Sent | ✅ Logged |
| Secret Values | ❌ Never in snapshot | Resolved locally | ❌ Never | ❌ Never | ❌ Never |

---

## 4. Runtime Hardening Checklist

- [x] **`-race` flag**: All tests run with `-race` (`make test` uses `go test -race ./...`)
- [x] **`GOMEMLIMIT`**: Auto-set from cgroup v2/v1 memory limit at container startup
- [x] **Non-root**: Container runs as UID 65532 (distroless `nonroot`)
- [x] **CGO_ENABLED=0**: Pure Go binary, no C dependencies or attack surface
- [x] **Read-only filesystem**: Distroless base image has no shell, package manager, or writable system directories
- [x] **No network from plugins**: WASM plugins have no network access; process plugins use isolated Unix sockets
- [x] **Graceful drain**: SIGTERM → mark unready → drain in-flight → flush telemetry → exit
- [x] **Bounded queues**: All internal queues (telemetry, audit) are bounded with explicit drop counters
- [x] **Fuzz tested**: Router, CEL compiler, JWT parser, MCP parser all have `testing.F` fuzz targets

---

## 5. Incident Response

| Signal | Action |
|--------|--------|
| `audit_events_dropped_total` > 0 | Audit pipeline is saturated — investigate sink latency, scale out, or increase ring buffer |
| Snapshot NACK logged | Invalid or tampered configuration — check control plane, verify signing key |
| `jwt_revocation_check` errors | Revocation list sync failure — check control plane connectivity |
| Plugin canary failure | New plugin version failed smoke test — automatic rollback, alert |
| GOMEMLIMIT soft limit hit | GC frequency increasing — consider scaling memory or reducing in-flight concurrency |

---

## 6. References

- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/)
- [RFC 7519 — JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [RFC 7517 — JSON Web Key](https://tools.ietf.org/html/rfc7517)
- [MCP Specification (2024-11-05)](https://spec.modelcontextprotocol.io/)
- [Go Runtime GOMEMLIMIT](https://pkg.go.dev/runtime#hdr-Environment_Variables)
- [CEL Specification](https://github.com/google/cel-spec)
