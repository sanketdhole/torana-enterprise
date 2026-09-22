# Egress Mock Connector Plugin

An out-of-process gRPC plugin implementing `plugin/v1` for Torana Enterprise Gateway, simulating an external upstream connector over a Unix domain socket or remote mTLS.

## Build Instructions

### Static Binary Compilation (CGO-free)
To ensure the binary runs reliably in any container without dynamic glibc dependencies:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o egress_mock_connector main.go
```

For local macOS development:
```bash
go build -o egress_mock_connector main.go
```

## Kubernetes Deployment Constraints & Best Practices

### 1. `readOnlyRootFilesystem: true` Compatibility
Enterprise Kubernetes security standards mandate running containers with `securityContext.readOnlyRootFilesystem: true`. Under this setting, the root container filesystem is immutable.

Out-of-process plugins must bind Unix domain sockets in an ephemeral volume. Mount an `emptyDir` volume to `/tmp` or `/var/run/torana/plugins`:

```yaml
securityContext:
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 10001
volumeMounts:
  - name: plugin-sockets
    mountPath: /var/run/torana/plugins
volumes:
  - name: plugin-sockets
    emptyDir:
      medium: Memory # In-memory tmpfs for high-performance Unix socket I/O
```

### 2. `emptyDir` with Exec Permissions
Ensure that the volume where plugin binaries are stored has execution permissions enabled (no `noexec` mount flag).

## Plugin Manifests

### Local Child Process Tier
```json
{
  "name": "egress-mock-connector",
  "version": "1.0.0",
  "tier": "local",
  "kind": "egress",
  "binary_path": "/opt/torana/plugins/egress_mock_connector",
  "sha256_checksum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "allowed_binary_dirs": ["/opt/torana/plugins"],
  "socket_dir": "/var/run/torana/plugins",
  "timeout": "500ms",
  "failure_policy": "fail_closed",
  "circuit_breaker_threshold": 5,
  "circuit_breaker_cooldown": "10s",
  "rlimits": {
    "max_memory_bytes": 268435456,
    "max_fds": 1024,
    "cpu_time_seconds": 60
  }
}
```

### Remote Tier (gRPC over mTLS)
```json
{
  "name": "remote-egress-connector",
  "version": "1.0.0",
  "tier": "remote",
  "kind": "egress",
  "remote_endpoint": "egress-service.torana.svc.cluster.local:8443",
  "timeout": "1s",
  "failure_policy": "fail_closed",
  "tls": {
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
    "key_pem": "-----BEGIN EC PRIVATE KEY-----\n...",
    "ca_pem": "-----BEGIN CERTIFICATE-----\n...",
    "server_name": "egress-service.torana.svc.cluster.local"
  }
}
```
