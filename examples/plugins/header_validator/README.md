# Header Validator WebAssembly Plugin

A Torana Gateway Wasm plugin that enforces authentication credentials (`X-API-Key` or `Authorization`) and injects an audit trace header (`X-Validated-By`).

## Compilation Instructions

### Option A: Build with TinyGo
```bash
tinygo build -o header_validator.wasm -target=wasm -opt=2 main.go
```

### Option B: Build with Rust
```bash
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/header_validator.wasm ./
```

## Plugin Manifest
```json
{
  "name": "header-validator",
  "version": "1.0.0",
  "phase": "request_headers",
  "body_mode": "none",
  "failure_policy": "fail_closed",
  "memory_limit_pages": 16,
  "timeout": "50ms",
  "capabilities": {
    "log": { "allowed": true }
  }
}
```
