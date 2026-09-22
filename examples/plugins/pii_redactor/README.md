# PII Redactor WebAssembly Plugin

A Torana Gateway Wasm plugin that scans request/response bodies and streaming chunks (`OnChunk`), automatically masking Social Security Numbers (`\d{3}-\d{2}-\d{4}` -> `***-**-****`) and email addresses (`[REDACTED_EMAIL]`).

## Compilation Instructions

### Option A: Build with TinyGo
```bash
tinygo build -o pii_redactor.wasm -target=wasm -opt=2 main.go
```

### Option B: Build with Rust
```bash
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/pii_redactor.wasm ./
```

## Plugin Manifest
```json
{
  "name": "pii-redactor",
  "version": "1.0.0",
  "phase": "response_body",
  "body_mode": "streaming",
  "failure_policy": "fail_closed",
  "memory_limit_pages": 32,
  "timeout": "100ms",
  "capabilities": {
    "log": { "allowed": true }
  }
}
```
