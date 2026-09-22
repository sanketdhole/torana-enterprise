package plugins_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/plugins/wasm"
)

// Helper: build a Wasm module that echoes or returns a mutated decision
func buildStandardPluginWasm(action int, statusCode int, headerKey, headerVal string) []byte {
	b := NewWasmBuilder()

	// Type 0: (i32) -> (i32) [alloc]
	typeAlloc := b.AddType([]byte{0x7F}, []byte{0x7F})
	// Type 1: (i32, i32) -> (i64) [process]
	typeProcess := b.AddType([]byte{0x7F, 0x7F}, []byte{0x7E})
	// Type 2: (i32, i32) -> (i64) [on_chunk]
	typeOnChunk := b.AddType([]byte{0x7F, 0x7F}, []byte{0x7E})

	b.AddMemory(1, nil) // 1 page = 64KB

	// Response payload at offset 2048
	dec := map[string]any{
		"action":      action,
		"status_code": statusCode,
	}
	if headerKey != "" {
		dec["mutate_headers"] = map[string]string{headerKey: headerVal}
	}
	decBytes, _ := json.Marshal(dec)
	respOffset := uint32(2048)
	b.AddDataSegment(respOffset, decBytes)

	// Function 0: alloc(size) -> 1024
	// i32.const 1024
	funcAlloc := b.AddFunction(typeAlloc, []byte{0x41, 0x80, 0x08})
	b.AddExport("alloc", 0, funcAlloc)

	// Function 1: process(ptr, len) -> (respOffset << 32 | len(decBytes))
	packed := (uint64(respOffset) << 32) | uint64(len(decBytes))
	var procCode []byte
	procCode = append(procCode, 0x42) // i64.const
	procCode = append(procCode, encodeIleb128(int64(packed))...)
	funcProcess := b.AddFunction(typeProcess, procCode)
	b.AddExport("process", 0, funcProcess)

	// Function 2: on_chunk(ptr, len) -> echo input (ptr << 32 | len)
	// local.get 0 (ptr) -> i64.extend_i32_u -> i64.const 32 -> i64.shl -> local.get 1 (len) -> i64.extend_i32_u -> i64.or
	var chunkCode []byte
	chunkCode = append(chunkCode, 0x20, 0x00)       // local.get 0
	chunkCode = append(chunkCode, 0xAD)             // i64.extend_i32_u
	chunkCode = append(chunkCode, 0x42, 0x20)       // i64.const 32
	chunkCode = append(chunkCode, 0x86)             // i64.shl
	chunkCode = append(chunkCode, 0x20, 0x01)       // local.get 1
	chunkCode = append(chunkCode, 0xAD)             // i64.extend_i32_u
	chunkCode = append(chunkCode, 0x84)             // i64.or
	funcOnChunk := b.AddFunction(typeOnChunk, chunkCode)
	b.AddExport("on_chunk", 0, funcOnChunk)

	return b.Build()
}

// Helper: build infinite loop Wasm module
func buildInfiniteLoopWasm() []byte {
	b := NewWasmBuilder()
	typeAlloc := b.AddType([]byte{0x7F}, []byte{0x7F})
	typeProcess := b.AddType([]byte{0x7F, 0x7F}, []byte{0x7E})
	b.AddMemory(1, nil)

	// alloc(size) -> 1024
	funcAlloc := b.AddFunction(typeAlloc, []byte{0x41, 0x80, 0x08})
	b.AddExport("alloc", 0, funcAlloc)

	// process(ptr, len) -> loop { br 0 }
	// 0x03 0x40 (loop emptyblock) -> 0x0C 0x00 (br 0) -> 0x0B (end loop) -> 0x42 0x00 (i64.const 0)
	var loopCode []byte
	loopCode = append(loopCode, 0x03, 0x40) // loop
	loopCode = append(loopCode, 0x0C, 0x00) // br 0
	loopCode = append(loopCode, 0x0B)       // end
	loopCode = append(loopCode, 0x42, 0x00) // i64.const 0
	funcProcess := b.AddFunction(typeProcess, loopCode)
	b.AddExport("process", 0, funcProcess)

	return b.Build()
}

// Helper: build memory bomb Wasm module
func buildMemoryBombWasm() []byte {
	b := NewWasmBuilder()
	typeAlloc := b.AddType([]byte{0x7F}, []byte{0x7F})
	typeProcess := b.AddType([]byte{0x7F, 0x7F}, []byte{0x7E})
	b.AddMemory(1, nil)

	funcAlloc := b.AddFunction(typeAlloc, []byte{0x41, 0x80, 0x08})
	b.AddExport("alloc", 0, funcAlloc)

	// process(ptr, len): attempts to grow memory by 1000 pages (64MB)
	// i32.const 1000 -> memory.grow 0 -> i32.const -1 -> i32.eq -> if unreachable end -> i64.const 0
	var bombCode []byte
	bombCode = append(bombCode, 0x41, 0xE8, 0x07) // i32.const 1000
	bombCode = append(bombCode, 0x40, 0x00)       // memory.grow 0
	bombCode = append(bombCode, 0x41, 0x7F)       // i32.const -1 (grow failed)
	bombCode = append(bombCode, 0x46)             // i32.eq
	bombCode = append(bombCode, 0x04, 0x40)       // if
	bombCode = append(bombCode, 0x00)             // unreachable (traps!)
	bombCode = append(bombCode, 0x0B)             // end
	bombCode = append(bombCode, 0x42, 0x00)       // i64.const 0
	funcProcess := b.AddFunction(typeProcess, bombCode)
	b.AddExport("process", 0, funcProcess)

	return b.Build()
}

// Helper: build guest panic Wasm module
func buildPanicWasm() []byte {
	b := NewWasmBuilder()
	typeAlloc := b.AddType([]byte{0x7F}, []byte{0x7F})
	typeProcess := b.AddType([]byte{0x7F, 0x7F}, []byte{0x7E})
	b.AddMemory(1, nil)

	funcAlloc := b.AddFunction(typeAlloc, []byte{0x41, 0x80, 0x08})
	b.AddExport("alloc", 0, funcAlloc)

	// process(ptr, len): unreachable opcode (trap)
	funcProcess := b.AddFunction(typeProcess, []byte{0x00}) // unreachable
	b.AddExport("process", 0, funcProcess)

	return b.Build()
}

// Helper: build host capability test Wasm module
func buildHostCallTestWasm() []byte {
	b := NewWasmBuilder()
	// Type 0: (i32) -> (i32) [alloc]
	typeAlloc := b.AddType([]byte{0x7F}, []byte{0x7F})
	// Type 1: (i32, i32) -> (i64) [process]
	typeProcess := b.AddType([]byte{0x7F, 0x7F}, []byte{0x7E})
	// Type 2: (i32, i32, i32, i32) -> (i32) [secret_get, http_call, kv_get, kv_set]
	typeHostCall := b.AddType([]byte{0x7F, 0x7F, 0x7F, 0x7F}, []byte{0x7F})

	// Import secret_get
	impSecretGet := b.AddImport("torana:host", "secret_get", typeHostCall)
	// Import http_call
	impHTTPCall := b.AddImport("torana:host", "http_call", typeHostCall)

	b.AddMemory(1, nil)

	// Place secret name "forbidden_token" at offset 1024 (len 15)
	b.AddDataSegment(1024, []byte("forbidden_token"))
	// Place unapproved URL at offset 1050
	urlJSON := []byte(`{"url":"https://unapproved.attacker.com"}`)
	b.AddDataSegment(1050, urlJSON)

	// alloc(size) -> 2048
	funcAlloc := b.AddFunction(typeAlloc, []byte{0x41, 0x80, 0x10})
	b.AddExport("alloc", 0, funcAlloc)

	// process:
	// 1. call secret_get(1024, 15, 3000, 256)
	// 2. call http_call(1050, len(urlJSON), 3500, 256)
	// 3. if both return -1 (denied), return Decision Continue (200), else trap
	var callCode []byte
	// secret_get
	callCode = append(callCode, 0x41, 0x80, 0x08) // i32.const 1024
	callCode = append(callCode, 0x41, 0x0F)       // i32.const 15
	callCode = append(callCode, 0x41, 0xB8, 0x17) // i32.const 3000 (outPtr)
	callCode = append(callCode, 0x41, 0x80, 0x02) // i32.const 256 (maxLen)
	callCode = append(callCode, 0x10, byte(impSecretGet))

	// if result != -1 -> unreachable (should have been denied!)
	callCode = append(callCode, 0x41, 0x7F) // i32.const -1
	callCode = append(callCode, 0x47)       // i32.ne
	callCode = append(callCode, 0x04, 0x40) // if
	callCode = append(callCode, 0x00)       // unreachable
	callCode = append(callCode, 0x0B)       // end

	// http_call
	callCode = append(callCode, 0x41, 0x9A, 0x08)     // i32.const 1050
	callCode = append(callCode, 0x41, byte(len(urlJSON))) // i32.const len(urlJSON)
	callCode = append(callCode, 0x41, 0xAC, 0x1B)     // i32.const 3500 (resOutPtr)
	callCode = append(callCode, 0x41, 0x80, 0x02)     // i32.const 256 (maxLen)
	callCode = append(callCode, 0x10, byte(impHTTPCall))

	// if result != -1 -> unreachable (should have been denied!)
	callCode = append(callCode, 0x41, 0x7F) // i32.const -1
	callCode = append(callCode, 0x47)       // i32.ne
	callCode = append(callCode, 0x04, 0x40) // if
	callCode = append(callCode, 0x00)       // unreachable
	callCode = append(callCode, 0x0B)       // end

	// Return Continue: packed (4000 << 32 | len)
	respBytes := []byte(`{"action":0,"status_code":200}`)
	b.AddDataSegment(4000, respBytes)
	packed := (uint64(4000) << 32) | uint64(len(respBytes))
	callCode = append(callCode, 0x42)
	callCode = append(callCode, encodeIleb128(int64(packed))...)

	funcProcess := b.AddFunction(typeProcess, callCode)
	b.AddExport("process", 0, funcProcess)

	return b.Build()
}

// Test 1: Standard Wasm Filter Execution & Mutation
func TestWasmFilter_StandardExecution(t *testing.T) {
	ctx := context.Background()
	wasmBytes := buildStandardPluginWasm(2, 200, "X-Validated-By", "Torana-Wasm/1.0")

	manifest := wasm.DefaultManifest("test-filter", "1.0.0")
	manifest.Phase = pipeline.PhaseRequestHeaders

	pool, err := wasm.NewInstancePool(ctx, wasmBytes, manifest, nil)
	if err != nil {
		t.Fatalf("failed to create instance pool: %v", err)
	}
	defer pool.Close(ctx)

	filter := wasm.NewWasmFilter(manifest, pool, nil)
	defer filter.Close()

	headers := make(http.Header)
	headers.Set("User-Agent", "ToranaTest/1.0")
	env := pipeline.GetEnvelope("req-123", pipeline.PhaseRequestHeaders, "GET", "/api/test", headers, nil)
	defer pipeline.PutEnvelope(env)

	decision, err := filter.Process(ctx, env)
	if err != nil {
		t.Fatalf("filter process returned unexpected error: %v", err)
	}

	if decision.Action != pipeline.ActionMutate {
		t.Errorf("expected action mutate, got %v", decision.Action)
	}
	if decision.MutateHeaders["X-Validated-By"] != "Torana-Wasm/1.0" {
		t.Errorf("expected header X-Validated-By, got %v", decision.MutateHeaders)
	}
}

// Test 2: Body Modes (none, headers, buffered, streaming OnChunk)
func TestWasmFilter_BodyModes(t *testing.T) {
	ctx := context.Background()
	wasmBytes := buildStandardPluginWasm(0, 200, "", "")

	// 1. Streaming OnChunk hook
	manifest := wasm.DefaultManifest("streaming-filter", "1.0.0")
	manifest.BodyMode = pipeline.BodyModeStreaming

	pool, err := wasm.NewInstancePool(ctx, wasmBytes, manifest, nil)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close(ctx)

	filter := wasm.NewWasmFilter(manifest, pool, nil)
	defer filter.Close()

	chunk := []byte("hello streaming wasm world")
	outChunk, err := filter.OnChunk(ctx, nil, chunk)
	if err != nil {
		t.Fatalf("OnChunk failed: %v", err)
	}
	if !bytes.Equal(outChunk, chunk) {
		t.Errorf("expected chunk echo, got %s", string(outChunk))
	}

	// 2. Buffered Body Mode
	manifestBuf := wasm.DefaultManifest("buffered-filter", "1.0.0")
	manifestBuf.BodyMode = pipeline.BodyModeBuffered
	manifestBuf.MaxBufferBytes = 1024

	poolBuf, err := wasm.NewInstancePool(ctx, wasmBytes, manifestBuf, nil)
	if err != nil {
		t.Fatalf("failed to create buffered pool: %v", err)
	}
	defer poolBuf.Close(ctx)

	filterBuf := wasm.NewWasmFilter(manifestBuf, poolBuf, nil)
	defer filterBuf.Close()

	bodyReader := strings.NewReader("sample buffered body payload")
	env := pipeline.GetEnvelope("req-buf", pipeline.PhaseRequestBody, "POST", "/api/upload", nil, bodyReader)
	defer pipeline.PutEnvelope(env)

	dec, err := filterBuf.Process(ctx, env)
	if err != nil || dec.Action != pipeline.ActionContinue {
		t.Errorf("buffered filter failed: %v, action: %v", err, dec.Action)
	}
}

// Test 3: Infinite Loop & Context Timeout Cancellation
func TestWasmFilter_InfiniteLoop_TimeoutCancellation(t *testing.T) {
	ctx := context.Background()
	wasmBytes := buildInfiniteLoopWasm()

	manifest := wasm.DefaultManifest("infinite-loop-filter", "1.0.0")
	manifest.Timeout = 50 * time.Millisecond // strict 50ms per-call timeout
	manifest.FailurePolicy = pipeline.FailurePolicyFailClosed

	pool, err := wasm.NewInstancePool(ctx, wasmBytes, manifest, nil)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close(ctx)

	filter := wasm.NewWasmFilter(manifest, pool, nil)
	defer filter.Close()

	env := pipeline.GetEnvelope("req-loop", pipeline.PhaseRequestHeaders, "GET", "/loop", nil, nil)
	defer pipeline.PutEnvelope(env)

	start := time.Now()
	decision, err := filter.Process(ctx, env)
	duration := time.Since(start)

	if err == nil {
		t.Fatalf("expected error from infinite loop, got nil (decision: %v)", decision)
	}

	if decision.Action != pipeline.ActionHalt || decision.StatusCode != 504 {
		t.Errorf("expected 504 Gateway Timeout halt, got action=%v status=%d", decision.Action, decision.StatusCode)
	}

	// Must terminate promptly near the 50ms deadline (< 250ms), proving context cancellation halted execution
	if duration > 300*time.Millisecond {
		t.Errorf("execution took %v, expected under 300ms", duration)
	}
}

// Test 4: Memory Bomb & Memory Page Limit Trapping
func TestWasmFilter_MemoryBomb_PageLimits(t *testing.T) {
	ctx := context.Background()
	wasmBytes := buildMemoryBombWasm()

	// Strict page limit: 2 pages (128KB max memory)
	manifest := wasm.DefaultManifest("memory-bomb-filter", "1.0.0")
	manifest.MemoryLimitPages = 2
	manifest.FailurePolicy = pipeline.FailurePolicyFailClosed

	pool, err := wasm.NewInstancePool(ctx, wasmBytes, manifest, nil)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close(ctx)

	filter := wasm.NewWasmFilter(manifest, pool, nil)
	defer filter.Close()

	env := pipeline.GetEnvelope("req-bomb", pipeline.PhaseRequestHeaders, "POST", "/bomb", nil, nil)
	defer pipeline.PutEnvelope(env)

	decision, err := filter.Process(ctx, env)
	if err == nil {
		t.Fatalf("expected guest trap on memory limit expansion, got success: %v", decision)
	}

	if decision.Action != pipeline.ActionHalt {
		t.Errorf("expected halt on memory bomb trap, got action %v", decision.Action)
	}
}

// Test 5: Forbidden Host Call & Capability Gating
func TestWasmFilter_ForbiddenHostCall(t *testing.T) {
	ctx := context.Background()
	wasmBytes := buildHostCallTestWasm()

	// Manifest intentionally leaves secret and http_call unapproved or restricted
	manifest := wasm.DefaultManifest("sandbox-test", "1.0.0")
	manifest.Capabilities.Secret = wasm.SecretCapability{
		Allowed:      true,
		AllowedNames: []string{"approved_secret_only"}, // "forbidden_token" is NOT allowed!
	}
	manifest.Capabilities.HTTPCall = wasm.HTTPCallCapability{
		Allowed:      true,
		AllowedHosts: []string{"api.internal.corp"}, // "unapproved.attacker.com" is NOT allowed!
	}

	pool, err := wasm.NewInstancePool(ctx, wasmBytes, manifest, nil)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close(ctx)

	filter := wasm.NewWasmFilter(manifest, pool, nil)
	defer filter.Close()

	env := pipeline.GetEnvelope("req-sec", pipeline.PhaseRequestHeaders, "GET", "/secure", nil, nil)
	defer pipeline.PutEnvelope(env)

	// Guest attempts to call forbidden secret and forbidden http endpoint.
	// Host functions correctly return -1, and guest completes without trap.
	decision, err := filter.Process(ctx, env)
	if err != nil {
		t.Fatalf("unexpected error in capability test: %v", err)
	}

	if decision.Action != pipeline.ActionContinue || decision.StatusCode != 200 {
		t.Errorf("expected 200 continue after verified capability denial, got %v (status %d)", decision.Action, decision.StatusCode)
	}
}

// Test 6: Panic in Guest / Unreachable Trap Handling
func TestWasmFilter_GuestPanic(t *testing.T) {
	ctx := context.Background()
	wasmBytes := buildPanicWasm()

	// 1. Fail Closed policy
	manifestClosed := wasm.DefaultManifest("panic-closed", "1.0.0")
	manifestClosed.FailurePolicy = pipeline.FailurePolicyFailClosed

	poolClosed, err := wasm.NewInstancePool(ctx, wasmBytes, manifestClosed, nil)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer poolClosed.Close(ctx)

	filterClosed := wasm.NewWasmFilter(manifestClosed, poolClosed, nil)
	defer filterClosed.Close()

	env := pipeline.GetEnvelope("req-panic", pipeline.PhaseRequestHeaders, "GET", "/panic", nil, nil)
	decClosed, errClosed := filterClosed.Process(ctx, env)
	if errClosed == nil || decClosed.Action != pipeline.ActionHalt || decClosed.StatusCode != 500 {
		t.Errorf("expected 500 halt on panic with fail-closed, got err=%v, dec=%v", errClosed, decClosed)
	}

	// 2. Fail Open policy
	manifestOpen := wasm.DefaultManifest("panic-open", "1.0.0")
	manifestOpen.FailurePolicy = pipeline.FailurePolicyFailOpen

	poolOpen, err := wasm.NewInstancePool(ctx, wasmBytes, manifestOpen, nil)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer poolOpen.Close(ctx)

	filterOpen := wasm.NewWasmFilter(manifestOpen, poolOpen, nil)
	defer filterOpen.Close()

	decOpen, errOpen := filterOpen.Process(ctx, env)
	if errOpen != nil || decOpen.Action != pipeline.ActionContinue {
		t.Errorf("expected continue on panic with fail-open, got err=%v, dec=%v", errOpen, decOpen)
	}
}

// Test 7: Hot-Swap Module Version in Shadow with Graceful Drain
func TestWasmFilter_HotSwapping(t *testing.T) {
	ctx := context.Background()

	// v1.0 returns status 200 with X-Version: v1
	v1Bytes := buildStandardPluginWasm(2, 200, "X-Version", "v1")
	m1 := wasm.DefaultManifest("hot-swap-plugin", "1.0.0")

	// v2.0 returns status 200 with X-Version: v2
	v2Bytes := buildStandardPluginWasm(2, 200, "X-Version", "v2")
	m2 := wasm.DefaultManifest("hot-swap-plugin", "2.0.0")

	mgr := wasm.NewPluginManager(nil, nil)
	defer mgr.Close()

	// Initial deployment v1
	if err := mgr.Deploy(ctx, m1, v1Bytes); err != nil {
		t.Fatalf("failed to deploy v1: %v", err)
	}

	filter, ok := mgr.GetFilter("hot-swap-plugin")
	if !ok {
		t.Fatalf("plugin not found in manager")
	}

	// Verify v1 active
	env1 := pipeline.GetEnvelope("req-v1", pipeline.PhaseRequestHeaders, "GET", "/", nil, nil)
	d1, err := filter.Process(ctx, env1)
	pipeline.PutEnvelope(env1)
	if err != nil || d1.MutateHeaders["X-Version"] != "v1" {
		t.Fatalf("expected v1 response, got %v (err: %v)", d1.MutateHeaders, err)
	}

	// Concurrent traffic while hot-swapping to v2 in shadow
	var wg sync.WaitGroup
	startSwap := make(chan struct{})
	doneTraffic := make(chan struct{})

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-startSwap
			for {
				select {
				case <-doneTraffic:
					return
				default:
					e := pipeline.GetEnvelope(fmt.Sprintf("req-%d", id), pipeline.PhaseRequestHeaders, "GET", "/", nil, nil)
					_, _ = filter.Process(ctx, e)
					pipeline.PutEnvelope(e)
					time.Sleep(5 * time.Millisecond)
				}
			}
		}(i)
	}

	close(startSwap)
	time.Sleep(20 * time.Millisecond)

	// Deploy v2.0 in shadow and hot-swap
	if err := mgr.Deploy(ctx, m2, v2Bytes); err != nil {
		t.Fatalf("hot-swap deployment of v2 failed: %v", err)
	}

	close(doneTraffic)
	wg.Wait()

	// Verify new requests execute v2
	env2 := pipeline.GetEnvelope("req-v2", pipeline.PhaseRequestHeaders, "GET", "/", nil, nil)
	d2, err := filter.Process(ctx, env2)
	pipeline.PutEnvelope(env2)
	if err != nil || d2.MutateHeaders["X-Version"] != "v2" {
		t.Errorf("expected v2 response after hot-swap, got %v (err: %v)", d2.MutateHeaders, err)
	}
}

// Benchmark per-call overhead of Wasm execution
func BenchmarkWasmFilter_PerCallOverhead(b *testing.B) {
	ctx := context.Background()
	wasmBytes := buildStandardPluginWasm(0, 200, "", "")

	manifest := wasm.DefaultManifest("bench-plugin", "1.0.0")
	manifest.PoolSize = 50

	pool, err := wasm.NewInstancePool(ctx, wasmBytes, manifest, nil)
	if err != nil {
		b.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close(ctx)

	filter := wasm.NewWasmFilter(manifest, pool, nil)
	defer filter.Close()

	env := pipeline.GetEnvelope("req-bench", pipeline.PhaseRequestHeaders, "GET", "/bench", nil, nil)
	defer pipeline.PutEnvelope(env)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = filter.Process(ctx, env)
	}
}
