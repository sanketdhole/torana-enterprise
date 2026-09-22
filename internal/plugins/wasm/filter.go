package wasm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
)

// WasmFilter implements pipeline.Filter and pipeline.ChunkHook backed by a pooled Wazero Wasm runtime.
type WasmFilter struct {
	manifest *PluginManifest
	pool     *InstancePool
	logger   *slog.Logger
}

// NewWasmFilter creates a new WasmFilter wrapping an InstancePool.
func NewWasmFilter(manifest *PluginManifest, pool *InstancePool, logger *slog.Logger) *WasmFilter {
	return &WasmFilter{
		manifest: manifest,
		pool:     pool,
		logger:   logger,
	}
}

// Name returns the plugin's declared identifier.
func (f *WasmFilter) Name() string {
	return f.manifest.Name
}

// Phase returns the lifecycle phase this filter executes in.
func (f *WasmFilter) Phase() pipeline.Phase {
	return f.manifest.Phase
}

// BodyMode declares whether this filter inspects headers only, buffered body, or streaming chunks.
func (f *WasmFilter) BodyMode() pipeline.BodyMode {
	return f.manifest.BodyMode
}

// FailurePolicy defines fail-closed vs fail-open behavior.
func (f *WasmFilter) FailurePolicy() pipeline.FailurePolicy {
	return f.manifest.FailurePolicy
}

// Manifest returns the active plugin manifest configuration.
func (f *WasmFilter) Manifest() *PluginManifest {
	return f.manifest
}

// Process evaluates a pipeline.Envelope through the Wasm guest plugin.
func (f *WasmFilter) Process(ctx context.Context, env *pipeline.Envelope) (pipeline.Decision, error) {
	// 1. Resolve body according to declared BodyMode
	var bodyBytes []byte
	var err error

	if f.manifest.BodyMode == pipeline.BodyModeBuffered {
		maxBytes := f.manifest.MaxBufferBytes
		if maxBytes <= 0 {
			maxBytes = 1024 * 1024 // 1MB default
		}
		bodyBytes, err = env.GetBufferedBody(maxBytes)
		if err != nil {
			return f.handleError(fmt.Errorf("failed to buffer body for wasm plugin: %w", err))
		}
	}

	// 2. Prepare JSON wire envelope
	wasmEnv := ConvertEnvelopeToWasm(env, bodyBytes)
	envData, err := MarshalJSONEnvelope(wasmEnv)
	if err != nil {
		return f.handleError(fmt.Errorf("failed to marshal wasm envelope: %w", err))
	}

	// 3. Acquire instance from pool
	inst, err := f.pool.Get(ctx)
	if err != nil {
		return f.handleError(err)
	}
	defer func() {
		f.pool.Put(inst)
	}()

	// 4. Apply per-call timeout via context cancellation
	timeout := f.manifest.Timeout
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 5. Transfer payload into guest memory
	inPtr, inLen, err := WriteBytesToGuest(callCtx, inst.Module, envData)
	if err != nil {
		inst.Faulted = true
		return f.handleError(fmt.Errorf("failed to write envelope to guest: %w", err))
	}

	// 6. Invoke guest "process" function
	processFn := inst.Module.ExportedFunction("process")
	if processFn == nil {
		processFn = inst.Module.ExportedFunction("on_request")
	}
	if processFn == nil {
		inst.Faulted = true
		return f.handleError(fmt.Errorf("wasm module does not export 'process' or 'on_request'"))
	}

	results, err := processFn.Call(callCtx, uint64(inPtr), uint64(inLen))
	if err != nil {
		inst.Faulted = true
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			return f.handleError(ErrExecutionTimeout)
		}
		return f.handleError(fmt.Errorf("%w: %v", ErrGuestTrap, err))
	}

	if len(results) == 0 {
		return pipeline.ContinueDecision(), nil
	}

	// 7. Read decision from guest memory
	outPtr, outLen := UnpackResult(results[0])
	if outLen == 0 {
		return pipeline.ContinueDecision(), nil
	}

	outBytes, err := ReadBytesFromGuest(callCtx, inst.Module, outPtr, outLen)
	if err != nil {
		inst.Faulted = true
		return f.handleError(fmt.Errorf("failed to read decision from guest: %w", err))
	}

	wasmDec, err := UnmarshalJSONDecision(outBytes)
	if err != nil {
		return f.handleError(fmt.Errorf("failed to parse wasm decision: %w", err))
	}

	return ConvertWasmToDecision(wasmDec), nil
}

// OnChunk inspects or mutates an individual streaming chunk or WebSocket message.
func (f *WasmFilter) OnChunk(ctx context.Context, env *pipeline.Envelope, chunk []byte) ([]byte, error) {
	if len(chunk) == 0 {
		return chunk, nil
	}

	inst, err := f.pool.Get(ctx)
	if err != nil {
		if f.manifest.FailurePolicy == pipeline.FailurePolicyFailOpen {
			return chunk, nil
		}
		return nil, err
	}
	defer f.pool.Put(inst)

	timeout := f.manifest.Timeout
	if timeout <= 0 {
		timeout = 50 * time.Millisecond
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	onChunkFn := inst.Module.ExportedFunction("on_chunk")
	if onChunkFn == nil {
		// Module doesn't implement OnChunk, pass through
		return chunk, nil
	}

	inPtr, inLen, err := WriteBytesToGuest(callCtx, inst.Module, chunk)
	if err != nil {
		inst.Faulted = true
		if f.manifest.FailurePolicy == pipeline.FailurePolicyFailOpen {
			return chunk, nil
		}
		return nil, err
	}

	results, err := onChunkFn.Call(callCtx, uint64(inPtr), uint64(inLen))
	if err != nil {
		inst.Faulted = true
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			if f.manifest.FailurePolicy == pipeline.FailurePolicyFailOpen {
				return chunk, nil
			}
			return nil, ErrExecutionTimeout
		}
		if f.manifest.FailurePolicy == pipeline.FailurePolicyFailOpen {
			return chunk, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrGuestTrap, err)
	}

	if len(results) == 0 {
		return chunk, nil
	}

	outPtr, outLen := UnpackResult(results[0])
	if outLen == 0 {
		return chunk, nil
	}

	outBytes, err := ReadBytesFromGuest(callCtx, inst.Module, outPtr, outLen)
	if err != nil {
		inst.Faulted = true
		if f.manifest.FailurePolicy == pipeline.FailurePolicyFailOpen {
			return chunk, nil
		}
		return nil, err
	}

	return outBytes, nil
}

func (f *WasmFilter) handleError(err error) (pipeline.Decision, error) {
	if f.logger != nil {
		f.logger.Warn("wasm plugin execution error", "plugin", f.manifest.Name, "policy", f.manifest.FailurePolicy, "error", err)
	}

	if f.manifest.FailurePolicy == pipeline.FailurePolicyFailOpen {
		return pipeline.ContinueDecision(), nil
	}

	statusCode := 500
	if errors.Is(err, ErrExecutionTimeout) {
		statusCode = 504 // Gateway Timeout
	}

	return pipeline.HaltDecision(statusCode, err.Error()), err
}

// Close gracefully releases the underlying instance pool.
func (f *WasmFilter) Close() error {
	return f.pool.Close(context.Background())
}
