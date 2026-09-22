package wasm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tetratelabs/wazero/api"
	"github.com/phaselume/torana/internal/pipeline"
)

// WasmEnvelope is the JSON wire representation of the pipeline envelope delivered to a plugin.
type WasmEnvelope struct {
	RequestID string            `json:"request_id"`
	Phase     int               `json:"phase"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Metadata  map[string]string `json:"metadata"`
	Claims    map[string]string `json:"claims"`
	Body      []byte            `json:"body,omitempty"`
	ClientIP  string            `json:"client_ip,omitempty"`
}

// WasmDecision is the JSON wire representation of the decision returned by the guest plugin.
type WasmDecision struct {
	Action         int               `json:"action"`
	StatusCode     int               `json:"status_code"`
	Reason         string            `json:"reason,omitempty"`
	MutateHeaders  map[string]string `json:"mutate_headers,omitempty"`
	MutateBody     []byte            `json:"mutate_body,omitempty"`
	MutateMetadata map[string]string `json:"mutate_metadata,omitempty"`
}

// ConvertEnvelopeToWasm serializes a pipeline.Envelope into a WasmEnvelope.
func ConvertEnvelopeToWasm(env *pipeline.Envelope, body []byte) *WasmEnvelope {
	headers := make(map[string]string, len(env.Headers))
	for k, v := range env.Headers {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	metadata := make(map[string]string, len(env.Metadata))
	for k, v := range env.Metadata {
		metadata[k] = v
	}

	claims := make(map[string]string, len(env.Claims))
	for k, v := range env.Claims {
		claims[k] = v
	}

	return &WasmEnvelope{
		RequestID: env.RequestID,
		Phase:     int(env.Phase),
		Method:    env.Method,
		Path:      env.Path,
		Headers:   headers,
		Metadata:  metadata,
		Claims:    claims,
		Body:      body,
		ClientIP:  env.PeerInfo.RemoteIP,
	}
}

// ConvertWasmToDecision translates a WasmDecision into a pipeline.Decision.
func ConvertWasmToDecision(wd *WasmDecision) pipeline.Decision {
	if wd == nil {
		return pipeline.ContinueDecision()
	}

	statusCode := wd.StatusCode
	if statusCode == 0 {
		statusCode = 200
	}

	return pipeline.Decision{
		Action:         pipeline.Action(wd.Action),
		StatusCode:     statusCode,
		Reason:         wd.Reason,
		MutateHeaders:  wd.MutateHeaders,
		MutateBody:     wd.MutateBody,
		MutateMetadata: wd.MutateMetadata,
	}
}

// WriteBytesToGuest allocates guest memory using guest's exported "alloc" function and writes data.
func WriteBytesToGuest(ctx context.Context, mod api.Module, data []byte) (uint32, uint32, error) {
	size := uint32(len(data))
	if size == 0 {
		return 0, 0, nil
	}

	allocFn := mod.ExportedFunction("alloc")
	if allocFn == nil {
		allocFn = mod.ExportedFunction("malloc")
	}
	if allocFn == nil {
		allocFn = mod.ExportedFunction("torana_alloc")
	}
	if allocFn == nil {
		return 0, 0, fmt.Errorf("wasm module does not export an alloc function")
	}

	results, err := allocFn.Call(ctx, uint64(size))
	if err != nil {
		return 0, 0, fmt.Errorf("alloc failed in guest: %w", err)
	}

	ptr := uint32(results[0])
	if !mod.Memory().Write(ptr, data) {
		return 0, 0, fmt.Errorf("failed to write %d bytes to guest linear memory at %d", size, ptr)
	}

	return ptr, size, nil
}

// ReadBytesFromGuest reads data from linear memory and optionally deallocates it.
func ReadBytesFromGuest(ctx context.Context, mod api.Module, ptr, size uint32) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}

	data, ok := mod.Memory().Read(ptr, size)
	if !ok {
		return nil, fmt.Errorf("failed to read %d bytes from guest linear memory at %d", size, ptr)
	}

	result := make([]byte, size)
	copy(result, data)

	// Free in guest if dealloc function exists
	deallocFn := mod.ExportedFunction("dealloc")
	if deallocFn == nil {
		deallocFn = mod.ExportedFunction("free")
	}
	if deallocFn != nil {
		_, _ = deallocFn.Call(ctx, uint64(ptr), uint64(size))
	}

	return result, nil
}

// UnpackResult unpacks a 64-bit integer into (ptr, size).
func UnpackResult(packed uint64) (uint32, uint32) {
	ptr := uint32(packed >> 32)
	size := uint32(packed & 0xFFFFFFFF)
	return ptr, size
}

// PackResult packs (ptr, size) into a single 64-bit integer.
func PackResult(ptr, size uint32) uint64 {
	return (uint64(ptr) << 32) | uint64(size)
}

// MarshalJSONEnvelope encodes WasmEnvelope to bytes.
func MarshalJSONEnvelope(env *WasmEnvelope) ([]byte, error) {
	return json.Marshal(env)
}

// UnmarshalJSONDecision decodes bytes into WasmDecision.
func UnmarshalJSONDecision(data []byte) (*WasmDecision, error) {
	var dec WasmDecision
	if err := json.Unmarshal(data, &dec); err != nil {
		return nil, err
	}
	return &dec, nil
}
