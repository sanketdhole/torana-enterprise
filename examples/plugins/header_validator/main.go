package main

import (
	"encoding/json"
	"unsafe"
)

// WasmEnvelope mirrors the Torana host envelope.
type WasmEnvelope struct {
	RequestID string            `json:"request_id"`
	Headers   map[string]string `json:"headers"`
	Path      string            `json:"path"`
	Method    string            `json:"method"`
}

// WasmDecision mirrors the Torana host decision.
type WasmDecision struct {
	Action        int               `json:"action"` // 0=Continue, 1=Halt, 2=Mutate
	StatusCode    int               `json:"status_code"`
	Reason        string            `json:"reason,omitempty"`
	MutateHeaders map[string]string `json:"mutate_headers,omitempty"`
}

//export alloc
func alloc(size uint32) *byte {
	buf := make([]byte, size)
	return &buf[0]
}

//export dealloc
func dealloc(ptr *byte, size uint32) {
	// Garbage collector in TinyGo will reclaim unused memory
}

//export process
func process(ptr *byte, size uint32) uint64 {
	data := unsafe.Slice(ptr, size)

	var env WasmEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return encodeDecision(WasmDecision{
			Action:     1, // Halt
			StatusCode: 400,
			Reason:     "Invalid envelope JSON",
		})
	}

	// Validate presence of API Key or Authorization header
	apiKey := env.Headers["x-api-key"]
	authHeader := env.Headers["authorization"]

	if apiKey == "" && authHeader == "" {
		return encodeDecision(WasmDecision{
			Action:     1, // Halt
			StatusCode: 401,
			Reason:     "Missing required authentication credentials (X-API-Key or Authorization)",
		})
	}

	// Passed validation: inject audit trace header
	return encodeDecision(WasmDecision{
		Action: 2, // Mutate
		MutateHeaders: map[string]string{
			"X-Validated-By": "Torana-Wasm-HeaderValidator/1.0",
		},
	})
}

func encodeDecision(d WasmDecision) uint64 {
	outBytes, _ := json.Marshal(d)
	ptr := &outBytes[0]
	length := uint32(len(outBytes))
	return (uint64(uintptr(unsafe.Pointer(ptr))) << 32) | uint64(length)
}

func main() {}
