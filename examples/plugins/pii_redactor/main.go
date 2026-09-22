package main

import (
	"encoding/json"
	"regexp"
	"unsafe"
)

var (
	ssnRegex   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
)

// WasmEnvelope mirrors the Torana host envelope.
type WasmEnvelope struct {
	Body []byte `json:"body"`
}

// WasmDecision mirrors the Torana host decision.
type WasmDecision struct {
	Action     int    `json:"action"` // 0=Continue, 2=Mutate
	StatusCode int    `json:"status_code"`
	MutateBody []byte `json:"mutate_body,omitempty"`
}

//export alloc
func alloc(size uint32) *byte {
	buf := make([]byte, size)
	return &buf[0]
}

//export dealloc
func dealloc(ptr *byte, size uint32) {}

// Redact sanitizes SSNs and emails in raw text.
func redactText(input []byte) []byte {
	res := ssnRegex.ReplaceAll(input, []byte("***-**-****"))
	res = emailRegex.ReplaceAll(res, []byte("[REDACTED_EMAIL]"))
	return res
}

//export process
func process(ptr *byte, size uint32) uint64 {
	data := unsafe.Slice(ptr, size)

	var env WasmEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return 0
	}

	redacted := redactText(env.Body)
	dec := WasmDecision{
		Action:     2, // Mutate
		StatusCode: 200,
		MutateBody: redacted,
	}

	outBytes, _ := json.Marshal(dec)
	outPtr := &outBytes[0]
	outLen := uint32(len(outBytes))
	return (uint64(uintptr(unsafe.Pointer(outPtr))) << 32) | uint64(outLen)
}

//export on_chunk
func on_chunk(ptr *byte, size uint32) uint64 {
	data := unsafe.Slice(ptr, size)
	redacted := redactText(data)

	outPtr := &redacted[0]
	outLen := uint32(len(redacted))
	return (uint64(uintptr(unsafe.Pointer(outPtr))) << 32) | uint64(outLen)
}

func main() {}
