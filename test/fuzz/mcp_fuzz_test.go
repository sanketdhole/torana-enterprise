package fuzz_test

import (
	"encoding/json"
	"testing"

	"github.com/phaselume/torana/internal/ingress/mcp"
)

// FuzzMCPParseRequest exercises the MCP JSON-RPC request parser with random bytes.
// Must never panic regardless of input.
func FuzzMCPParseRequest(f *testing.F) {
	// Seed corpus: valid JSON-RPC requests
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":"abc","method":"tools/list"}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":null,"method":"notifications/cancelled","params":{"requestId":"x"}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search","arguments":{"q":"hello"}}}`))

	// Edge cases
	f.Add([]byte(`{}`))                                 // empty object
	f.Add([]byte(`[]`))                                 // array (batch)
	f.Add([]byte(`null`))                               // null
	f.Add([]byte(`"not an object"`))                    // string
	f.Add([]byte(`{"jsonrpc":"1.0","id":1}`))           // wrong version
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":""}`)) // empty method
	f.Add([]byte{0xff, 0xfe, 0x00, 0x01})              // binary garbage
	f.Add(make([]byte, 1<<16))                          // large zero payload

	f.Fuzz(func(t *testing.T, data []byte) {
		// Parse as single JSON-RPC request — must not panic.
		var req mcp.JSONRPCRequest
		_ = json.Unmarshal(data, &req)

		// Also exercise batch parsing.
		var batch []mcp.JSONRPCRequest
		_ = json.Unmarshal(data, &batch)

		// Validate the IsNotification helper if parse succeeded.
		if req.Method != "" {
			_ = req.IsNotification()
		}

		// Parse specific MCP param types — must not panic.
		if req.Method == "initialize" && len(req.Params) > 0 {
			var params mcp.InitializeParams
			_ = json.Unmarshal(req.Params, &params)
		}
		if req.Method == "tools/call" && len(req.Params) > 0 {
			var params mcp.ToolCallParams
			_ = json.Unmarshal(req.Params, &params)
		}
		if (req.Method == "$/cancelRequest" || req.Method == "notifications/cancelled") && len(req.Params) > 0 {
			var params mcp.CancelParams
			_ = json.Unmarshal(req.Params, &params)
		}
	})
}
