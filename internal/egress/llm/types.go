package llm

import (
	"context"
	"errors"
	"time"

	"github.com/phaselume/torana/internal/limits"
)

var (
	// ErrProviderNotFound is returned when no provider is registered for an ID.
	ErrProviderNotFound = errors.New("llm provider not found")
	// ErrFallbackExhausted is returned when all primary and fallback providers have failed.
	ErrFallbackExhausted = errors.New("all providers in fallback chain exhausted")
	// ErrRateLimit429 is returned when an upstream provider signals HTTP 429 Too Many Requests.
	ErrRateLimit429 = errors.New("upstream provider rate limited (429)")
	// ErrStreamClosed is returned when attempting to read from a closed stream.
	ErrStreamClosed = errors.New("chat stream is closed")
)

// ChatMessage represents a single turn in a conversational completion.
type ChatMessage struct {
	Role       string     `json:"role"` // "system", "user", "assistant", "tool"
	Content    string     `json:"content"`
	Name       string     `json:"name,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// ToolCall represents a model-requested function or tool invocation.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"` // e.g. "function"
	Function FunctionCall `json:"function"`
}

// FunctionCall describes the specific function name and JSON arguments.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ChatRequest defines parameters for a chat completion request.
type ChatRequest struct {
	Model       string        `json:"model"`
	Messages    []ChatMessage `json:"messages"`
	Temperature *float32      `json:"temperature,omitempty"`
	TopP        *float32      `json:"top_p,omitempty"`
	MaxTokens   int64         `json:"max_tokens,omitempty"`
	Stream      bool          `json:"stream,omitempty"`
	Stop        []string      `json:"stop,omitempty"`
}

// ChatChoice represents an individual choice in a chat completion response.
type ChatChoice struct {
	Index        int         `json:"index"`
	Message      ChatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

// ChatResponse holds the output of a non-streaming chat completion.
type ChatResponse struct {
	ID      string             `json:"id"`
	Model   string             `json:"model"`
	Choices []ChatChoice       `json:"choices"`
	Usage   *limits.TokenUsage `json:"usage,omitempty"`
}

// ChatChunk represents a single delta frame emitted in a streaming completion.
type ChatChunk struct {
	ID           string             `json:"id"`
	Delta        ChatMessage        `json:"delta"`
	FinishReason string             `json:"finish_reason,omitempty"`
	Usage        *limits.TokenUsage `json:"usage,omitempty"`
}

// ChatStream defines an iterator over streaming completion chunks.
type ChatStream interface {
	// Next returns the next chunk. It returns io.EOF when the stream terminates.
	Next() (*ChatChunk, error)
	// Usage returns the token usage accumulated or reported in the stream.
	Usage() *limits.TokenUsage
	// Close releases underlying HTTP response and resources.
	Close() error
}

// EmbeddingRequest defines parameters for computing vector embeddings.
type EmbeddingRequest struct {
	Model      string   `json:"model"`
	Input      []string `json:"input"`
	Dimensions int      `json:"dimensions,omitempty"`
}

// EmbeddingResponse holds the computed embedding vectors and token usage.
type EmbeddingResponse struct {
	Model string             `json:"model"`
	Data  [][]float32        `json:"data"`
	Usage *limits.TokenUsage `json:"usage,omitempty"`
}

// Provider defines the standard pluggable egress interface for LLM backends.
// This interface allows adding Bedrock, Anthropic, vLLM, Ollama, etc. seamlessly.
type Provider interface {
	ID() string
	ChatCompletion(ctx context.Context, model string, req *ChatRequest) (*ChatResponse, error)
	StreamChatCompletion(ctx context.Context, model string, req *ChatRequest) (ChatStream, error)
	Embeddings(ctx context.Context, model string, req *EmbeddingRequest) (*EmbeddingResponse, error)
	Close() error
}

// TargetEndpoint specifies an individual target in a fallback chain.
type TargetEndpoint struct {
	Provider Provider      `json:"-"`
	Model    string        `json:"model"`
	Timeout  time.Duration `json:"timeout,omitempty"`
}
