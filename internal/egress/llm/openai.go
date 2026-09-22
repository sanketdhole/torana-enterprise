package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/phaselume/torana/internal/limits"
)

// OpenAIConfig configures an OpenAI-compatible provider.
type OpenAIConfig struct {
	ID         string
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
	Timeout    time.Duration
}

// OpenAIProvider implements the Provider interface for OpenAI and OpenAI-compatible backends
// (including vLLM, Ollama, Groq, Together, DeepSeek, etc.).
type OpenAIProvider struct {
	id         string
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewOpenAIProvider creates an OpenAI-compatible provider.
func NewOpenAIProvider(cfg OpenAIConfig) *OpenAIProvider {
	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        500,
				MaxIdleConnsPerHost: 50,
				IdleConnTimeout:     90 * time.Second,
			},
		}
	}

	return &OpenAIProvider{
		id:         cfg.ID,
		baseURL:    baseURL,
		apiKey:     cfg.APIKey,
		httpClient: client,
	}
}

// ID returns the provider identifier.
func (p *OpenAIProvider) ID() string {
	return p.id
}

// ChatCompletion executes a synchronous, non-streaming chat completion.
func (p *OpenAIProvider) ChatCompletion(ctx context.Context, model string, req *ChatRequest) (*ChatResponse, error) {
	cloneReq := *req
	cloneReq.Model = model
	cloneReq.Stream = false

	bodyBytes, err := json.Marshal(cloneReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal chat request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	p.applyHeaders(httpReq)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("%w: %s", ErrRateLimit429, string(respBytes))
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("upstream openai error (status %d): %s", resp.StatusCode, string(respBytes))
	}

	var chatResp struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Index   int `json:"index"`
			Message struct {
				Role       string     `json:"role"`
				Content    string     `json:"content"`
				Name       string     `json:"name,omitempty"`
				ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
				ToolCallID string     `json:"tool_call_id,omitempty"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(respBytes, &chatResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal chat response: %w", err)
	}

	usage, _ := limits.ParseUsageFromBody(respBytes)

	choices := make([]ChatChoice, len(chatResp.Choices))
	for i, c := range chatResp.Choices {
		choices[i] = ChatChoice{
			Index: c.Index,
			Message: ChatMessage{
				Role:       c.Message.Role,
				Content:    c.Message.Content,
				Name:       c.Message.Name,
				ToolCalls:  c.Message.ToolCalls,
				ToolCallID: c.Message.ToolCallID,
			},
			FinishReason: c.FinishReason,
		}
	}

	return &ChatResponse{
		ID:      chatResp.ID,
		Model:   chatResp.Model,
		Choices: choices,
		Usage:   usage,
	}, nil
}

// StreamChatCompletion opens an SSE stream for chat completion deltas.
func (p *OpenAIProvider) StreamChatCompletion(ctx context.Context, model string, req *ChatRequest) (ChatStream, error) {
	// Include stream_options to request token usage in final stream chunk
	type openAIStreamReq struct {
		ChatRequest
		StreamOptions map[string]any `json:"stream_options,omitempty"`
	}

	sReq := openAIStreamReq{
		ChatRequest: *req,
		StreamOptions: map[string]any{
			"include_usage": true,
		},
	}
	sReq.Model = model
	sReq.Stream = true

	bodyBytes, err := json.Marshal(sReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal stream request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	p.applyHeaders(httpReq)
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: %s", ErrRateLimit429, string(body))
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("upstream openai stream error (status %d): %s", resp.StatusCode, string(body))
	}

	return newOpenAIStream(resp.Body), nil
}

// Embeddings generates vector embeddings for input strings.
func (p *OpenAIProvider) Embeddings(ctx context.Context, model string, req *EmbeddingRequest) (*EmbeddingResponse, error) {
	cloneReq := *req
	cloneReq.Model = model

	bodyBytes, err := json.Marshal(cloneReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal embedding request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/embeddings", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	p.applyHeaders(httpReq)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read embeddings response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("%w: %s", ErrRateLimit429, string(respBytes))
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("upstream embeddings error (status %d): %s", resp.StatusCode, string(respBytes))
	}

	var rawResp struct {
		Model string `json:"model"`
		Data  []struct {
			Embedding []float32 `json:"embedding"`
			Index     int       `json:"index"`
		} `json:"data"`
	}

	if err := json.Unmarshal(respBytes, &rawResp); err != nil {
		return nil, fmt.Errorf("failed to parse embeddings response: %w", err)
	}

	usage, _ := limits.ParseUsageFromBody(respBytes)

	vectors := make([][]float32, len(rawResp.Data))
	for _, item := range rawResp.Data {
		if item.Index < len(vectors) {
			vectors[item.Index] = item.Embedding
		}
	}

	return &EmbeddingResponse{
		Model: rawResp.Model,
		Data:  vectors,
		Usage: usage,
	}, nil
}

// Close closes idle transport connections.
func (p *OpenAIProvider) Close() error {
	p.httpClient.CloseIdleConnections()
	return nil
}

func (p *OpenAIProvider) applyHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
}

// openAIStream parses SSE data frames into ChatChunks and captures usage.
type openAIStream struct {
	reader io.ReadCloser
	scanner *bufio.Scanner
	mu     sync.Mutex
	usage  *limits.TokenUsage
	closed bool
}

func newOpenAIStream(reader io.ReadCloser) *openAIStream {
	return &openAIStream{
		reader:  reader,
		scanner: bufio.NewScanner(reader),
	}
}

func (s *openAIStream) Next() (*ChatChunk, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrStreamClosed
	}

	for s.scanner.Scan() {
		line := bytes.TrimSpace(s.scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}

		data := bytes.TrimSpace(line[5:])
		if bytes.Equal(data, []byte("[DONE]")) {
			return nil, io.EOF
		}

		// Inspect chunk for usage
		if u, ok := limits.ParseUsageFromChunk(line); ok {
			s.usage = u
		}

		var rawChunk struct {
			ID      string `json:"id"`
			Choices []struct {
				Delta struct {
					Role       string     `json:"role"`
					Content    string     `json:"content"`
					ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
					ToolCallID string     `json:"tool_call_id,omitempty"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage *limits.TokenUsage `json:"usage,omitempty"`
		}

		if err := json.Unmarshal(data, &rawChunk); err != nil {
			continue
		}

		if rawChunk.Usage != nil {
			s.usage = rawChunk.Usage
		}

		deltaMsg := ChatMessage{}
		finishReason := ""
		if len(rawChunk.Choices) > 0 {
			c := rawChunk.Choices[0]
			deltaMsg.Role = c.Delta.Role
			deltaMsg.Content = c.Delta.Content
			deltaMsg.ToolCalls = c.Delta.ToolCalls
			deltaMsg.ToolCallID = c.Delta.ToolCallID
			finishReason = c.FinishReason
		}

		return &ChatChunk{
			ID:           rawChunk.ID,
			Delta:        deltaMsg,
			FinishReason: finishReason,
			Usage:        s.usage,
		}, nil
	}

	if err := s.scanner.Err(); err != nil {
		return nil, err
	}

	return nil, io.EOF
}

func (s *openAIStream) Usage() *limits.TokenUsage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usage
}

func (s *openAIStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return s.reader.Close()
}
