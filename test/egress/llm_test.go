package egress_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/egress/llm"
	"github.com/phaselume/torana/internal/limits"
	"github.com/phaselume/torana/internal/security/authn"
	"google.golang.org/grpc/test/bufconn"
)

type fakeLLMServerOpts struct {
	return429    bool
	return500    bool
	delay        time.Duration
	streamChunks []string
}

func setupFakeLLMServer(t *testing.T, opts fakeLLMServerOpts) (*bufconn.Listener, func()) {
	lis := bufconn.Listen(1024 * 1024)
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if opts.delay > 0 {
			select {
			case <-time.After(opts.delay):
			case <-r.Context().Done():
				return
			}
		}

		if opts.return429 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"message":"Rate limit reached","type":"requests","code":"rate_limit_exceeded"}}`))
			return
		}

		if opts.return500 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"message":"Internal server error"}}`))
			return
		}

		bodyBytes, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		var req llm.ChatRequest
		_ = json.Unmarshal(bodyBytes, &req)

		if req.Stream {
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "streaming unsupported", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")

			chunks := opts.streamChunks
			if len(chunks) == 0 {
				chunks = []string{"Hello", " from", " stream!"}
			}

			for i, word := range chunks {
				data := fmt.Sprintf(`{"id":"chatcmpl-stream","choices":[{"index":0,"delta":{"content":%q},"finish_reason":null}]}`, word)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
				if i < len(chunks)-1 && opts.delay > 0 {
					time.Sleep(opts.delay)
				}
			}

			// Final usage chunk
			usageData := `{"id":"chatcmpl-stream","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":28,"total_tokens":40}}`
			_, _ = fmt.Fprintf(w, "data: %s\n\n", usageData)
			flusher.Flush()

			_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
			flusher.Flush()
			return
		}

		// Non-streaming response
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"id":    "chatcmpl-12345",
			"model": req.Model,
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": "Hello! How can I help you today?",
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     10,
				"completion_tokens": 20,
				"total_tokens":      30,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/v1/embeddings", func(w http.ResponseWriter, r *http.Request) {
		if opts.return429 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"model": "text-embedding-3-small",
			"data": []map[string]any{
				{
					"index":     0,
					"embedding": []float32{0.123, -0.456, 0.789},
				},
			},
			"usage": map[string]any{
				"prompt_tokens": 8,
				"total_tokens":  8,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(lis) }()

	cleanup := func() {
		_ = srv.Close()
		_ = lis.Close()
	}
	return lis, cleanup
}

func makeOpenAIProvider(lis *bufconn.Listener, id string) *llm.OpenAIProvider {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			},
		},
	}
	return llm.NewOpenAIProvider(llm.OpenAIConfig{
		ID:         id,
		BaseURL:    "http://bufconn/v1",
		APIKey:     "test-key",
		HTTPClient: client,
	})
}

func TestLLM_OpenAICompletion(t *testing.T) {
	lis, cleanup := setupFakeLLMServer(t, fakeLLMServerOpts{})
	defer cleanup()

	provider := makeOpenAIProvider(lis, "p-openai")
	client := llm.NewClient(nil, nil)
	client.RegisterProvider(provider)

	req := &llm.ChatRequest{
		Messages: []llm.ChatMessage{
			{Role: "user", Content: "Hello!"},
		},
		MaxTokens: 50,
	}

	resp, err := client.ChatCompletion(context.Background(), "p-openai", "gpt-4o", req, nil)
	if err != nil {
		t.Fatalf("unexpected completion error: %v", err)
	}

	if len(resp.Choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(resp.Choices))
	}
	if resp.Choices[0].Message.Content != "Hello! How can I help you today?" {
		t.Fatalf("unexpected content: %s", resp.Choices[0].Message.Content)
	}
	if resp.Usage == nil || resp.Usage.TotalTokens != 30 {
		t.Fatalf("expected 30 total tokens, got %+v", resp.Usage)
	}
}

func TestLLM_OpenAIStreaming(t *testing.T) {
	lis, cleanup := setupFakeLLMServer(t, fakeLLMServerOpts{})
	defer cleanup()

	provider := makeOpenAIProvider(lis, "p-openai")
	client := llm.NewClient(nil, nil)
	client.RegisterProvider(provider)

	req := &llm.ChatRequest{
		Messages: []llm.ChatMessage{
			{Role: "user", Content: "Stream to me"},
		},
	}

	stream, err := client.StreamChatCompletion(context.Background(), "p-openai", "gpt-4o", req, nil)
	if err != nil {
		t.Fatalf("failed to start stream: %v", err)
	}
	defer stream.Close()

	var assembled string
	for {
		chunk, err := stream.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("unexpected stream error: %v", err)
		}
		assembled += chunk.Delta.Content
	}

	if assembled != "Hello from stream!" {
		t.Fatalf("expected 'Hello from stream!', got %q", assembled)
	}

	usage := stream.Usage()
	if usage == nil || usage.TotalTokens != 40 {
		t.Fatalf("expected usage 40 total tokens from stream, got %+v", usage)
	}
}

func TestLLM_OpenAIEmbeddings(t *testing.T) {
	lis, cleanup := setupFakeLLMServer(t, fakeLLMServerOpts{})
	defer cleanup()

	provider := makeOpenAIProvider(lis, "p-openai")
	client := llm.NewClient(nil, nil)
	client.RegisterProvider(provider)

	req := &llm.EmbeddingRequest{
		Input: []string{"document text to vectorize"},
	}

	resp, err := client.Embeddings(context.Background(), "p-openai", "text-embedding-3-small", req, nil)
	if err != nil {
		t.Fatalf("unexpected embeddings error: %v", err)
	}

	if len(resp.Data) != 1 || len(resp.Data[0]) != 3 {
		t.Fatalf("expected 1 vector with 3 dimensions, got %+v", resp.Data)
	}
	if resp.Usage == nil || resp.Usage.PromptTokens != 8 {
		t.Fatalf("expected 8 prompt tokens, got %+v", resp.Usage)
	}
}

func TestLLM_LimitsTwoStageAccounting(t *testing.T) {
	lis, cleanup := setupFakeLLMServer(t, fakeLLMServerOpts{})
	defer cleanup()

	// Configure limiter with minute budget of 100 tokens
	limiter := limits.NewLimiter(limits.LimiterConfig{
		Store: limits.NewLocalCounterStore(nil, 30*time.Second),
		DefaultBudget: &limits.BudgetRule{
			Limits: map[limits.Window]int64{
				limits.WindowMinute: 100,
			},
		},
	})

	provider := makeOpenAIProvider(lis, "p-openai")
	client := llm.NewClient(limiter, nil)
	client.RegisterProvider(provider)

	ident := authn.NewIdentity("developer-alice", "tenant-engineering", "api_key")

	req := &llm.ChatRequest{
		Messages:  []llm.ChatMessage{{Role: "user", Content: "Hello"}},
		MaxTokens: 20,
	}

	// 1. First completion succeeds and reconciles actual tokens (30 tokens)
	resp, err := client.ChatCompletion(context.Background(), "p-openai", "gpt-4o", req, ident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Usage.TotalTokens != 30 {
		t.Fatalf("expected 30 tokens, got %d", resp.Usage.TotalTokens)
	}

	// 2. Stream completion succeeds and reconciles actual tokens (40 tokens)
	stream, err := client.StreamChatCompletion(context.Background(), "p-openai", "gpt-4o", req, ident)
	if err != nil {
		t.Fatalf("failed to start stream: %v", err)
	}
	for {
		_, err := stream.Next()
		if errors.Is(err, io.EOF) {
			break
		}
	}
	_ = stream.Close() // Triggers reconciliation

	// Total consumed so far: 30 + 40 = 70 tokens. Remaining in 100-token budget: 30.
	// 3. Third request asks for MaxTokens 50 -> EstimateTokens is ~51 tokens, which exceeds remaining 30!
	hugeReq := &llm.ChatRequest{
		Messages:  []llm.ChatMessage{{Role: "user", Content: "Give me a huge response"}},
		MaxTokens: 50,
	}

	_, err = client.ChatCompletion(context.Background(), "p-openai", "gpt-4o", hugeReq, ident)
	if err == nil {
		t.Fatalf("expected rate limit rejection due to budget exhaustion, but succeeded")
	}
}

func TestLLM_FallbackChain_On429(t *testing.T) {
	// Primary returns 429 rate limit
	primaryLis, primaryCleanup := setupFakeLLMServer(t, fakeLLMServerOpts{return429: true})
	defer primaryCleanup()

	// Secondary succeeds
	secondaryLis, secondaryCleanup := setupFakeLLMServer(t, fakeLLMServerOpts{})
	defer secondaryCleanup()

	primaryProvider := makeOpenAIProvider(primaryLis, "primary")
	secondaryProvider := makeOpenAIProvider(secondaryLis, "secondary")

	client := llm.NewClient(nil, nil)
	client.RegisterProvider(primaryProvider)
	client.RegisterProvider(secondaryProvider)

	client.RegisterFallbackChain("chain-robust", []llm.TargetEndpoint{
		{Provider: primaryProvider, Model: "gpt-4o"},
		{Provider: secondaryProvider, Model: "claude-3-5-sonnet"},
	})

	req := &llm.ChatRequest{
		Messages: []llm.ChatMessage{{Role: "user", Content: "Hello fallback"}},
	}

	resp, err := client.ExecuteChainChat(context.Background(), "chain-robust", "gpt-4o", req, nil)
	if err != nil {
		t.Fatalf("expected fallback to secondary provider to succeed, got %v", err)
	}
	if resp.Choices[0].Message.Content != "Hello! How can I help you today?" {
		t.Fatalf("unexpected content from fallback: %s", resp.Choices[0].Message.Content)
	}
}

func TestLLM_FallbackChain_OnTimeout(t *testing.T) {
	// Primary delays by 500ms
	primaryLis, primaryCleanup := setupFakeLLMServer(t, fakeLLMServerOpts{delay: 500 * time.Millisecond})
	defer primaryCleanup()

	// Secondary returns immediately
	secondaryLis, secondaryCleanup := setupFakeLLMServer(t, fakeLLMServerOpts{})
	defer secondaryCleanup()

	primaryProvider := makeOpenAIProvider(primaryLis, "primary-slow")
	secondaryProvider := makeOpenAIProvider(secondaryLis, "secondary-fast")

	client := llm.NewClient(nil, nil)
	client.RegisterProvider(primaryProvider)
	client.RegisterProvider(secondaryProvider)

	client.RegisterFallbackChain("chain-timeout", []llm.TargetEndpoint{
		{Provider: primaryProvider, Model: "gpt-4o", Timeout: 20 * time.Millisecond},
		{Provider: secondaryProvider, Model: "gpt-4o-mini", Timeout: 2 * time.Second},
	})

	req := &llm.ChatRequest{
		Messages: []llm.ChatMessage{{Role: "user", Content: "Speed test"}},
	}

	resp, err := client.ExecuteChainChat(context.Background(), "chain-timeout", "gpt-4o", req, nil)
	if err != nil {
		t.Fatalf("expected secondary provider to succeed after primary timeout, got %v", err)
	}
	if resp == nil || len(resp.Choices) == 0 {
		t.Fatalf("expected valid choice from fallback")
	}
}

func TestLLM_PerModelTimeout(t *testing.T) {
	lis, cleanup := setupFakeLLMServer(t, fakeLLMServerOpts{delay: 200 * time.Millisecond})
	defer cleanup()

	provider := makeOpenAIProvider(lis, "p-slow")
	client := llm.NewClient(nil, nil)
	client.RegisterProvider(provider)

	// Set per-model timeout to 20ms
	client.SetModelTimeout("gpt-slow", 20*time.Millisecond)

	req := &llm.ChatRequest{
		Messages: []llm.ChatMessage{{Role: "user", Content: "Time me out"}},
	}

	_, err := client.ChatCompletion(context.Background(), "p-slow", "gpt-slow", req, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

func BenchmarkLLM_Streaming(b *testing.B) {
	lis, cleanup := setupFakeLLMServer(&testing.T{}, fakeLLMServerOpts{
		streamChunks: []string{"The", " quick", " brown", " fox", " jumps", " over", " the", " lazy", " dog"},
	})
	defer cleanup()

	provider := makeOpenAIProvider(lis, "bench-provider")
	client := llm.NewClient(nil, nil)
	client.RegisterProvider(provider)

	req := &llm.ChatRequest{
		Messages: []llm.ChatMessage{{Role: "user", Content: "bench stream"}},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		stream, err := client.StreamChatCompletion(context.Background(), "bench-provider", "gpt-4o", req, nil)
		if err != nil {
			b.Fatalf("failed to open stream: %v", err)
		}
		for {
			_, err := stream.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				b.Fatalf("stream next err: %v", err)
			}
		}
		_ = stream.Close()
	}
}
