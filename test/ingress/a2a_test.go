package ingress_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/config"
	ingressa2a "github.com/phaselume/torana/internal/ingress/a2a"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/authn"
	"github.com/phaselume/torana/internal/security/authz"
	"github.com/phaselume/torana/internal/security/sts"
	"google.golang.org/grpc/test/bufconn"
)

type upstreamCapture struct {
	mu           sync.Mutex
	lastAuthHdr  string
	lastTaskReq  ingressa2a.TaskSendRequest
	lastMsgReq   ingressa2a.MessageSendRequest
}

func setupA2ATestServer(t *testing.T) (*bufconn.Listener, *upstreamCapture, func()) {
	lis := bufconn.Listen(1024 * 1024)
	mux := http.NewServeMux()
	cap := &upstreamCapture{}

	mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		card := ingressa2a.AgentCard{
			ID:          "agent-doc-processor",
			Name:        "Document Processor Agent",
			Description: "Processes and audits documents",
			URL:         "http://upstream-internal:8080/.well-known/agent-card.json",
			Version:     "1.0.0",
			Skills: []ingressa2a.Skill{
				{
					ID:          "summarize",
					Name:        "Summarize Document",
					Description: "Public summarization skill",
				},
				{
					ID:          "confidential_audit",
					Name:        "Confidential Security Audit",
					Description: "Restricted audit skill",
				},
			},
		}
		_ = json.NewEncoder(w).Encode(card)
	})

	mux.HandleFunc("/tasks/send", func(w http.ResponseWriter, r *http.Request) {
		cap.mu.Lock()
		cap.lastAuthHdr = r.Header.Get("Authorization")
		cap.mu.Unlock()

		bodyBytes, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		var req ingressa2a.TaskSendRequest
		_ = json.Unmarshal(bodyBytes, &req)

		cap.mu.Lock()
		cap.lastTaskReq = req
		cap.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		resp := ingressa2a.TaskResponse{
			ID:      "task-12345",
			Status:  "completed",
			SkillID: req.TargetSkill(),
			Output:  map[string]any{"result": "success"},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/tasks/stream", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "flusher unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")

		_, _ = w.Write([]byte("event: status\ndata: {\"status\":\"running\"}\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("event: status\ndata: {\"status\":\"completed\"}\n\n"))
		flusher.Flush()
	})

	mux.HandleFunc("/messages/send", func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		var msgReq ingressa2a.MessageSendRequest
		_ = json.Unmarshal(bodyBytes, &msgReq)

		cap.mu.Lock()
		cap.lastMsgReq = msgReq
		cap.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ingressa2a.MessageResponse{
			ID:      "msg-999",
			Content: "agent received: " + msgReq.Content,
		})
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(lis) }()

	cleanup := func() {
		_ = srv.Close()
		_ = lis.Close()
	}
	return lis, cap, cleanup
}

func setupA2AAuthzEngine(t *testing.T) *authz.PolicyEngine {
	compiler, err := authz.NewCompiler(authz.CompilerConfig{CostLimit: 1000})
	if err != nil {
		t.Fatalf("failed to create authz compiler: %v", err)
	}

	rules := []authz.Rule{
		{
			ID:         "allow-summarize-skill",
			Priority:   50,
			Effect:     authz.EffectAllow,
			Expression: `resource.type == 'a2a_skill' && resource.id == 'summarize'`,
		},
		{
			ID:         "deny-confidential-audit",
			Priority:   100,
			Effect:     authz.EffectDeny,
			Expression: `resource.type == 'a2a_skill' && resource.id == 'confidential_audit'`,
		},
	}

	compiled, err := compiler.CompileRules(rules)
	if err != nil {
		t.Fatalf("failed to compile rules: %v", err)
	}
	return authz.NewPolicyEngine(compiled, nil)
}

func setupSTSService(t *testing.T) *sts.Service {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	svc, err := sts.NewService(sts.Config{
		Namespace:  "torana-system",
		Issuer:     "https://gateway.torana.internal/sts",
		SigningKey: priv,
		KeyID:      "gateway-key-1",
		DefaultTTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to create sts service: %v", err)
	}
	return svc
}

func TestA2A_AgentCardServingAndRewriting(t *testing.T) {
	lis, _, cleanup := setupA2ATestServer(t)
	defer cleanup()

	cluster := &config.UpstreamCluster{
		ID:        "u-a2a",
		Protocol:  "a2a",
		Endpoints: []string{"http://bufconn"},
	}

	authzEngine := setupA2AAuthzEngine(t)
	handler := ingressa2a.NewHandler(authzEngine, nil, "https://api.gateway.example.com", nil)
	handler.SetClientForCluster("u-a2a", &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			},
		},
	})

	r, _ := http.NewRequest(http.MethodGet, "http://torana/.well-known/agent-card.json", nil)
	w := &mockResponseWriter{header: make(http.Header), body: new(bytes.Buffer)}

	env := &pipeline.Envelope{
		Path:   "/.well-known/agent-card.json",
		Method: "GET",
		Identity: &authn.Identity{
			Subject: "user-alice",
		},
	}

	handler.ServeHTTP(w, r, cluster, env)

	if w.code != 0 && w.code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.code)
	}

	var card ingressa2a.AgentCard
	if err := json.Unmarshal(w.body.Bytes(), &card); err != nil {
		t.Fatalf("failed to decode agent card: %v", err)
	}

	// 1. Verify URL rewriting to gateway endpoint
	expectedURL := "https://api.gateway.example.com/.well-known/agent-card.json"
	if card.URL != expectedURL {
		t.Fatalf("expected card URL %q, got %q", expectedURL, card.URL)
	}

	// 2. Verify skill filtering: "summarize" is present, "confidential_audit" is stripped out
	if len(card.Skills) != 1 {
		t.Fatalf("expected 1 skill after policy filtering, got %d", len(card.Skills))
	}
	if card.Skills[0].ID != "summarize" {
		t.Fatalf("expected summarize skill, got %s", card.Skills[0].ID)
	}
}

func TestA2A_SkillAuthorization(t *testing.T) {
	lis, _, cleanup := setupA2ATestServer(t)
	defer cleanup()

	cluster := &config.UpstreamCluster{
		ID:        "u-a2a",
		Protocol:  "a2a",
		Endpoints: []string{"http://bufconn"},
	}

	authzEngine := setupA2AAuthzEngine(t)
	handler := ingressa2a.NewHandler(authzEngine, nil, "https://api.gateway.example.com", nil)
	handler.SetClientForCluster("u-a2a", &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			},
		},
	})

	t.Run("Denied Skill returns 403", func(t *testing.T) {
		taskReq := ingressa2a.TaskSendRequest{
			SkillID: "confidential_audit",
			Input:   map[string]any{"target": "db-server"},
		}
		raw, _ := json.Marshal(taskReq)

		r, _ := http.NewRequest(http.MethodPost, "http://torana/tasks/send", bytes.NewReader(raw))
		w := &mockResponseWriter{header: make(http.Header), body: new(bytes.Buffer)}

		env := &pipeline.Envelope{
			Path:   "/tasks/send",
			Method: "POST",
			Identity: &authn.Identity{
				Subject: "bob",
			},
		}

		handler.ServeHTTP(w, r, cluster, env)

		if w.code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden, got %d", w.code)
		}

		var errResp ingressa2a.ErrorResponse
		_ = json.Unmarshal(w.body.Bytes(), &errResp)
		if errResp.Error.Code != "UNAUTHORIZED_SKILL" {
			t.Fatalf("expected UNAUTHORIZED_SKILL, got %s", errResp.Error.Code)
		}
	})

	t.Run("Allowed Skill succeeds", func(t *testing.T) {
		taskReq := ingressa2a.TaskSendRequest{
			SkillID: "summarize",
			Input:   map[string]any{"text": "long document"},
		}
		raw, _ := json.Marshal(taskReq)

		r, _ := http.NewRequest(http.MethodPost, "http://torana/tasks/send", bytes.NewReader(raw))
		w := &mockResponseWriter{header: make(http.Header), body: new(bytes.Buffer)}

		env := &pipeline.Envelope{
			Path:   "/tasks/send",
			Method: "POST",
			Identity: &authn.Identity{
				Subject: "bob",
			},
		}

		handler.ServeHTTP(w, r, cluster, env)

		if w.code != 0 && w.code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.code)
		}

		var taskResp ingressa2a.TaskResponse
		_ = json.Unmarshal(w.body.Bytes(), &taskResp)
		if taskResp.Status != "completed" {
			t.Fatalf("expected completed status, got %s", taskResp.Status)
		}
	})
}

func TestA2A_DownstreamSTSTokenPropagation(t *testing.T) {
	lis, cap, cleanup := setupA2ATestServer(t)
	defer cleanup()

	cluster := &config.UpstreamCluster{
		ID:        "u-a2a",
		Protocol:  "a2a",
		Endpoints: []string{"http://bufconn"},
	}

	authzEngine := setupA2AAuthzEngine(t)
	stsService := setupSTSService(t)

	handler := ingressa2a.NewHandler(authzEngine, stsService, "https://api.gateway.example.com", nil)
	handler.SetClientForCluster("u-a2a", &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			},
		},
	})

	taskReq := ingressa2a.TaskSendRequest{
		SkillID: "summarize",
		Input:   map[string]any{"text": "document to summarize"},
	}
	raw, _ := json.Marshal(taskReq)

	r, _ := http.NewRequest(http.MethodPost, "http://torana/tasks/send", bytes.NewReader(raw))
	w := &mockResponseWriter{header: make(http.Header), body: new(bytes.Buffer)}

	env := &pipeline.Envelope{
		Path:   "/tasks/send",
		Method: "POST",
		Identity: &authn.Identity{
			Subject: "developer-charlie",
			Tenant:  "tenant-prod",
		},
	}

	handler.ServeHTTP(w, r, cluster, env)

	if w.code != 0 && w.code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.code)
	}

	// Verify upstream captured authorization token
	cap.mu.Lock()
	authHdr := cap.lastAuthHdr
	cap.mu.Unlock()

	if !strings.HasPrefix(authHdr, "Bearer ") {
		t.Fatalf("expected Bearer token header, got %q", authHdr)
	}

	tokenStr := strings.TrimPrefix(authHdr, "Bearer ")
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-part JWT, got %d parts", len(parts))
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to base64 decode jwt payload: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		t.Fatalf("failed to decode claims JSON: %v", err)
	}

	// Verify audience is set to target upstream cluster ID
	if claims["aud"] != "u-a2a" {
		t.Fatalf("expected audience 'u-a2a', got %v", claims["aud"])
	}
	// Verify subject is preserved with namespace URN
	if !strings.HasSuffix(claims["sub"].(string), "developer-charlie") {
		t.Fatalf("expected subject to contain 'developer-charlie', got %v", claims["sub"])
	}
}

func TestA2A_StreamingUpdates(t *testing.T) {
	lis, _, cleanup := setupA2ATestServer(t)
	defer cleanup()

	cluster := &config.UpstreamCluster{
		ID:        "u-a2a",
		Protocol:  "a2a",
		Endpoints: []string{"http://bufconn"},
	}

	handler := ingressa2a.NewHandler(nil, nil, "https://api.gateway.example.com", nil)
	handler.SetClientForCluster("u-a2a", &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			},
		},
	})

	r, _ := http.NewRequest(http.MethodPost, "http://torana/tasks/stream", bytes.NewBufferString("{}"))
	w := &mockResponseWriter{header: make(http.Header), body: new(bytes.Buffer)}

	env := &pipeline.Envelope{
		Path:   "/tasks/stream",
		Method: "POST",
	}

	handler.ServeHTTP(w, r, cluster, env)

	if !w.flushed {
		t.Fatalf("expected response flusher to be called for SSE stream")
	}

	output := w.body.String()
	if !strings.Contains(output, `"status":"running"`) || !strings.Contains(output, `"status":"completed"`) {
		t.Fatalf("expected streamed SSE updates, got: %s", output)
	}
}

func BenchmarkA2A_TaskSend(b *testing.B) {
	lis, _, cleanup := setupA2ATestServer(&testing.T{})
	defer cleanup()

	cluster := &config.UpstreamCluster{
		ID:        "u-a2a",
		Protocol:  "a2a",
		Endpoints: []string{"http://bufconn"},
	}

	authzEngine := setupA2AAuthzEngine(&testing.T{})
	stsService := setupSTSService(&testing.T{})

	handler := ingressa2a.NewHandler(authzEngine, stsService, "https://api.gateway.example.com", nil)
	handler.SetClientForCluster("u-a2a", &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			},
		},
	})

	env := &pipeline.Envelope{
		Path:   "/tasks/send",
		Method: "POST",
		Identity: &authn.Identity{
			Subject: "developer-charlie",
			Tenant:  "tenant-prod",
		},
	}

	taskReq := ingressa2a.TaskSendRequest{
		SkillID: "summarize",
		Input:   map[string]any{"text": "document to summarize"},
	}
	raw, _ := json.Marshal(taskReq)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, _ := http.NewRequest(http.MethodPost, "http://torana/tasks/send", bytes.NewReader(raw))
		w := &mockResponseWriter{header: make(http.Header), body: new(bytes.Buffer)}
		handler.ServeHTTP(w, r, cluster, env)
	}
}

