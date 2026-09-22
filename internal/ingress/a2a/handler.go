package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/authn"
	"github.com/phaselume/torana/internal/security/authz"
	"github.com/phaselume/torana/internal/security/sts"
)

// Handler processes incoming Agent-to-Agent (A2A) protocol calls.
type Handler struct {
	authzEngine      *authz.PolicyEngine
	stsService       *sts.Service
	gatewayPublicURL string
	logger           *slog.Logger

	mu            sync.RWMutex
	pools         map[string]*http.Client
	defaultClient *http.Client
}

// NewHandler creates a new A2A ingress handler.
func NewHandler(
	authzEngine *authz.PolicyEngine,
	stsService *sts.Service,
	gatewayPublicURL string,
	logger *slog.Logger,
) *Handler {
	transport := &http.Transport{
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}
	return &Handler{
		authzEngine:      authzEngine,
		stsService:       stsService,
		gatewayPublicURL: strings.TrimRight(gatewayPublicURL, "/"),
		logger:           logger,
		pools:            make(map[string]*http.Client),
		defaultClient: &http.Client{
			Transport: transport,
			Timeout:   60 * time.Second,
		},
	}
}

// SetClientForCluster sets a custom HTTP client for a specific cluster (used for tests).
func (h *Handler) SetClientForCluster(clusterID string, client *http.Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pools[clusterID] = client
}

func (h *Handler) getClient(cluster *config.UpstreamCluster) *http.Client {
	h.mu.RLock()
	client, ok := h.pools[cluster.ID]
	h.mu.RUnlock()
	if ok && client != nil {
		return client
	}
	return h.defaultClient
}

// authorizeSkill evaluates CEL policy for a specific A2A skill.
func (h *Handler) authorizeSkill(ctx context.Context, env *pipeline.Envelope, skillID, actionName string) bool {
	if h.authzEngine == nil || skillID == "" {
		return true // Allow if no authz engine configured or no specific skill targeted
	}

	var ident *authn.Identity
	if env != nil {
		if id, ok := env.Identity.(*authn.Identity); ok {
			ident = id
		}
	}

	headers := make(map[string]string)
	if env != nil && env.Headers != nil {
		for k, vv := range env.Headers {
			if len(vv) > 0 {
				headers[k] = vv[0]
			}
		}
	}

	path := ""
	if env != nil {
		path = env.Path
	}

	reqAttrs := authz.RequestAttributes{
		Path:    path,
		Method:  "POST",
		Headers: headers,
		Time:    time.Now(),
	}
	res := authz.Resource{
		Type: authz.ResourceTypeA2ASkill,
		ID:   skillID,
	}
	act := authz.Action{
		Name:   actionName,
		Method: "POST",
	}

	err := h.authzEngine.Evaluate(ctx, ident, res, act, reqAttrs)
	if err != nil {
		if h.logger != nil {
			h.logger.Debug("a2a skill access denied by policy", "skill", skillID, "action", actionName, "error", err)
		}
		return false
	}
	return true
}

// ServeHTTP handles A2A discovery, task execution, messages, and streaming.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, cluster *config.UpstreamCluster, env *pipeline.Envelope) {
	if len(cluster.Endpoints) == 0 {
		http.Error(w, `{"error":{"code":"NO_ENDPOINTS","message":"upstream cluster has no endpoints"}}`, http.StatusBadGateway)
		return
	}

	path := r.URL.Path

	// 1. Agent Card Serving and URL Rewriting
	if strings.HasSuffix(path, "/.well-known/agent-card.json") || strings.HasSuffix(path, "/.well-known/agent.json") {
		h.handleAgentCard(w, r, cluster, env)
		return
	}

	// 2. Task & Message Execution Calls
	bodyBytes, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		http.Error(w, `{"error":{"code":"BAD_REQUEST","message":"failed to read request body"}}`, http.StatusBadRequest)
		return
	}

	// Skill-level authorization check
	if r.Method == http.MethodPost && (strings.Contains(path, "/tasks") || strings.Contains(path, "/messages")) {
		skillID := extractTargetSkill(bodyBytes)
		if skillID != "" && !h.authorizeSkill(r.Context(), env, skillID, "execute") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(ErrorResponse{
				Error: ErrorDetail{
					Code:    "UNAUTHORIZED_SKILL",
					Message: fmt.Sprintf("unauthorized: access to skill %q denied by policy", skillID),
					SkillID: skillID,
				},
			})
			return
		}
	}

	// 3. Mint and Propagate Downstream STS Token
	upstreamHeaders := r.Header.Clone()
	if h.stsService != nil && env != nil {
		if ident, ok := env.Identity.(*authn.Identity); ok && ident != nil {
			audience := cluster.ID
			token, mintErr := h.stsService.MintDownstreamToken(r.Context(), ident, sts.WithAudience(audience))
			if mintErr == nil && token != "" {
				upstreamHeaders.Set("Authorization", "Bearer "+token)
			} else if h.logger != nil {
				h.logger.Warn("failed to mint downstream sts token for a2a upstream", "error", mintErr, "audience", audience)
			}
		}
	}

	// 4. Forward Request Upstream
	targetURL := cluster.Endpoints[0] + r.URL.RequestURI()
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, `{"error":{"code":"INTERNAL_ERROR","message":"failed to construct upstream request"}}`, http.StatusInternalServerError)
		return
	}
	upReq.Header = upstreamHeaders

	client := h.getClient(cluster)
	resp, err := client.Do(upReq)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"code":"UPSTREAM_ERROR","message":%q}}`, err.Error()), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 5. Copy Response Headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// 6. Support Streaming Updates (SSE) and Chunked Bodies
	flusher, isFlusher := w.(http.Flusher)
	isSSE := strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")

	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			_, _ = w.Write(buf[:n])
			if isFlusher && (isSSE || n < len(buf)) {
				flusher.Flush()
			}
		}
		if readErr != nil {
			break
		}
	}
}

// handleAgentCard fetches upstream Agent Card, rewrites URLs, and optionally filters skills.
func (h *Handler) handleAgentCard(w http.ResponseWriter, r *http.Request, cluster *config.UpstreamCluster, env *pipeline.Envelope) {
	targetURL := cluster.Endpoints[0] + r.URL.RequestURI()
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, targetURL, nil)
	if err != nil {
		http.Error(w, `{"error":{"code":"INTERNAL_ERROR","message":"failed to create upstream agent card request"}}`, http.StatusInternalServerError)
		return
	}

	client := h.getClient(cluster)
	resp, err := client.Do(upReq)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"code":"UPSTREAM_ERROR","message":%q}}`, err.Error()), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, `{"error":{"code":"INTERNAL_ERROR","message":"failed to read upstream agent card"}}`, http.StatusInternalServerError)
		return
	}

	var card AgentCard
	if err := json.Unmarshal(body, &card); err != nil {
		// Passthrough if not JSON or parsing fails
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}

	// Rewrite agent card URL to gateway public endpoint
	publicBase := h.gatewayPublicURL
	if publicBase == "" {
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		publicBase = fmt.Sprintf("%s://%s", scheme, r.Host)
	}
	card.URL = publicBase + r.URL.Path

	// Filter skills by caller authorization if authz engine is configured
	if h.authzEngine != nil && len(card.Skills) > 0 {
		authorizedSkills := make([]Skill, 0, len(card.Skills))
		for _, s := range card.Skills {
			if h.authorizeSkill(r.Context(), env, s.ID, "view") {
				authorizedSkills = append(authorizedSkills, s)
			}
		}
		card.Skills = authorizedSkills
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(card)
}

// extractTargetSkill pulls skill_id or skill from incoming task or message JSON payloads.
func extractTargetSkill(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var probe struct {
		SkillID string `json:"skill_id"`
		Skill   string `json:"skill"`
	}
	if err := json.Unmarshal(body, &probe); err == nil {
		if probe.SkillID != "" {
			return probe.SkillID
		}
		return probe.Skill
	}
	return ""
}
