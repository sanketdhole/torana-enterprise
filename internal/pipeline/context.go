package pipeline

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/phaselume/torana/internal/config"
)

// RequestContext carries all state for a request through the filter pipeline.
type RequestContext struct {
	// Standard Go context for deadline and cancellation propagation
	Ctx context.Context

	// Route & Upstream resolved from immutable snapshot
	Route    *config.RouteRule
	Upstream *config.UpstreamCluster

	// Request details
	Method  string
	Path    string
	Headers http.Header

	// Streaming Request Body
	RequestBody io.Reader

	// Buffered body if requested by a BodyModeBuffered filter
	bufferedBody []byte

	// Response state
	ResponseStatus  int
	ResponseHeaders http.Header
	ResponseBody    io.Reader

	// Metadata collected for telemetry (tokens, model ID, latency, tenant, user ID)
	// Payload content is NEVER placed in Metadata
	Metadata map[string]string

	// Timestamps
	StartTime time.Time
}

// NewRequestContext constructs a new RequestContext.
func NewRequestContext(ctx context.Context, method, path string, headers http.Header, body io.Reader) *RequestContext {
	if headers == nil {
		headers = make(http.Header)
	}
	return &RequestContext{
		Ctx:             ctx,
		Method:          method,
		Path:            path,
		Headers:         headers,
		RequestBody:     body,
		ResponseHeaders: make(http.Header),
		Metadata:        make(map[string]string),
		StartTime:       time.Now(),
	}
}

// GetBufferedBody returns the buffered body if already buffered, or buffers it up to maxBytes.
func (rc *RequestContext) GetBufferedBody(maxBytes int64) ([]byte, error) {
	if rc.bufferedBody != nil {
		return rc.bufferedBody, nil
	}
	if rc.RequestBody == nil {
		return nil, nil
	}

	lr := io.LimitReader(rc.RequestBody, maxBytes+1)
	buf, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > maxBytes {
		return nil, ErrBodyTooLarge
	}

	rc.bufferedBody = buf
	// Reset RequestBody to allow downstream readers to read from buffered bytes
	rc.RequestBody = bytes.NewReader(buf)
	return rc.bufferedBody, nil
}

// SetMetadata records non-sensitive telemetry metadata (e.g. "model", "tokens_prompt", "tenant_id").
func (rc *RequestContext) SetMetadata(key, val string) {
	rc.Metadata[key] = val
}

// GetMetadata retrieves a metadata value.
func (rc *RequestContext) GetMetadata(key string) (string, bool) {
	val, ok := rc.Metadata[key]
	return val, ok
}
