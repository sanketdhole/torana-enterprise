package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/phaselume/torana/internal/config"
)

var (
	// ErrFilterHalted is returned when a filter halts the request.
	ErrFilterHalted = errors.New("request halted by filter policy")
	// ErrUnauthorized is returned when authentication/authorization fails (fail-closed).
	ErrUnauthorized = errors.New("unauthorized request")
	// ErrBodyTooLarge is returned when a buffered filter encounters a body exceeding allowed limit.
	ErrBodyTooLarge = errors.New("request body exceeds max allowed buffer size")
)

// Phase represents the lifecycle execution phase of a filter.
type Phase int

const (
	PhaseRequestHeaders Phase = iota + 1
	PhaseRequestBody
	PhaseResponseHeaders
	PhaseResponseBody
)

func (p Phase) String() string {
	switch p {
	case PhaseRequestHeaders:
		return "request_headers"
	case PhaseRequestBody:
		return "request_body"
	case PhaseResponseHeaders:
		return "response_headers"
	case PhaseResponseBody:
		return "response_body"
	default:
		return "unspecified"
	}
}

// BodyMode declares whether a filter requires no body, streaming chunks, or full buffering.
type BodyMode int

const (
	// BodyModeNone indicates the filter inspects/modifies headers or metadata only without touching the body.
	BodyModeNone BodyMode = iota
	// BodyModeStreaming indicates the filter inspects or transforms body chunks on-the-fly without full buffering.
	BodyModeStreaming
	// BodyModeBuffered indicates the filter explicitly requires the complete body in memory up to a declared limit.
	BodyModeBuffered
)

func (m BodyMode) String() string {
	switch m {
	case BodyModeNone:
		return "none"
	case BodyModeStreaming:
		return "streaming"
	case BodyModeBuffered:
		return "buffered"
	default:
		return "unknown"
	}
}

// Action represents the outcome decided by a Filter.
type Action int

const (
	ActionContinue Action = iota
	ActionHalt
	ActionMutate
	ActionDrop
)

func (a Action) String() string {
	switch a {
	case ActionContinue:
		return "continue"
	case ActionHalt:
		return "halt"
	case ActionMutate:
		return "mutate"
	case ActionDrop:
		return "drop"
	default:
		return "unknown"
	}
}

// PeerInfo holds client peer connection information.
type PeerInfo struct {
	RemoteIP       string
	Protocol       string
	ClientIdentity string
}

// Decision represents the output returned by a filter process step.
type Decision struct {
	Action         Action
	StatusCode     int
	Reason         string
	MutateHeaders  map[string]string
	MutateBody     []byte
	MutateMetadata map[string]string
}

// ContinueDecision returns a default continue decision.
func ContinueDecision() Decision {
	return Decision{
		Action:     ActionContinue,
		StatusCode: http.StatusOK,
	}
}

// HaltDecision returns a halting decision with an HTTP status code and reason.
func HaltDecision(statusCode int, reason string) Decision {
	return Decision{
		Action:     ActionHalt,
		StatusCode: statusCode,
		Reason:     reason,
	}
}

// Envelope carries request/response data through the filter phases.
type Envelope struct {
	RequestID    string
	Route        *config.RouteRule
	Upstream     *config.UpstreamCluster
	Phase        Phase
	Method       string
	Path         string
	Headers      http.Header
	Metadata     map[string]string
	Body         io.Reader
	BufferedBody []byte
	PeerInfo     PeerInfo
	StartTime    time.Time
}

// NewEnvelope constructs a new Envelope instance.
func NewEnvelope(requestID string, phase Phase, method, path string, headers http.Header, body io.Reader) *Envelope {
	if headers == nil {
		headers = make(http.Header)
	}
	return &Envelope{
		RequestID: requestID,
		Phase:     phase,
		Method:    method,
		Path:      path,
		Headers:   headers,
		Metadata:  make(map[string]string),
		Body:      body,
		StartTime: time.Now(),
	}
}

// GetBufferedBody buffers the envelope body up to maxBytes and caches it.
func (e *Envelope) GetBufferedBody(maxBytes int64) ([]byte, error) {
	if e.BufferedBody != nil {
		return e.BufferedBody, nil
	}
	if e.Body == nil {
		return nil, nil
	}

	lr := io.LimitReader(e.Body, maxBytes+1)
	buf, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}
	if int64(len(buf)) > maxBytes {
		return nil, ErrBodyTooLarge
	}

	e.BufferedBody = buf
	e.Body = bytes.NewReader(buf)
	return e.BufferedBody, nil
}

// SetMetadata records non-sensitive telemetry metadata.
func (e *Envelope) SetMetadata(key, val string) {
	e.Metadata[key] = val
}

// GetMetadata retrieves a metadata key.
func (e *Envelope) GetMetadata(key string) (string, bool) {
	val, ok := e.Metadata[key]
	return val, ok
}

// Filter represents a plugin or internal filter unit in the pipeline.
type Filter interface {
	Name() string
	Phase() Phase
	BodyMode() BodyMode
	Process(ctx context.Context, env *Envelope) (Decision, error)
	Close() error
}
