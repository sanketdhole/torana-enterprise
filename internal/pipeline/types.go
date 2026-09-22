package pipeline

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
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
	// ErrPhaseTimeout is returned when a phase exceeds its latency budget.
	ErrPhaseTimeout = errors.New("phase latency budget exceeded")
	// ErrCircuitOpen is returned when a filter's circuit breaker is open.
	ErrCircuitOpen = errors.New("filter circuit breaker open")
)

// Phase represents the lifecycle execution phase of a filter.
type Phase int

const (
	PhaseRequestHeaders Phase = iota + 1
	PhaseRequestBody
	PhaseResponseHeaders
	PhaseResponseBody
	PhaseAuthn
)

func (p Phase) String() string {
	switch p {
	case PhaseAuthn:
		return "authn"
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
	BodyModeNone BodyMode = iota
	BodyModeStreaming
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

// FailurePolicy defines whether a filter failure should halt the request or fail open.
type FailurePolicy int

const (
	FailurePolicyFailClosed FailurePolicy = iota
	FailurePolicyFailOpen
)

func (f FailurePolicy) String() string {
	if f == FailurePolicyFailOpen {
		return "fail_open"
	}
	return "fail_closed"
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
	TLS            *tls.ConnectionState
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
	Claims       map[string]string
	Identity     any
	Body         io.Reader
	BufferedBody []byte
	PeerInfo     PeerInfo
	StartTime    time.Time
}

// Reset clears fields so the Envelope can be recycled in sync.Pool.
func (e *Envelope) Reset() {
	e.RequestID = ""
	e.Route = nil
	e.Upstream = nil
	e.Phase = 0
	e.Method = ""
	e.Path = ""
	e.Body = nil
	e.BufferedBody = nil
	e.PeerInfo = PeerInfo{}
	e.StartTime = time.Time{}
	e.Headers = nil
	e.Identity = nil

	clear(e.Metadata)
	clear(e.Claims)
}

// EnvelopePool manages reusable Envelope instances to eliminate allocations on the hot path.
var envelopePool = sync.Pool{
	New: func() any {
		return &Envelope{
			Metadata: make(map[string]string),
			Claims:   make(map[string]string),
		}
	},
}

// GetEnvelope retrieves a recycled Envelope from the pool.
func GetEnvelope(requestID string, phase Phase, method, path string, headers http.Header, body io.Reader) *Envelope {
	env := envelopePool.Get().(*Envelope)
	env.Reset()
	env.RequestID = requestID
	env.Phase = phase
	env.Method = method
	env.Path = path
	env.Body = body
	env.StartTime = time.Now()

	if headers != nil {
		env.Headers = headers
	} else {
		env.Headers = make(http.Header)
	}
	return env
}

// PutEnvelope returns an Envelope to the pool for reuse.
func PutEnvelope(env *Envelope) {
	if env != nil {
		envelopePool.Put(env)
	}
}

// BufferPool manages reusable 32KB streaming chunk byte slices.
var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// GetBuffer retrieves a 32KB chunk buffer from the pool.
func GetBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool.
func PutBuffer(b *[]byte) {
	if b != nil {
		bufferPool.Put(b)
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

// CircuitBreaker tracks error states for a filter.
type CircuitBreaker struct {
	consecutiveFailures atomic.Int64
	threshold           int64
	lastFailure         atomic.Int64 // Unix nanoseconds
	cooldown            time.Duration
}

// NewCircuitBreaker creates a circuit breaker.
func NewCircuitBreaker(threshold int64, cooldown time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold: threshold,
		cooldown:  cooldown,
	}
}

// Allow returns true if the circuit allows execution.
func (cb *CircuitBreaker) Allow() bool {
	if cb.threshold <= 0 {
		return true
	}
	fails := cb.consecutiveFailures.Load()
	if fails < cb.threshold {
		return true
	}
	last := time.Unix(0, cb.lastFailure.Load())
	if time.Since(last) > cb.cooldown {
		return true
	}
	return false
}

// RecordSuccess resets the circuit breaker.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.consecutiveFailures.Store(0)
}

// RecordFailure registers a failure.
func (cb *CircuitBreaker) RecordFailure() {
	cb.consecutiveFailures.Add(1)
	cb.lastFailure.Store(time.Now().UnixNano())
}

// Filter represents a plugin or internal filter unit in the pipeline.
type Filter interface {
	Name() string
	Phase() Phase
	BodyMode() BodyMode
	FailurePolicy() FailurePolicy
	Process(ctx context.Context, env *Envelope) (Decision, error)
	Close() error
}

// ChunkHook represents a filter that inspects or mutates individual streaming chunks or messages.
type ChunkHook interface {
	OnChunk(ctx context.Context, env *Envelope, chunk []byte) ([]byte, error)
}

