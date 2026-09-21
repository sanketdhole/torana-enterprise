package pipeline

import (
	"errors"
)

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

var (
	// ErrFilterRejected is returned when a security or policy filter halts request execution.
	ErrFilterRejected = errors.New("request rejected by filter policy")
	// ErrUnauthorized is returned when authn/authz fails (fail-closed).
	ErrUnauthorized = errors.New("unauthorized request")
	// ErrBodyTooLarge is returned when a buffered filter encounters a body exceeding allowed limit.
	ErrBodyTooLarge = errors.New("request body exceeds max allowed buffer size")
)

// Filter represents a step in the pipeline.
type Filter interface {
	Name() string
	BodyMode() BodyMode
	Execute(ctx *RequestContext) error
}
