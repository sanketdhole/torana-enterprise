package observe

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

// redactedFields is the set of slog attribute keys whose values are replaced
// with "[REDACTED]" before being written. The comparison is case-insensitive.
var redactedFields = map[string]struct{}{
	"authorization":    {},
	"token":            {},
	"password":         {},
	"secret":           {},
	"cookie":           {},
	"x-api-key":        {},
	"api_key":          {},
	"apikey":           {},
	"pull_token":       {},
	"bearer":           {},
	"credentials":      {},
	"private_key":      {},
	"access_token":     {},
	"refresh_token":    {},
	"session_id":       {},
}

// SetRedactedFields replaces the default redaction set with the provided keys
// (all lowercased internally). Intended for testing.
func SetRedactedFields(keys []string) {
	m := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		m[strings.ToLower(k)] = struct{}{}
	}
	redactedFields = m
}

// isRedacted returns true if the key should be redacted.
func isRedacted(key string) bool {
	_, ok := redactedFields[strings.ToLower(key)]
	return ok
}

// redactingHandler wraps an slog.Handler, replacing sensitive attribute values
// with the string "[REDACTED]".
type redactingHandler struct {
	inner slog.Handler
}

// Enabled delegates to the inner handler.
func (h *redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle redacts sensitive attributes before passing the record to the inner handler.
func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	var redacted []slog.Attr
	r.Attrs(func(a slog.Attr) bool {
		if isRedacted(a.Key) {
			redacted = append(redacted, slog.String(a.Key, "[REDACTED]"))
		} else {
			redacted = append(redacted, a)
		}
		return true
	})

	// Build a new Record with only the redacted attributes.
	nr := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	nr.AddAttrs(redacted...)
	return h.inner.Handle(ctx, nr)
}

// WithAttrs returns a new handler with the given attrs pre-appended.
func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	safe := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		if isRedacted(a.Key) {
			safe[i] = slog.String(a.Key, "[REDACTED]")
		} else {
			safe[i] = a
		}
	}
	return &redactingHandler{inner: h.inner.WithAttrs(safe)}
}

// WithGroup returns a new handler that opens a group scope.
func (h *redactingHandler) WithGroup(name string) slog.Handler {
	return &redactingHandler{inner: h.inner.WithGroup(name)}
}

// NewLogger creates a structured JSON slog.Logger that redacts sensitive
// fields before writing to stderr.
func NewLogger(level slog.Level) *slog.Logger {
	jsonHandler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
	})
	return slog.New(&redactingHandler{inner: jsonHandler})
}

// NewLoggerWithHandler creates a redacting Logger wrapping the given handler.
// Useful for testing (e.g. wrapping a handler backed by a bytes.Buffer).
func NewLoggerWithHandler(h slog.Handler) *slog.Logger {
	return slog.New(&redactingHandler{inner: h})
}
