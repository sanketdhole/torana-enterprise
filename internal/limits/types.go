package limits

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrRateLimitExceeded is returned when the request rate limit (token bucket) is exceeded.
	ErrRateLimitExceeded = errors.New("request rate limit exceeded")
	// ErrTokenBudgetExceeded is returned when an LLM token budget window is exceeded.
	ErrTokenBudgetExceeded = errors.New("token budget exceeded")
	// ErrReservationNotFound is returned when attempting to reconcile a non-existent or expired reservation.
	ErrReservationNotFound = errors.New("reservation not found")
)

// Window represents the time window for an LLM token budget.
type Window string

const (
	WindowMinute Window = "minute"
	WindowDay    Window = "day"
	WindowMonth  Window = "month"
)

// Duration returns the time.Duration corresponding to the window.
func (w Window) Duration() time.Duration {
	switch w {
	case WindowMinute:
		return 1 * time.Minute
	case WindowDay:
		return 24 * time.Hour
	case WindowMonth:
		return 30 * 24 * time.Hour
	default:
		return 1 * time.Minute
	}
}

// DimensionKeys holds the extracted dimensional keys for a request.
type DimensionKeys struct {
	Identity string // User / caller subject
	Team     string // Tenant / team / group
	Route    string // Route ID or path
	Model    string // Target LLM model
}

// BuildKey constructs a unique storage key for a specific dimension, window, and bucket timestamp.
func (d DimensionKeys) BuildKey(prefix string, window Window, bucketTime time.Time) string {
	var bucketKey string
	switch window {
	case WindowMinute:
		bucketKey = bucketTime.UTC().Format("2006-01-02T15:04")
	case WindowDay:
		bucketKey = bucketTime.UTC().Format("2006-01-02")
	case WindowMonth:
		bucketKey = bucketTime.UTC().Format("2006-01")
	}

	return fmt.Sprintf("limits:%s:%s:%s:%s:%s:%s:%s",
		prefix,
		sanitizeKeyPart(d.Team),
		sanitizeKeyPart(d.Identity),
		sanitizeKeyPart(d.Route),
		sanitizeKeyPart(d.Model),
		string(window),
		bucketKey,
	)
}

// RateLimitKey constructs a key for request-rate limiting.
func (d DimensionKeys) RateLimitKey() string {
	return fmt.Sprintf("limits:rps:%s:%s:%s",
		sanitizeKeyPart(d.Team),
		sanitizeKeyPart(d.Identity),
		sanitizeKeyPart(d.Route),
	)
}

func sanitizeKeyPart(part string) string {
	if part == "" {
		return "*"
	}
	return part
}

// BudgetRule configures token limits across time windows.
type BudgetRule struct {
	Limits map[Window]int64 // Window -> max allowed tokens
}

// RateLimitRule configures request-rate limiting using a token bucket.
type RateLimitRule struct {
	Rate  float64 // tokens per second
	Burst int64   // maximum burst size
}

// ReservationResult contains the verdict of a pre-check reservation attempt.
type ReservationResult struct {
	Allowed    bool          `json:"allowed"`
	Reason     string        `json:"reason,omitempty"`
	Window     Window        `json:"window,omitempty"`
	Limit      int64         `json:"limit,omitempty"`
	Remaining  int64         `json:"remaining,omitempty"`
	RetryAfter time.Duration `json:"retry_after,omitempty"`
}

// Reservation stores the state of an in-flight token reservation.
type Reservation struct {
	ID             string
	Keys           DimensionKeys
	ReservedTokens int64
	Windows        []Window
	CreatedAt      time.Time
}

// RateLimitError defines the standardized machine-readable HTTP 429 response body.
type RateLimitError struct {
	ErrorMessage string `json:"error"`
	Code         string `json:"code"`
	Reason       string `json:"reason"`
	Window       string `json:"window,omitempty"`
	RetryAfter   int    `json:"retry_after"` // seconds
	Limit        int64  `json:"limit,omitempty"`
	Remaining    int64  `json:"remaining"`
}

func (e RateLimitError) Error() string {
	return fmt.Sprintf("%s: %s (retry after %ds)", e.Code, e.Reason, e.RetryAfter)
}

// ToJSON converts the RateLimitError into a JSON byte slice.
func (e RateLimitError) ToJSON() []byte {
	b, _ := json.Marshal(e)
	return b
}
