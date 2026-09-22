package postgres

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrUnknownNamedQuery is returned when a caller references a query name not defined in configuration.
	ErrUnknownNamedQuery = errors.New("unknown named query")
	// ErrRawSQLForbidden is returned when a caller attempts to supply raw SQL text.
	ErrRawSQLForbidden = errors.New("raw SQL execution is strictly forbidden: callers must specify registered named queries")
	// ErrUnauthorizedDBQuery is returned when access to a named query is denied by CEL authorization policy.
	ErrUnauthorizedDBQuery = errors.New("unauthorized: db_query access denied by policy")
	// ErrMaxRowsExceeded is returned or indicates truncation when a query exceeds its max_rows limit.
	ErrMaxRowsExceeded = errors.New("query exceeded maximum allowed row limit")
	// ErrMaxBytesExceeded is returned when the accumulated payload exceeds max_bytes.
	ErrMaxBytesExceeded = errors.New("query exceeded maximum allowed byte limit")
	// ErrBulkheadExhausted is returned when the target database bulkhead queue is saturated.
	ErrBulkheadExhausted = errors.New("database bulkhead capacity exhausted")
	// ErrMissingRequiredParam is returned when a required named parameter is not provided.
	ErrMissingRequiredParam = errors.New("missing required query parameter")
	// ErrInvalidParamType is returned when a parameter value cannot be coerced into the specified type.
	ErrInvalidParamType = errors.New("invalid parameter type")
	// ErrTargetNotFound is returned when the specified database target cluster does not exist.
	ErrTargetNotFound = errors.New("database target not found")
)

// ParamType represents the expected data type of a named parameter.
type ParamType string

const (
	ParamTypeString ParamType = "string"
	ParamTypeInt    ParamType = "int"
	ParamTypeFloat  ParamType = "float"
	ParamTypeBool   ParamType = "bool"
	ParamTypeJSON   ParamType = "json"
	ParamTypeBytes  ParamType = "bytes"
)

// ParamSpec defines the schema for a query parameter.
type ParamSpec struct {
	Name     string    `json:"name"`
	Type     ParamType `json:"type"`
	Required bool      `json:"required"`
}

// NamedQuery defines an immutable, pre-approved SQL statement.
type NamedQuery struct {
	Name     string        `json:"name"`
	SQL      string        `json:"sql"`
	Params   []ParamSpec   `json:"params"`
	MaxRows  int64         `json:"max_rows"`
	MaxBytes int64         `json:"max_bytes"`
	Timeout  time.Duration `json:"timeout"`
	ReadOnly bool          `json:"read_only"`
}

// TargetConfig defines connection and bulkhead settings for a database upstream.
type TargetConfig struct {
	TargetID          string        `json:"target_id"`
	ConnString        string        `json:"conn_string"`
	MaxConns          int32         `json:"max_conns"`
	MinConns          int32         `json:"min_conns"`
	BulkheadLimit     int           `json:"bulkhead_limit"`      // Maximum concurrent queries
	BulkheadQueueSize int           `json:"bulkhead_queue_size"` // Maximum queued queries before rejection
	DefaultTimeout    time.Duration `json:"default_timeout"`
}

// QueryRequest represents an invocation request from a caller.
// Raw SQL cannot be specified.
type QueryRequest struct {
	TargetID  string         `json:"target_id"`
	QueryName string         `json:"query_name"`
	Params    map[string]any `json:"params"`
}

// QueryResult represents the structured rows and metadata returned to the caller.
type QueryResult struct {
	Columns   []string        `json:"columns"`
	Rows      [][]any         `json:"rows"`
	RowCount  int64           `json:"row_count"`
	BytesRead int64           `json:"bytes_read"`
	Duration  time.Duration   `json:"duration"`
	Truncated bool            `json:"truncated,omitempty"`
}

// ValidateParam casts and validates a value against a ParamSpec.
func (p *ParamSpec) ValidateAndCoerce(val any) (any, error) {
	if val == nil {
		if p.Required {
			return nil, fmt.Errorf("%w: parameter %q", ErrMissingRequiredParam, p.Name)
		}
		return nil, nil
	}

	switch p.Type {
	case ParamTypeString:
		return fmt.Sprint(val), nil

	case ParamTypeInt:
		switch v := val.(type) {
		case int:
			return int64(v), nil
		case int32:
			return int64(v), nil
		case int64:
			return v, nil
		case float64:
			return int64(v), nil
		case float32:
			return int64(v), nil
		default:
			return nil, fmt.Errorf("%w: param %q expected int, got %T", ErrInvalidParamType, p.Name, val)
		}

	case ParamTypeFloat:
		switch v := val.(type) {
		case float64:
			return v, nil
		case float32:
			return float64(v), nil
		case int:
			return float64(v), nil
		case int64:
			return float64(v), nil
		default:
			return nil, fmt.Errorf("%w: param %q expected float, got %T", ErrInvalidParamType, p.Name, val)
		}

	case ParamTypeBool:
		if b, ok := val.(bool); ok {
			return b, nil
		}
		return nil, fmt.Errorf("%w: param %q expected bool, got %T", ErrInvalidParamType, p.Name, val)

	case ParamTypeJSON, ParamTypeBytes:
		switch v := val.(type) {
		case []byte:
			return v, nil
		case string:
			return []byte(v), nil
		default:
			return val, nil
		}

	default:
		return val, nil
	}
}
