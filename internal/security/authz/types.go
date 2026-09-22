package authz

import (
	"errors"
	"time"
)

var (
	// ErrAccessDenied is returned when authorization policy evaluation denies the request.
	ErrAccessDenied = errors.New("access denied by authorization policy")
	// ErrDefaultDeny is returned when no matching allow rule was found.
	ErrDefaultDeny = errors.New("access denied: default deny")
	// ErrInvalidResourceType is returned when a resource type is not recognized.
	ErrInvalidResourceType = errors.New("invalid or unsupported resource type")
	// ErrCompilationFailed is returned when a CEL expression fails syntax, type checking, or cost limits.
	ErrCompilationFailed = errors.New("cel compilation failed")
)

// ResourceType defines standard target resources protected by Torana data plane.
type ResourceType string

const (
	ResourceTypeRoute    ResourceType = "route"
	ResourceTypeMCPTool  ResourceType = "mcp_tool"
	ResourceTypeLLMModel ResourceType = "llm_model"
	ResourceTypeDBQuery  ResourceType = "db_query"
	ResourceTypeA2ASkill ResourceType = "a2a_skill"
)

// Valid returns true if the resource type is one of the supported types.
func (r ResourceType) Valid() bool {
	switch r {
	case ResourceTypeRoute, ResourceTypeMCPTool, ResourceTypeLLMModel, ResourceTypeDBQuery, ResourceTypeA2ASkill:
		return true
	default:
		return false
	}
}

// Effect declares the intended policy outcome if a rule condition evaluates to true.
type Effect string

const (
	EffectAllow Effect = "ALLOW"
	EffectDeny  Effect = "DENY"
)

// Resource describes the object or entity being accessed.
type Resource struct {
	Type       ResourceType   `json:"type"`
	ID         string         `json:"id"`
	Namespace  string         `json:"namespace,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Action describes the operation attempted on the resource.
type Action struct {
	Name   string `json:"name"`   // e.g. "invoke", "query", "generate", "call"
	Method string `json:"method"` // e.g. "GET", "POST", "RPC"
}

// RequestAttributes captures network and transport metadata for the request.
type RequestAttributes struct {
	Path     string            `json:"path"`
	Method   string            `json:"method"`
	Host     string            `json:"host"`
	RemoteIP string            `json:"remote_ip"`
	Headers  map[string]string `json:"headers,omitempty"`
	Time     time.Time         `json:"time"`
}

// Rule defines an individual authorization policy rule.
type Rule struct {
	ID         string `json:"id"`
	Priority   int    `json:"priority"` // Higher number = evaluated earlier in order
	Effect     Effect `json:"effect"`   // EffectAllow or EffectDeny
	Expression string `json:"expression"`
}

// DecisionLog records an authorization verdict for the async audit buffer.
type DecisionLog struct {
	Timestamp    time.Time     `json:"timestamp"`
	RuleID       string        `json:"rule_id,omitempty"`
	Effect       Effect        `json:"effect"`
	Reason       string        `json:"reason"`
	Latency      time.Duration `json:"latency"`
	Subject      string        `json:"subject"`
	Tenant       string        `json:"tenant"`
	ResourceType ResourceType  `json:"resource_type"`
	ResourceID   string        `json:"resource_id"`
	Action       string        `json:"action"`
}
