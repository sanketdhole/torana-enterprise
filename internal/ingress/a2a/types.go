// Package a2a implements an ingress gateway proxy for the Agent-to-Agent (A2A) Protocol.
//
// Targeted Specifications:
//   - Specification: Agent-to-Agent (A2A) Protocol Specification (v0.2 / v1.0 draft)
//     (Linux Foundation / Agentic AI Foundation / Google / IBM)
//   - Protocol Version: v0.2 / v1.0
//   - Core Capabilities:
//       1. Agent Card Discovery: Serves discovery documents at /.well-known/agent-card.json
//          and /.well-known/agent.json. Rewrites endpoint URLs to point to the gateway's
//          public address so downstream callers remain routed through security policies.
//       2. Skill-based Authorization: Evaluates CEL authorization policies (resource type
//          "a2a_skill") before executing tasks or sending messages directed at specific skills.
//       3. Downstream Token Minting: Exchanges the caller's verified Identity via the Security
//          Token Service (STS) to mint short-lived downstream tokens (audience-scoped to the
//          target upstream agent) and injects them as Bearer tokens.
//       4. Task & Message Lifecycles: Handles tasks/send, tasks/get, tasks/cancel, and
//          messages/send with streaming Server-Sent Events (SSE) pass-through.
package a2a

import (
	"errors"
)

// A2A Protocol Version targeted by this implementation.
const ProtocolVersion = "v0.2"

var (
	ErrUnauthorizedSkill = errors.New("unauthorized: a2a skill execution denied by policy")
	ErrAgentCardNotFound = errors.New("upstream agent card not found")
)

// AgentCard represents the standard A2A agent discovery manifest.
type AgentCard struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Description    string            `json:"description,omitempty"`
	URL            string            `json:"url"`
	Version        string            `json:"version,omitempty"`
	Skills         []Skill           `json:"skills,omitempty"`
	Capabilities   []string          `json:"capabilities,omitempty"`
	Authentication map[string]any    `json:"authentication,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// Skill represents a modular capability exposed by an A2A agent.
type Skill struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
}

// TaskSendRequest represents a request to create and execute a task.
type TaskSendRequest struct {
	ID       string         `json:"id,omitempty"`
	SkillID  string         `json:"skill_id,omitempty"`
	Skill    string         `json:"skill,omitempty"` // Alternative alias for skill identifier
	Input    map[string]any `json:"input,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
	Stream   bool           `json:"stream,omitempty"`
}

// TargetSkill returns the normalized skill ID from the request.
func (r *TaskSendRequest) TargetSkill() string {
	if r.SkillID != "" {
		return r.SkillID
	}
	return r.Skill
}

// TaskResponse represents the status and output of a task.
type TaskResponse struct {
	ID       string         `json:"id"`
	Status   string         `json:"status"` // "pending", "running", "completed", "failed", "cancelled"
	SkillID  string         `json:"skill_id,omitempty"`
	Output   map[string]any `json:"output,omitempty"`
	Error    string         `json:"error,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// MessageSendRequest represents a conversational message sent to an agent.
type MessageSendRequest struct {
	ID       string         `json:"id,omitempty"`
	TaskID   string         `json:"task_id,omitempty"`
	SkillID  string         `json:"skill_id,omitempty"`
	Content  string         `json:"content"`
	Role     string         `json:"role,omitempty"` // "user", "assistant", "system"
	Metadata map[string]any `json:"metadata,omitempty"`
}

// MessageResponse represents the agent's response to a message.
type MessageResponse struct {
	ID       string         `json:"id"`
	TaskID   string         `json:"task_id,omitempty"`
	Content  string         `json:"content"`
	Role     string         `json:"role,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// ErrorResponse represents an RFC-7807 / A2A standard error envelope.
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail describes the error code and message.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	SkillID string `json:"skill_id,omitempty"`
}
