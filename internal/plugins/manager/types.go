package manager

import (
	"errors"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
)

var (
	// ErrUnsupportedABI is returned when the plugin manifest requests an ABI version not supported by the gateway runtime.
	ErrUnsupportedABI = errors.New("unsupported plugin ABI version")
	// ErrDisallowedCapability is returned when the plugin requests capabilities not permitted by platform policy.
	ErrDisallowedCapability = errors.New("requested capability is not allowed by policy")
	// ErrSchemaValidationFailed is returned when the plugin configuration fails its JSON Schema validation.
	ErrSchemaValidationFailed = errors.New("plugin config failed JSON schema validation")
	// ErrHealthCheckFailed is returned when the shadow instance fails its initial smoke test or health probe.
	ErrHealthCheckFailed = errors.New("plugin shadow health check probe failed")
	// ErrRollbackUnavailable is returned when attempting to rollback a plugin that has no previous version.
	ErrRollbackUnavailable = errors.New("no previous plugin version available for rollback")
	// ErrVersionPinnedMismatch is returned when an assignment requests a pinned version that does not match the artifact.
	ErrVersionPinnedMismatch = errors.New("artifact version does not match pinned version constraint")
	// ErrNilAssignment is returned when attempting to install a nil plugin assignment.
	ErrNilAssignment = errors.New("plugin assignment cannot be nil")
	// ErrPluginNotFound is returned when querying or rolling back an unregistered plugin.
	ErrPluginNotFound = errors.New("plugin not found")
)

// InstallRequest specifies the parameters and constraints for installing or updating a plugin.
type InstallRequest struct {
	Assignment       *controlplanev1.PluginAssignment `json:"assignment"`
	ArtifactRef      string                           `json:"artifact_ref"`
	PinnedVersion    string                           `json:"pinned_version,omitempty"`
	CanaryPercentage int                              `json:"canary_percentage,omitempty"` // 0 to 100
	PullToken        string                           `json:"pull_token,omitempty"`
	DryRun           bool                             `json:"dry_run,omitempty"`
}

// InstallResult details the outcome of an installation attempt.
type InstallResult struct {
	Success          bool                          `json:"success"`
	PluginID         string                        `json:"plugin_id"`
	Version          string                        `json:"version"`
	Digest           string                        `json:"digest"`
	CanaryPercentage int                           `json:"canary_percentage"`
	Status           *controlplanev1.PluginStatus  `json:"status"`
	NackCode         string                        `json:"nack_code,omitempty"`
	NackReason       string                        `json:"nack_reason,omitempty"`
}
