package manager

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/plugins/process"
	"github.com/phaselume/torana/internal/plugins/wasm"
)

// Manifest represents the universal configuration and constraint specification for a Torana plugin.
type Manifest struct {
	Name             string                   `json:"name"`
	Version          string                   `json:"version"`
	Runtime          string                   `json:"runtime"` // "wasm" or "process"
	ABICompatibility string                   `json:"abi_compatibility"`
	Capabilities     []string                 `json:"capabilities"`
	ConfigSchema     map[string]any           `json:"config_schema,omitempty"`
	Phase            string                   `json:"phase"`
	BodyMode         string                   `json:"body_mode"`
	FailurePolicy    string                   `json:"failure_policy"`
	TimeoutMs        int64                    `json:"timeout_ms"`
	Wasm             *wasm.PluginManifest     `json:"wasm,omitempty"`
	Process          *process.ProcessManifest `json:"process,omitempty"`
}

// ParseManifest deserializes a JSON manifest payload.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to parse plugin manifest: %w", err)
	}
	return &m, nil
}

// ValidateManifest validates manifest structural integrity, ABI compatibility, and requested capabilities.
func ValidateManifest(m *Manifest, supportedABIs []string, allowedCaps []string) error {
	if m == nil {
		return fmt.Errorf("manifest cannot be nil")
	}
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("manifest name is required")
	}
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("manifest version is required")
	}

	runtime := strings.ToLower(m.Runtime)
	if runtime != "wasm" && runtime != "process" {
		return fmt.Errorf("invalid plugin runtime %q (must be 'wasm' or 'process')", m.Runtime)
	}

	// 1. ABI Compatibility Check
	if len(supportedABIs) > 0 {
		abiSupported := false
		for _, abi := range supportedABIs {
			if strings.EqualFold(abi, m.ABICompatibility) {
				abiSupported = true
				break
			}
		}
		if !abiSupported {
			return fmt.Errorf("%w: declared ABI %q is not supported by gateway (supported: %v)", ErrUnsupportedABI, m.ABICompatibility, supportedABIs)
		}
	}

	// 2. Capability Allowlist Check
	if len(allowedCaps) > 0 {
		allowedSet := make(map[string]struct{}, len(allowedCaps))
		for _, c := range allowedCaps {
			allowedSet[strings.ToLower(c)] = struct{}{}
		}

		for _, capReq := range m.Capabilities {
			norm := strings.ToLower(capReq)
			if _, ok := allowedSet[norm]; !ok {
				return fmt.Errorf("%w: capability %q is not permitted by gateway policy", ErrDisallowedCapability, capReq)
			}
		}
	}

	return nil
}

// ToPipelinePhase converts string phase name into pipeline.Phase.
func (m *Manifest) ToPipelinePhase() pipeline.Phase {
	switch strings.ToUpper(m.Phase) {
	case "AUTHN":
		return pipeline.PhaseAuthn
	case "REQUEST_BODY":
		return pipeline.PhaseRequestBody
	case "RESPONSE_HEADERS":
		return pipeline.PhaseResponseHeaders
	case "RESPONSE_BODY":
		return pipeline.PhaseResponseBody
	default:
		return pipeline.PhaseRequestHeaders
	}
}

// ToPipelineBodyMode converts string body mode into pipeline.BodyMode.
func (m *Manifest) ToPipelineBodyMode() pipeline.BodyMode {
	switch strings.ToUpper(m.BodyMode) {
	case "STREAMING":
		return pipeline.BodyModeStreaming
	case "BUFFERED":
		return pipeline.BodyModeBuffered
	default:
		return pipeline.BodyModeNone
	}
}

// ToPipelineFailurePolicy converts string failure policy into pipeline.FailurePolicy.
func (m *Manifest) ToPipelineFailurePolicy() pipeline.FailurePolicy {
	if strings.EqualFold(m.FailurePolicy, "FAIL_OPEN") {
		return pipeline.FailurePolicyFailOpen
	}
	return pipeline.FailurePolicyFailClosed
}

// TimeoutDuration returns the per-call timeout duration.
func (m *Manifest) TimeoutDuration() time.Duration {
	if m.TimeoutMs > 0 {
		return time.Duration(m.TimeoutMs) * time.Millisecond
	}
	return 250 * time.Millisecond
}

// ValidateConfigJSON validates a plugin configuration JSON payload against a JSON Schema definition.
func ValidateConfigJSON(schema map[string]any, configJSON string) error {
	if len(schema) == 0 {
		return nil
	}
	if strings.TrimSpace(configJSON) == "" || strings.TrimSpace(configJSON) == "{}" {
		// Check if required fields exist
		if req, ok := schema["required"]; ok {
			if reqList, ok := req.([]any); ok && len(reqList) > 0 {
				return fmt.Errorf("%w: missing required field %v", ErrSchemaValidationFailed, reqList[0])
			}
			if strList, ok := req.([]string); ok && len(strList) > 0 {
				return fmt.Errorf("%w: missing required field %v", ErrSchemaValidationFailed, strList[0])
			}
		}
		return nil
	}

	var data any
	if err := json.Unmarshal([]byte(configJSON), &data); err != nil {
		return fmt.Errorf("%w: invalid JSON syntax: %v", ErrSchemaValidationFailed, err)
	}

	return validateSchemaNode(schema, data, "")
}

func validateSchemaNode(schema map[string]any, data any, fieldPath string) error {
	// Type check
	if expectedType, ok := schema["type"].(string); ok {
		switch expectedType {
		case "object":
			obj, ok := data.(map[string]any)
			if !ok {
				return fmt.Errorf("%w: field %q expected object, got %T", ErrSchemaValidationFailed, fieldPath, data)
			}

			// Validate required properties
			if req, ok := schema["required"]; ok {
				var requiredFields []string
				switch r := req.(type) {
				case []any:
					for _, item := range r {
						if s, ok := item.(string); ok {
							requiredFields = append(requiredFields, s)
						}
					}
				case []string:
					requiredFields = r
				}

				for _, rf := range requiredFields {
					if _, exists := obj[rf]; !exists {
						return fmt.Errorf("%w: missing required property %q at %q", ErrSchemaValidationFailed, rf, fieldPath)
					}
				}
			}

			// Validate properties
			if props, ok := schema["properties"].(map[string]any); ok {
				for propName, propSchema := range props {
					if propSchemaMap, ok := propSchema.(map[string]any); ok {
						if val, exists := obj[propName]; exists {
							subPath := propName
							if fieldPath != "" {
								subPath = fieldPath + "." + propName
							}
							if err := validateSchemaNode(propSchemaMap, val, subPath); err != nil {
								return err
							}
						}
					}
				}
			}

		case "string":
			s, ok := data.(string)
			if !ok {
				return fmt.Errorf("%w: field %q expected string, got %T", ErrSchemaValidationFailed, fieldPath, data)
			}
			if enumList, ok := schema["enum"].([]any); ok {
				matched := false
				for _, e := range enumList {
					if es, ok := e.(string); ok && es == s {
						matched = true
						break
					}
				}
				if !matched {
					return fmt.Errorf("%w: value %q not allowed in enum %v at %q", ErrSchemaValidationFailed, s, enumList, fieldPath)
				}
			}

		case "integer":
			val, ok := data.(float64)
			if !ok || val != float64(int64(val)) {
				return fmt.Errorf("%w: field %q expected integer, got %T", ErrSchemaValidationFailed, fieldPath, data)
			}
			if min, ok := schema["minimum"].(float64); ok && val < min {
				return fmt.Errorf("%w: field %q value %v is less than minimum %v", ErrSchemaValidationFailed, fieldPath, val, min)
			}
			if max, ok := schema["maximum"].(float64); ok && val > max {
				return fmt.Errorf("%w: field %q value %v is greater than maximum %v", ErrSchemaValidationFailed, fieldPath, val, max)
			}

		case "number":
			val, ok := data.(float64)
			if !ok {
				return fmt.Errorf("%w: field %q expected number, got %T", ErrSchemaValidationFailed, fieldPath, data)
			}
			if min, ok := schema["minimum"].(float64); ok && val < min {
				return fmt.Errorf("%w: field %q value %v is less than minimum %v", ErrSchemaValidationFailed, fieldPath, val, min)
			}

		case "boolean":
			if _, ok := data.(bool); !ok {
				return fmt.Errorf("%w: field %q expected boolean, got %T", ErrSchemaValidationFailed, fieldPath, data)
			}

		case "array":
			arr, ok := data.([]any)
			if !ok {
				return fmt.Errorf("%w: field %q expected array, got %T", ErrSchemaValidationFailed, fieldPath, data)
			}
			if itemsSchema, ok := schema["items"].(map[string]any); ok {
				for i, item := range arr {
					subPath := fmt.Sprintf("%s[%d]", fieldPath, i)
					if err := validateSchemaNode(itemsSchema, item, subPath); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}
