package limits

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
)

// TokenUsage holds extracted actual token usage metrics.
type TokenUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// EstimateTokens calculates an upfront estimate of tokens required for a request.
// Heuristic: ~4 characters per token for input text + max_tokens for output.
func EstimateTokens(bodyBytes []byte, defaultMaxTokens int64) int64 {
	if defaultMaxTokens <= 0 {
		defaultMaxTokens = 1000
	}

	if len(bodyBytes) == 0 {
		return defaultMaxTokens
	}

	// Try extracting max_tokens and prompt/messages from JSON
	var payload struct {
		Prompt              any   `json:"prompt"`
		Messages            []any `json:"messages"`
		MaxTokens           int64 `json:"max_tokens"`
		MaxCompletionTokens int64 `json:"max_completion_tokens"`
	}

	inputChars := 0
	maxTokens := defaultMaxTokens

	if err := json.Unmarshal(bodyBytes, &payload); err == nil {
		if payload.MaxTokens > 0 {
			maxTokens = payload.MaxTokens
		} else if payload.MaxCompletionTokens > 0 {
			maxTokens = payload.MaxCompletionTokens
		}

		if s, ok := payload.Prompt.(string); ok {
			inputChars += len(s)
		} else if len(payload.Messages) > 0 {
			// Estimate characters in messages
			msgBytes, _ := json.Marshal(payload.Messages)
			inputChars += len(msgBytes)
		}
	} else {
		// Fallback: estimate based on total body length
		inputChars = len(bodyBytes)
	}

	// ~4 characters per token heuristic
	inputTokens := int64(math.Ceil(float64(inputChars) / 4.0))
	if inputTokens < 1 {
		inputTokens = 1
	}

	return inputTokens + maxTokens
}

// ParseUsageFromBody parses token usage from standard LLM response payloads.
// Supports:
// - OpenAI: usage.prompt_tokens, usage.completion_tokens, usage.total_tokens
// - Anthropic: usage.input_tokens, usage.output_tokens
// - Gemini: usageMetadata.promptTokenCount, usageMetadata.candidatesTokenCount
func ParseUsageFromBody(bodyBytes []byte) (*TokenUsage, bool) {
	if len(bodyBytes) == 0 {
		return nil, false
	}

	var root map[string]any
	if err := json.Unmarshal(bodyBytes, &root); err != nil {
		return nil, false
	}

	// 1. Check OpenAI / Anthropic format ("usage")
	if uVal, ok := root["usage"]; ok {
		if uMap, isMap := uVal.(map[string]any); isMap {
			return extractFromMap(uMap)
		}
	}

	// 2. Check Gemini format ("usageMetadata")
	if uVal, ok := root["usageMetadata"]; ok {
		if uMap, isMap := uVal.(map[string]any); isMap {
			prompt := getInt64(uMap, "promptTokenCount")
			completion := getInt64(uMap, "candidatesTokenCount")
			total := getInt64(uMap, "totalTokenCount")
			if total == 0 {
				total = prompt + completion
			}
			if total > 0 {
				return &TokenUsage{
					PromptTokens:     prompt,
					CompletionTokens: completion,
					TotalTokens:      total,
				}, true
			}
		}
	}

	return nil, false
}

// ParseUsageFromChunk inspects an SSE chunk for final usage statistics.
func ParseUsageFromChunk(chunk []byte) (*TokenUsage, bool) {
	lines := bytes.Split(chunk, []byte("\n"))
	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("data:")) {
			dataContent := bytes.TrimSpace(trimmed[5:])
			if bytes.Equal(dataContent, []byte("[DONE]")) {
				continue
			}
			if usage, ok := ParseUsageFromBody(dataContent); ok {
				return usage, true
			}
		}
	}
	return nil, false
}

func extractFromMap(m map[string]any) (*TokenUsage, bool) {
	prompt := getInt64(m, "prompt_tokens")
	if prompt == 0 {
		prompt = getInt64(m, "input_tokens")
	}

	completion := getInt64(m, "completion_tokens")
	if completion == 0 {
		completion = getInt64(m, "output_tokens")
	}

	total := getInt64(m, "total_tokens")
	if total == 0 {
		total = prompt + completion
	}

	if total > 0 || prompt > 0 || completion > 0 {
		return &TokenUsage{
			PromptTokens:     prompt,
			CompletionTokens: completion,
			TotalTokens:      total,
		}, true
	}

	return nil, false
}

func getInt64(m map[string]any, key string) int64 {
	v, ok := m[key]
	if !ok {
		// Also check case-insensitive or snake_case
		for mk, mv := range m {
			if strings.EqualFold(mk, key) {
				v = mv
				ok = true
				break
			}
		}
	}
	if !ok {
		return 0
	}

	switch val := v.(type) {
	case float64:
		return int64(val)
	case int64:
		return val
	case int:
		return int64(val)
	case json.Number:
		i, _ := val.Int64()
		return i
	default:
		return 0
	}
}
