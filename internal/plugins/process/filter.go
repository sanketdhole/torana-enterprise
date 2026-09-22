package process

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	pluginv1 "github.com/phaselume/torana/api/proto/plugin/v1"
	"github.com/phaselume/torana/internal/pipeline"
)

// ProcessFilter integrates an out-of-process or remote gRPC plugin into pipeline.Filter and pipeline.ChunkHook.
type ProcessFilter struct {
	manifest       *ProcessManifest
	launcher       *ProcessLauncher
	client         *PluginClient
	circuitBreaker *pipeline.CircuitBreaker
	logger         *slog.Logger
}

// NewProcessFilter creates a new ProcessFilter.
func NewProcessFilter(manifest *ProcessManifest, launcher *ProcessLauncher, client *PluginClient, logger *slog.Logger) *ProcessFilter {
	threshold := manifest.CircuitBreakerThreshold
	if threshold <= 0 {
		threshold = 5
	}
	cooldown := manifest.CircuitBreakerCooldown
	if cooldown <= 0 {
		cooldown = 10 * time.Second
	}

	return &ProcessFilter{
		manifest:       manifest,
		launcher:       launcher,
		client:         client,
		circuitBreaker: pipeline.NewCircuitBreaker(threshold, cooldown),
		logger:         logger,
	}
}

// Name returns the plugin identifier.
func (f *ProcessFilter) Name() string {
	return f.manifest.Name
}

// Phase returns the lifecycle phase this filter runs in.
func (f *ProcessFilter) Phase() pipeline.Phase {
	return f.manifest.Phase
}

// BodyMode returns the body inspection mode.
func (f *ProcessFilter) BodyMode() pipeline.BodyMode {
	return f.manifest.BodyMode
}

// FailurePolicy returns fail-closed vs fail-open.
func (f *ProcessFilter) FailurePolicy() pipeline.FailurePolicy {
	return f.manifest.FailurePolicy
}

// Process executes request/response inspection and mutation over gRPC.
func (f *ProcessFilter) Process(ctx context.Context, env *pipeline.Envelope) (pipeline.Decision, error) {
	// 1. Enforce Circuit Breaker
	if !f.circuitBreaker.Allow() {
		return f.handleError(ErrCircuitOpen)
	}

	// 2. Track in-flight calls on child process
	if f.launcher != nil {
		f.launcher.InFlightAdd(1)
		defer f.launcher.InFlightAdd(-1)
	}

	// 3. Apply per-call timeout
	timeout := f.manifest.Timeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 4. Resolve Body if buffered
	var bodyBytes []byte
	var err error
	if f.manifest.BodyMode == pipeline.BodyModeBuffered {
		bodyBytes, err = env.GetBufferedBody(1024 * 1024)
		if err != nil {
			return f.handleError(err)
		}
	}

	// 5. Convert Envelope
	pbEnv := convertToProtoEnvelope(env, bodyBytes)

	// 6. Invoke gRPC stub
	grpcClient := f.client.Client()
	if grpcClient == nil {
		return f.handleError(ErrPluginClosed)
	}

	var pbDec *pluginv1.Decision
	if env.Phase == pipeline.PhaseResponseHeaders || env.Phase == pipeline.PhaseResponseBody {
		pbDec, err = grpcClient.OnResponse(callCtx, pbEnv)
	} else {
		pbDec, err = grpcClient.OnRequest(callCtx, pbEnv)
	}

	if err != nil {
		f.circuitBreaker.RecordFailure()
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			return f.handleError(ErrPluginTimeout)
		}
		return f.handleError(fmt.Errorf("grpc call to plugin failed: %w", err))
	}

	// Success
	f.circuitBreaker.RecordSuccess()
	return convertFromProtoDecision(pbDec), nil
}

// OnChunk inspects or mutates individual streaming chunks.
func (f *ProcessFilter) OnChunk(ctx context.Context, env *pipeline.Envelope, chunk []byte) ([]byte, error) {
	if len(chunk) == 0 {
		return chunk, nil
	}

	if !f.circuitBreaker.Allow() {
		if f.manifest.FailurePolicy == pipeline.FailurePolicyFailOpen {
			return chunk, nil
		}
		return nil, ErrCircuitOpen
	}

	if f.launcher != nil {
		f.launcher.InFlightAdd(1)
		defer f.launcher.InFlightAdd(-1)
	}

	timeout := f.manifest.Timeout
	if timeout <= 0 {
		timeout = 250 * time.Millisecond
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	grpcClient := f.client.Client()
	if grpcClient == nil {
		if f.manifest.FailurePolicy == pipeline.FailurePolicyFailOpen {
			return chunk, nil
		}
		return nil, ErrPluginClosed
	}

	stream, err := grpcClient.OnChunk(callCtx)
	if err != nil {
		f.circuitBreaker.RecordFailure()
		if f.manifest.FailurePolicy == pipeline.FailurePolicyFailOpen {
			return chunk, nil
		}
		return nil, err
	}

	reqID := ""
	if env != nil {
		reqID = env.RequestID
	}

	if err := stream.Send(&pluginv1.ChunkEnvelope{
		RequestId: reqID,
		Chunk:     chunk,
	}); err != nil {
		f.circuitBreaker.RecordFailure()
		if f.manifest.FailurePolicy == pipeline.FailurePolicyFailOpen {
			return chunk, nil
		}
		return nil, err
	}
	_ = stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		f.circuitBreaker.RecordFailure()
		if f.manifest.FailurePolicy == pipeline.FailurePolicyFailOpen {
			return chunk, nil
		}
		return nil, err
	}

	f.circuitBreaker.RecordSuccess()
	if len(resp.TransformedChunk) > 0 {
		return resp.TransformedChunk, nil
	}
	return chunk, nil
}

func (f *ProcessFilter) handleError(err error) (pipeline.Decision, error) {
	if f.logger != nil {
		f.logger.Warn("process plugin execution error",
			"plugin", f.manifest.Name,
			"policy", f.manifest.FailurePolicy,
			"error", err,
		)
	}

	if f.manifest.FailurePolicy == pipeline.FailurePolicyFailOpen {
		return pipeline.ContinueDecision(), nil
	}

	statusCode := 500
	if errors.Is(err, ErrPluginTimeout) {
		statusCode = 504
	} else if errors.Is(err, ErrCircuitOpen) {
		statusCode = 503
	}

	return pipeline.HaltDecision(statusCode, err.Error()), err
}

// Close terminates client connection and launcher.
func (f *ProcessFilter) Close() error {
	var err1, err2 error
	if f.client != nil {
		err1 = f.client.Close()
	}
	if f.launcher != nil {
		err2 = f.launcher.Close()
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func convertToProtoEnvelope(env *pipeline.Envelope, body []byte) *pluginv1.Envelope {
	headers := make(map[string]string)
	for k, v := range env.Headers {
		if len(v) > 0 {
			headers[k] = v[0]
			headers[strings.ToLower(k)] = v[0]
		}
	}

	metadata := make(map[string]string)
	for k, v := range env.Metadata {
		metadata[k] = v
	}

	var peerInfo *pluginv1.PeerInfo
	peerInfo = &pluginv1.PeerInfo{
		RemoteIp:       env.PeerInfo.RemoteIP,
		Protocol:       env.PeerInfo.Protocol,
		ClientIdentity: env.PeerInfo.ClientIdentity,
	}

	return &pluginv1.Envelope{
		RequestId: env.RequestID,
		RouteId:   "",
		Phase:     pluginv1.Phase(env.Phase),
		Headers:   headers,
		Metadata:  metadata,
		Body:      body,
		PeerInfo:  peerInfo,
	}
}

func convertFromProtoDecision(p *pluginv1.Decision) pipeline.Decision {
	if p == nil {
		return pipeline.ContinueDecision()
	}

	statusCode := int(p.StatusCode)
	if statusCode == 0 {
		statusCode = 200
	}

	return pipeline.Decision{
		Action:         pipeline.Action(p.Action),
		StatusCode:     statusCode,
		Reason:         p.Reason,
		MutateHeaders:  p.MutateHeaders,
		MutateBody:     p.MutateBody,
		MutateMetadata: p.MutateMetadata,
	}
}
