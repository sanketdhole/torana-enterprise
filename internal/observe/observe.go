package observe

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Config is the top-level observability configuration.
type Config struct {
	// LogLevel controls the minimum slog level (default: slog.LevelInfo).
	LogLevel slog.Level

	// AuditShipperConfig configures the audit event pipeline.
	AuditShipperConfig *ShipperConfig

	// EnableTracing controls whether the OTel tracer provider is initialised.
	EnableTracing bool
	// EnableMetrics controls whether the OTel meter provider is initialised.
	EnableMetrics bool
}

// Provider is the top-level observability handle providing access to tracing,
// metrics, structured logging, and the audit shipper.
type Provider struct {
	Logger  *slog.Logger
	Metrics *Metrics
	Shipper *Shipper

	shutdownTrace   func(context.Context) error
	shutdownMetrics func(context.Context) error
}

// Shutdown gracefully flushes and stops all observability subsystems.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p.Shipper != nil {
		p.Shipper.Stop(5 * time.Second)
	}
	if p.shutdownTrace != nil {
		_ = p.shutdownTrace(ctx)
	}
	if p.shutdownMetrics != nil {
		_ = p.shutdownMetrics(ctx)
	}
	return nil
}

// ObserveRequest is a convenience wrapper that instruments a unit of work with
// a span, in-flight/latency/counter metrics, and an audit event — guaranteeing
// the caller is never blocked by observability. The supplied function fn
// receives a context with an active span.
func (p *Provider) ObserveRequest(
	ctx context.Context,
	pluginID, phase, route string,
	capturePayload bool,
	payload []byte,
	fn func(ctx context.Context) error,
) error {
	// --- Span ---
	ctx, span := StartSpan(ctx, "observe.request",
		trace.WithAttributes(
			attribute.String("plugin", pluginID),
			attribute.String("phase", phase),
			attribute.String("route", route),
		),
	)
	defer span.End()

	// --- In-flight ---
	if p.Metrics != nil {
		p.Metrics.IncInflight(ctx, pluginID)
		defer p.Metrics.DecInflight(ctx, pluginID)
	}

	start := time.Now()
	err := fn(ctx)
	durationMs := float64(time.Since(start).Milliseconds())

	// --- Metrics ---
	if p.Metrics != nil {
		p.Metrics.RecordRequest(ctx, pluginID, phase, route, durationMs, err)
	}

	// --- Span status ---
	if err != nil {
		span.RecordError(err)
	}

	// --- Audit (non-blocking) ---
	if p.Shipper != nil {
		ev := AuditEvent{
			Timestamp:  start,
			TraceID:    span.SpanContext().TraceID().String(),
			RequestID:  "", // caller may enrich
			RouteID:    route,
			PluginID:   pluginID,
			Phase:      phase,
			DurationMs: int64(durationMs),
		}
		if err != nil {
			ev.Error = err.Error()
		}
		if capturePayload {
			ev.Payload = payload
		}
		p.Shipper.Capture(ev) // never blocks
	}

	return err
}
