package observe

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Metrics holds the pre-registered OTel metric instruments.
// All instruments use the "torana." namespace for Prometheus exposition.
type Metrics struct {
	// requestCounter counts completed requests, keyed by plugin/phase/route.
	requestCounter metric.Int64Counter
	// latencyHistogram records per-request latency in milliseconds.
	latencyHistogram metric.Float64Histogram
	// inflightGauge tracks in-flight requests per plugin.
	inflightGauge metric.Int64UpDownCounter
	// tokenUsageCounter tracks token consumption per plugin.
	tokenUsageCounter metric.Int64Counter
	// configVersionGauge exposes the active config snapshot version.
	configVersionGauge metric.Int64Gauge
	// pluginStateGauge exposes per-plugin lifecycle state as an enum ordinal.
	pluginStateGauge metric.Int64Gauge
	// auditDroppedCounter counts audit events lost due to ring buffer saturation.
	auditDroppedCounter metric.Int64Counter

	provider *sdkmetric.MeterProvider
}

// InitMetrics creates a MeterProvider from the supplied reader (Prometheus or
// OTLP) and registers all Torana metric instruments.
// Returns a Metrics handle and a shutdown function.
func InitMetrics(reader sdkmetric.Reader) (*Metrics, func(context.Context) error, error) {
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
		sdkmetric.WithResource(otelResource()),
	)

	meter := mp.Meter(tracerName)

	reqCounter, err := meter.Int64Counter("torana.request.count",
		metric.WithDescription("Total completed requests"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, nil, err
	}

	latHist, err := meter.Float64Histogram("torana.request.duration",
		metric.WithDescription("Request latency in milliseconds"),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 5000),
	)
	if err != nil {
		return nil, nil, err
	}

	inflight, err := meter.Int64UpDownCounter("torana.request.inflight",
		metric.WithDescription("Currently in-flight requests"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, nil, err
	}

	tokenCounter, err := meter.Int64Counter("torana.token.usage",
		metric.WithDescription("Token consumption"),
		metric.WithUnit("{token}"),
	)
	if err != nil {
		return nil, nil, err
	}

	cfgGauge, err := meter.Int64Gauge("torana.config.version",
		metric.WithDescription("Active configuration snapshot version"),
	)
	if err != nil {
		return nil, nil, err
	}

	pluginGauge, err := meter.Int64Gauge("torana.plugin.state",
		metric.WithDescription("Plugin lifecycle state ordinal (0=inactive, 1=active, 2=canary, 3=rollback)"),
	)
	if err != nil {
		return nil, nil, err
	}

	auditDropped, err := meter.Int64Counter("torana.audit.dropped",
		metric.WithDescription("Audit events dropped due to ring buffer saturation"),
		metric.WithUnit("{event}"),
	)
	if err != nil {
		return nil, nil, err
	}

	m := &Metrics{
		requestCounter:      reqCounter,
		latencyHistogram:    latHist,
		inflightGauge:       inflight,
		tokenUsageCounter:   tokenCounter,
		configVersionGauge:  cfgGauge,
		pluginStateGauge:    pluginGauge,
		auditDroppedCounter: auditDropped,
		provider:            mp,
	}

	return m, mp.Shutdown, nil
}

// --- Recording helpers -------------------------------------------------------

// RecordRequest increments request counter and records latency.
func (m *Metrics) RecordRequest(ctx context.Context, plugin, phase, route string, durationMs float64, err error) {
	if m == nil {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("plugin", plugin),
		attribute.String("phase", phase),
		attribute.String("route", route),
		attribute.Bool("error", err != nil),
	)
	m.requestCounter.Add(ctx, 1, attrs)
	m.latencyHistogram.Record(ctx, durationMs, attrs)
}

// IncInflight adds 1 to in-flight for the given plugin.
func (m *Metrics) IncInflight(ctx context.Context, plugin string) {
	if m == nil {
		return
	}
	m.inflightGauge.Add(ctx, 1, metric.WithAttributes(attribute.String("plugin", plugin)))
}

// DecInflight subtracts 1 from in-flight for the given plugin.
func (m *Metrics) DecInflight(ctx context.Context, plugin string) {
	if m == nil {
		return
	}
	m.inflightGauge.Add(ctx, -1, metric.WithAttributes(attribute.String("plugin", plugin)))
}

// RecordTokens records token usage for a plugin.
func (m *Metrics) RecordTokens(ctx context.Context, plugin, tokenType string, count int64) {
	if m == nil {
		return
	}
	m.tokenUsageCounter.Add(ctx, count, metric.WithAttributes(
		attribute.String("plugin", plugin),
		attribute.String("token_type", tokenType),
	))
}

// SetConfigVersion records the active config version.
func (m *Metrics) SetConfigVersion(ctx context.Context, version int64) {
	if m == nil {
		return
	}
	m.configVersionGauge.Record(ctx, version)
}

// SetPluginState records the lifecycle state of a plugin.
// States: 0=inactive, 1=active, 2=canary, 3=rollback.
func (m *Metrics) SetPluginState(ctx context.Context, plugin string, stateOrdinal int64) {
	if m == nil {
		return
	}
	m.pluginStateGauge.Record(ctx, stateOrdinal, metric.WithAttributes(
		attribute.String("plugin", plugin),
	))
}

// IncAuditDropped increments the audit-dropped counter.
func (m *Metrics) IncAuditDropped(ctx context.Context) {
	if m == nil {
		return
	}
	m.auditDroppedCounter.Add(ctx, 1)
}
