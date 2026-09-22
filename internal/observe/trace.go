package observe

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// tracerName is the instrumentation library name used for all spans.
const tracerName = "github.com/phaselume/torana/internal/observe"

// tracer is the package-level tracer.
var tracer = otel.Tracer(tracerName)

// InitTracer configures the global OTel tracer provider and W3C propagator.
// Returns a shutdown function that must be called at process exit.
func InitTracer(ctx context.Context, exporter sdktrace.SpanExporter) (func(context.Context) error, error) {
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(otelResource()),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	)

	// Re-bind the package-level tracer to the real provider.
	tracer = tp.Tracer(tracerName)

	return tp.Shutdown, nil
}

// StartSpan begins a new span in the current trace and returns the child context.
func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return tracer.Start(ctx, name, opts...)
}

// SpanFromContext returns the current span from context (never nil).
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// InjectTraceContext serialises the W3C traceparent/tracestate into a flat
// string map suitable for gRPC metadata or internal envelope propagation.
func InjectTraceContext(ctx context.Context, carrier map[string]string) {
	otel.GetTextMapPropagator().Inject(ctx, propagation.MapCarrier(carrier))
}

// ExtractTraceContext deserialises W3C headers from a flat string map.
func ExtractTraceContext(ctx context.Context, carrier map[string]string) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, propagation.MapCarrier(carrier))
}

// InjectHTTP injects trace context into outgoing HTTP request headers.
func InjectHTTP(ctx context.Context, req *http.Request) {
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))
}

// ExtractHTTP extracts trace context from incoming HTTP request headers.
func ExtractHTTP(ctx context.Context, req *http.Request) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(req.Header))
}

// TraceMiddleware is an HTTP middleware that extracts W3C trace context from
// inbound requests, creates a server span, and propagates context downstream.
func TraceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := ExtractHTTP(r.Context(), r)
		ctx, span := StartSpan(ctx, r.Method+" "+r.URL.Path,
			trace.WithSpanKind(trace.SpanKindServer),
		)
		defer span.End()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// EnvelopeTraceCarrier adapts a pipeline Envelope's Metadata map for trace
// propagation so that trace context can travel across internal process
// boundaries without HTTP headers.
type EnvelopeTraceCarrier struct {
	Metadata map[string]string
}

func (c EnvelopeTraceCarrier) Get(key string) string   { return c.Metadata[key] }
func (c EnvelopeTraceCarrier) Set(key, value string)    { c.Metadata[key] = value }
func (c EnvelopeTraceCarrier) Keys() []string {
	keys := make([]string, 0, len(c.Metadata))
	for k := range c.Metadata {
		keys = append(keys, k)
	}
	return keys
}

// InjectEnvelope writes trace context into the envelope metadata map.
func InjectEnvelope(ctx context.Context, metadata map[string]string) {
	otel.GetTextMapPropagator().Inject(ctx, EnvelopeTraceCarrier{Metadata: metadata})
}

// ExtractEnvelope reads trace context from the envelope metadata map.
func ExtractEnvelope(ctx context.Context, metadata map[string]string) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, EnvelopeTraceCarrier{Metadata: metadata})
}
