package observe

import (
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// otelResource returns the OTel resource descriptor identifying this service.
func otelResource() *resource.Resource {
	r, _ := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("torana-gateway"),
			semconv.ServiceVersion("0.1.0"),
		),
	)
	return r
}
