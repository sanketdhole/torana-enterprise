package http

import (
	"github.com/phaselume/torana/internal/egress"
)

// HTTPClient aliases the egress HTTP client.
type HTTPClient = egress.HTTPClient

// NewHTTPClient constructs a new HTTP egress client with pooled connections.
var NewHTTPClient = egress.NewHTTPClient
