package http

import (
	"github.com/phaselume/torana/internal/ingress"
)

// HTTPListener aliases the ingress HTTP listener.
type HTTPListener = ingress.HTTPListener

// NewHTTPListener constructs a new HTTP ingress listener.
var NewHTTPListener = ingress.NewHTTPListener
