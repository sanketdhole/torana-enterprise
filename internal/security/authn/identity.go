package authn

import (
	"context"
	"fmt"
	"slices"

	"github.com/phaselume/torana/internal/pipeline"
)

type contextKey struct{}

var identityContextKey = contextKey{}

// Identity represents the authenticated identity of a caller.
type Identity struct {
	Subject    string         `json:"subject"`
	Tenant     string         `json:"tenant"`
	Groups     []string       `json:"groups"`
	Scopes     []string       `json:"scopes"`
	Claims     map[string]any `json:"claims"`
	AuthMethod string         `json:"auth_method"` // e.g. "jwt", "api_key", "mtls", "custom"
}

// NewIdentity constructs a initialized Identity.
func NewIdentity(subject, tenant, authMethod string) *Identity {
	return &Identity{
		Subject:    subject,
		Tenant:     tenant,
		Groups:     make([]string, 0),
		Scopes:     make([]string, 0),
		Claims:     make(map[string]any),
		AuthMethod: authMethod,
	}
}

// HasScope checks if the identity contains a specific scope.
func (id *Identity) HasScope(scope string) bool {
	if id == nil {
		return false
	}
	return slices.Contains(id.Scopes, scope)
}

// InGroup checks if the identity belongs to a specific group/role.
func (id *Identity) InGroup(group string) bool {
	if id == nil {
		return false
	}
	return slices.Contains(id.Groups, group)
}

// GetClaim returns the value of a specific claim if present.
func (id *Identity) GetClaim(key string) (any, bool) {
	if id == nil || id.Claims == nil {
		return nil, false
	}
	v, ok := id.Claims[key]
	return v, ok
}

// GetClaimString returns a string claim value or empty string if not found.
func (id *Identity) GetClaimString(key string) string {
	if v, ok := id.GetClaim(key); ok {
		switch s := v.(type) {
		case string:
			return s
		case fmt.Stringer:
			return s.String()
		default:
			return fmt.Sprintf("%v", s)
		}
	}
	return ""
}

// Clone creates a deep copy of the Identity.
func (id *Identity) Clone() *Identity {
	if id == nil {
		return nil
	}
	claimsCopy := make(map[string]any, len(id.Claims))
	for k, v := range id.Claims {
		claimsCopy[k] = v
	}
	return &Identity{
		Subject:    id.Subject,
		Tenant:     id.Tenant,
		Groups:     slices.Clone(id.Groups),
		Scopes:     slices.Clone(id.Scopes),
		Claims:     claimsCopy,
		AuthMethod: id.AuthMethod,
	}
}

// SetIdentity attaches the Identity to the request envelope and synchronizes client identity.
func SetIdentity(env *pipeline.Envelope, id *Identity) {
	if env == nil || id == nil {
		return
	}
	env.Identity = id
	env.PeerInfo.ClientIdentity = id.Subject
	if env.Claims == nil {
		env.Claims = make(map[string]string)
	}
	if id.Subject != "" {
		env.Claims["sub"] = id.Subject
	}
	if id.Tenant != "" {
		env.Claims["tenant"] = id.Tenant
	}
	for k, v := range id.Claims {
		if _, exists := env.Claims[k]; !exists {
			if s, ok := v.(string); ok {
				env.Claims[k] = s
			} else {
				env.Claims[k] = fmt.Sprintf("%v", v)
			}
		}
	}
}

// GetIdentity extracts the Identity from the pipeline envelope.
func GetIdentity(env *pipeline.Envelope) (*Identity, bool) {
	if env == nil || env.Identity == nil {
		return nil, false
	}
	id, ok := env.Identity.(*Identity)
	return id, ok
}

// WithIdentity stores the Identity in a standard context.Context.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityContextKey, id)
}

// IdentityFromContext retrieves the Identity from context.Context.
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(identityContextKey).(*Identity)
	return id, ok
}
