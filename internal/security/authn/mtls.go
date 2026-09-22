package authn

import (
	"context"
	"crypto/x509"
	"net/url"
	"strings"

	"github.com/phaselume/torana/internal/pipeline"
)

// MTLSProviderConfig holds configuration for mTLS client identity extraction.
type MTLSProviderConfig struct {
	// RequireClientCert if true will fail closed if no certificate is provided.
	// If false, returns ErrNoCredentials so downstream authenticators can evaluate.
	RequireClientCert bool
	// TenantExtractor is an optional custom function to extract a tenant from the certificate.
	TenantExtractor func(cert *x509.Certificate) string
}

// MTLSProvider extracts authenticated identity from verified client TLS certificates.
type MTLSProvider struct {
	requireCert     bool
	tenantExtractor func(cert *x509.Certificate) string
}

// NewMTLSProvider constructs an MTLSProvider.
func NewMTLSProvider(cfg MTLSProviderConfig) *MTLSProvider {
	return &MTLSProvider{
		requireCert:     cfg.RequireClientCert,
		tenantExtractor: cfg.TenantExtractor,
	}
}

func (m *MTLSProvider) Name() string {
	return "mtls"
}

// Authenticate extracts caller identity from client certificates attached to the envelope.
func (m *MTLSProvider) Authenticate(ctx context.Context, env *pipeline.Envelope) (*Identity, error) {
	if env == nil || env.PeerInfo.TLS == nil || len(env.PeerInfo.TLS.PeerCertificates) == 0 {
		if m.requireCert {
			return nil, ErrUntrustedCert
		}
		return nil, ErrNoCredentials
	}

	cert := env.PeerInfo.TLS.PeerCertificates[0]
	return m.ExtractIdentity(cert)
}

// ExtractIdentity extracts subject, tenant, groups, and claims from an X.509 client certificate.
// Priority for Subject:
// 1. SAN URI (e.g. SPIFFE ID: spiffe://cluster.local/ns/prod/sa/payment-service)
// 2. SAN DNS
// 3. SAN Email
// 4. Subject Common Name (CN)
func (m *MTLSProvider) ExtractIdentity(cert *x509.Certificate) (*Identity, error) {
	if cert == nil {
		return nil, ErrUntrustedCert
	}

	var subject string
	var spiffeURI *url.URL

	// 1. SAN URI extraction (SPIFFE identity)
	if len(cert.URIs) > 0 {
		for _, u := range cert.URIs {
			if u != nil {
				subject = u.String()
				if strings.EqualFold(u.Scheme, "spiffe") {
					spiffeURI = u
				}
				break
			}
		}
	}

	// 2. SAN DNS fallback
	if subject == "" && len(cert.DNSNames) > 0 {
		subject = cert.DNSNames[0]
	}

	// 3. SAN Email fallback
	if subject == "" && len(cert.EmailAddresses) > 0 {
		subject = cert.EmailAddresses[0]
	}

	// 4. Common Name fallback
	if subject == "" && cert.Subject.CommonName != "" {
		subject = cert.Subject.CommonName
	}

	if subject == "" {
		return nil, ErrUntrustedCert
	}

	// Tenant extraction
	var tenant string
	if m.tenantExtractor != nil {
		tenant = m.tenantExtractor(cert)
	} else if spiffeURI != nil {
		// Extract namespace from spiffe://<domain>/ns/<namespace>/...
		pathSegments := strings.Split(strings.Trim(spiffeURI.Path, "/"), "/")
		for i, seg := range pathSegments {
			if seg == "ns" && i+1 < len(pathSegments) {
				tenant = pathSegments[i+1]
				break
			}
		}
	}
	if tenant == "" && len(cert.Subject.Organization) > 0 {
		tenant = cert.Subject.Organization[0]
	}

	ident := NewIdentity(subject, tenant, "mtls")

	// Groups from OrganizationalUnit
	if len(cert.Subject.OrganizationalUnit) > 0 {
		ident.Groups = append(ident.Groups, cert.Subject.OrganizationalUnit...)
	}

	// Certificate claims
	ident.Claims["cert_serial"] = cert.SerialNumber.String()
	ident.Claims["cert_issuer"] = cert.Issuer.CommonName
	if len(cert.URIs) > 0 {
		uris := make([]string, 0, len(cert.URIs))
		for _, u := range cert.URIs {
			uris = append(uris, u.String())
		}
		ident.Claims["san_uris"] = uris
	}
	if len(cert.DNSNames) > 0 {
		ident.Claims["san_dns"] = cert.DNSNames
	}
	if cert.Subject.CommonName != "" {
		ident.Claims["cert_cn"] = cert.Subject.CommonName
	}

	return ident, nil
}
