package security_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/authn"
)

func createTestCert(t *testing.T, uris []*url.URL, dnsNames, emails []string, cn, org, ou string) *x509.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{org},
			OrganizationalUnit: []string{ou},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  uris,
		DNSNames:              dnsNames,
		EmailAddresses:        emails,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

func TestMTLSProvider_SPIFFEURI(t *testing.T) {
	spiffeURL, _ := url.Parse("spiffe://cluster.local/ns/payments/sa/processor")
	cert := createTestCert(t, []*url.URL{spiffeURL}, nil, nil, "processor-svc", "AcmeCorp", "Engineering")

	provider := authn.NewMTLSProvider(authn.MTLSProviderConfig{
		RequireClientCert: true,
	})

	env := pipeline.GetEnvelope("req-mtls-1", pipeline.PhaseAuthn, "POST", "/v1/charges", nil, nil)
	env.PeerInfo.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	ident, err := provider.Authenticate(context.Background(), env)
	if err != nil {
		t.Fatalf("expected successful mTLS authentication, got: %v", err)
	}

	if ident.Subject != "spiffe://cluster.local/ns/payments/sa/processor" {
		t.Errorf("expected SPIFFE URI subject, got %s", ident.Subject)
	}
	if ident.Tenant != "payments" {
		t.Errorf("expected tenant extracted as payments, got %s", ident.Tenant)
	}
	if !ident.InGroup("Engineering") {
		t.Errorf("expected group Engineering")
	}
	if ident.AuthMethod != "mtls" {
		t.Errorf("expected auth_method mtls, got %s", ident.AuthMethod)
	}
}

func TestMTLSProvider_Fallbacks(t *testing.T) {
	t.Run("DNS SAN fallback", func(t *testing.T) {
		cert := createTestCert(t, nil, []string{"client.internal.company.com"}, nil, "fallback-cn", "Acme", "Ops")
		provider := authn.NewMTLSProvider(authn.MTLSProviderConfig{RequireClientCert: true})

		ident, err := provider.ExtractIdentity(cert)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ident.Subject != "client.internal.company.com" {
			t.Errorf("expected DNS SAN subject, got %s", ident.Subject)
		}
		if ident.Tenant != "Acme" {
			t.Errorf("expected tenant Acme from Organization, got %s", ident.Tenant)
		}
	})

	t.Run("Email SAN fallback", func(t *testing.T) {
		cert := createTestCert(t, nil, nil, []string{"agent@company.com"}, "agent-cn", "Acme", "")
		provider := authn.NewMTLSProvider(authn.MTLSProviderConfig{RequireClientCert: true})

		ident, err := provider.ExtractIdentity(cert)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ident.Subject != "agent@company.com" {
			t.Errorf("expected Email SAN subject, got %s", ident.Subject)
		}
	})

	t.Run("Common Name fallback", func(t *testing.T) {
		cert := createTestCert(t, nil, nil, nil, "service-gateway-node-1", "ToranaCorp", "")
		provider := authn.NewMTLSProvider(authn.MTLSProviderConfig{RequireClientCert: true})

		ident, err := provider.ExtractIdentity(cert)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ident.Subject != "service-gateway-node-1" {
			t.Errorf("expected CN subject, got %s", ident.Subject)
		}
	})
}

func TestMTLSProvider_MissingCert(t *testing.T) {
	t.Run("require cert fails closed", func(t *testing.T) {
		provider := authn.NewMTLSProvider(authn.MTLSProviderConfig{
			RequireClientCert: true,
		})
		env := pipeline.GetEnvelope("req-no-cert", pipeline.PhaseAuthn, "GET", "/test", nil, nil)
		// TLS is nil
		_, err := provider.Authenticate(context.Background(), env)
		if !errors.Is(err, authn.ErrUntrustedCert) {
			t.Errorf("expected ErrUntrustedCert, got: %v", err)
		}
	})

	t.Run("optional cert returns ErrNoCredentials", func(t *testing.T) {
		provider := authn.NewMTLSProvider(authn.MTLSProviderConfig{
			RequireClientCert: false,
		})
		env := pipeline.GetEnvelope("req-no-cert", pipeline.PhaseAuthn, "GET", "/test", nil, nil)
		_, err := provider.Authenticate(context.Background(), env)
		if !errors.Is(err, authn.ErrNoCredentials) {
			t.Errorf("expected ErrNoCredentials, got: %v", err)
		}
	})
}
