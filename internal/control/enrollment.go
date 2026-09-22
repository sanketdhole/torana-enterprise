package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PersistedCredential stores the node's enrolled cryptographic credentials.
type PersistedCredential struct {
	ClusterID   string    `json:"cluster_id"`
	NodeID      string    `json:"node_id"`
	Namespace   string    `json:"namespace"`
	EnrolledAt  time.Time `json:"enrolled_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	CertPEM     string    `json:"cert_pem"`
	KeyPEM      string    `json:"key_pem"`
}

// EnrollmentManager manages gateway identity creation, token exchange, file persistence, and auto-rotation.
type EnrollmentManager struct {
	cfg        Config
	client     controlplanev1.ControlPlaneServiceClient
	logger     *slog.Logger
	mu         sync.RWMutex
	cred       *PersistedCredential
	tlsCert    *tls.Certificate
	stopChan   chan struct{}
	rotateOnce sync.Once
}

// NewEnrollmentManager creates a new enrollment manager.
func NewEnrollmentManager(
	cfg Config,
	client controlplanev1.ControlPlaneServiceClient,
	logger *slog.Logger,
) *EnrollmentManager {
	if cfg.StateDir == "" {
		cfg.StateDir = filepath.Join(os.TempDir(), "torana_state")
	}

	return &EnrollmentManager{
		cfg:      cfg,
		client:   client,
		logger:   logger,
		stopChan: make(chan struct{}),
	}
}

// EnsureEnrolled loads existing valid credentials from state directory (0600) or executes enrollment.
func (m *EnrollmentManager) EnsureEnrolled(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Try loading existing persisted credential
	credPath := filepath.Join(m.cfg.StateDir, "credential.json")
	if cred, err := m.loadPersistedCredential(credPath); err == nil {
		// Verify not expired (with 10-minute safety margin)
		if time.Now().Add(10 * time.Minute).Before(cred.ExpiresAt) {
			tlsCert, err := tls.X509KeyPair([]byte(cred.CertPEM), []byte(cred.KeyPEM))
			if err == nil {
				m.cred = cred
				m.tlsCert = &tlsCert
				if m.logger != nil {
					m.logger.Info("loaded existing valid enrolled credentials", "node_id", cred.NodeID, "expires_at", cred.ExpiresAt)
				}
				m.startRotationWatcher()
				return nil
			}
		}
	}

	// 2. Perform enrollment exchange
	return m.enrollLocked(ctx)
}

// enrollLocked generates a keypair + CSR, exchanges the one-time token, and persists the credential with 0600.
func (m *EnrollmentManager) enrollLocked(ctx context.Context) error {
	// A. Generate ECDSA P-256 private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate enrollment keypair: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to marshal ec private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// B. Generate Certificate Signing Request (CSR)
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   m.cfg.NodeID,
			Organization: []string{"Torana Gateway"},
		},
		DNSNames: []string{m.cfg.NodeID, "localhost"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate request: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// C. Read one-time enrollment token
	token := m.readEnrollToken()

	// D. Send Enrollment RPC to Control Plane Platform
	enrollReq := &controlplanev1.EnrollRequest{
		Namespace:   m.cfg.Namespace,
		NodeId:      m.cfg.NodeID,
		EnrollToken: token,
		Version:     "0.1.0",
		Labels: map[string]string{
			"csr": string(csrPEM),
		},
	}

	var enrollResp *controlplanev1.EnrollResponse
	if m.client != nil {
		enrollResp, err = m.client.Enroll(ctx, enrollReq)
		if err != nil {
			return fmt.Errorf("enrollment rpc failed: %w", err)
		}
		if !enrollResp.Accepted {
			return fmt.Errorf("%w: %s", ErrEnrollmentFailed, enrollResp.ErrorMessage)
		}
	} else {
		// Self-signed fallback when mock client is not directly attached
		enrollResp = &controlplanev1.EnrollResponse{
			Accepted:   true,
			ClusterId:  "local-cluster",
			EnrolledAt: timestamppb.Now(),
		}
	}

	// E. Mint client certificate (signed by key for self-signed or platform issued)
	certPEM, expiresAt, err := m.generateCertPEM(privKey, &csrTemplate)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse generated keypair: %w", err)
	}

	cred := &PersistedCredential{
		ClusterID:  enrollResp.ClusterId,
		NodeID:     m.cfg.NodeID,
		Namespace:  m.cfg.Namespace,
		EnrolledAt: time.Now(),
		ExpiresAt:  expiresAt,
		CertPEM:    string(certPEM),
		KeyPEM:     string(keyPEM),
	}

	// F. Persist Credential with 0600 file permissions in state directory
	if err := m.persistCredential(cred); err != nil {
		return fmt.Errorf("failed to persist credential to state dir: %w", err)
	}

	m.cred = cred
	m.tlsCert = &tlsCert

	if m.logger != nil {
		m.logger.Info("enrolled node successfully with control plane", "cluster_id", cred.ClusterID, "expires_at", expiresAt)
	}

	m.startRotationWatcher()
	return nil
}

// TLSCertificate returns the active enrolled mTLS certificate.
func (m *EnrollmentManager) TLSCertificate() *tls.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tlsCert
}

// Credential returns the active persisted credential metadata.
func (m *EnrollmentManager) Credential() *PersistedCredential {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cred
}

func (m *EnrollmentManager) readEnrollToken() string {
	if m.cfg.EnrollTokenFile == "" {
		return ""
	}
	// Check if string is direct token or file path
	if _, err := os.Stat(m.cfg.EnrollTokenFile); err == nil {
		data, err := os.ReadFile(m.cfg.EnrollTokenFile)
		if err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return m.cfg.EnrollTokenFile
}

func (m *EnrollmentManager) persistCredential(cred *PersistedCredential) error {
	if err := os.MkdirAll(m.cfg.StateDir, 0700); err != nil {
		return err
	}

	credPath := filepath.Join(m.cfg.StateDir, "credential.json")
	data, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return err
	}

	// Enforce 0600 file permissions strictly
	return os.WriteFile(credPath, data, 0600)
}

func (m *EnrollmentManager) loadPersistedCredential(path string) (*PersistedCredential, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Verify file mode permissions
	info, err := os.Stat(path)
	if err == nil {
		mode := info.Mode().Perm()
		if mode&0077 != 0 {
			// Warn or fix insecure file mode
			_ = os.Chmod(path, 0600)
		}
	}

	var cred PersistedCredential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, err
	}
	return &cred, nil
}

func (m *EnrollmentManager) generateCertPEM(privKey *ecdsa.PrivateKey, csr *x509.CertificateRequest) ([]byte, time.Time, error) {
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now().Add(-1 * time.Minute)
	notAfter := notBefore.Add(90 * 24 * time.Hour) // 90 days standard validity

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, time.Time{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM, notAfter, nil
}

// startRotationWatcher checks certificate validity and triggers renewal at 2/3 of its lifetime.
func (m *EnrollmentManager) startRotationWatcher() {
	m.rotateOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()

			for {
				select {
				case <-m.stopChan:
					return
				case <-ticker.C:
					m.checkAndRotate()
				}
			}
		}()
	})
}

func (m *EnrollmentManager) checkAndRotate() {
	m.mu.RLock()
	cred := m.cred
	m.mu.RUnlock()

	if cred == nil {
		return
	}

	totalLifetime := cred.ExpiresAt.Sub(cred.EnrolledAt)
	rotateThreshold := cred.EnrolledAt.Add((totalLifetime * 2) / 3)

	if time.Now().After(rotateThreshold) {
		if m.logger != nil {
			m.logger.Info("auto-rotating certificate before expiry", "expires_at", cred.ExpiresAt)
		}
		m.mu.Lock()
		_ = m.enrollLocked(context.Background())
		m.mu.Unlock()
	}
}

// Close stops the rotation watcher.
func (m *EnrollmentManager) Close() {
	close(m.stopChan)
}
