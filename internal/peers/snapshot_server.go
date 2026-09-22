package peers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// SnapshotServer serves signed configuration snapshots to peers over mTLS.
type SnapshotServer struct {
	cfg      Config
	listener net.Listener
	server   *http.Server
	addr     string
	mu       sync.RWMutex
}

// NewSnapshotServer initializes and starts the HTTPS/mTLS snapshot server.
func NewSnapshotServer(cfg Config) (*SnapshotServer, error) {
	tlsConfig, err := PeerTLSConfig(cfg.TLSCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to create peer mTLS config: %w", err)
	}

	bindAddr := cfg.BindAddr
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	listenAddr := fmt.Sprintf("%s:%d", bindAddr, cfg.PeerServicePort)

	var listener net.Listener
	for attempts := 0; attempts < 5; attempts++ {
		listener, err = net.Listen("tcp", listenAddr)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s for snapshot server: %w", listenAddr, err)
	}

	actualAddr := listener.Addr().String()

	mux := http.NewServeMux()
	s := &SnapshotServer{
		cfg:      cfg,
		listener: listener,
		addr:     actualAddr,
	}

	mux.HandleFunc("/peer/snapshot", s.handleSnapshot)

	tlsListener := tls.NewListener(listener, tlsConfig)

	s.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		_ = s.server.Serve(tlsListener)
	}()

	return s, nil
}

// Addr returns the network address the snapshot server is listening on.
func (s *SnapshotServer) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.addr
}

func (s *SnapshotServer) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.cfg.SnapshotProvider == nil {
		http.Error(w, ErrNoActiveSnapshot.Error(), http.StatusServiceUnavailable)
		return
	}

	snap, version := s.cfg.SnapshotProvider.GetActiveSnapshot()
	if snap == nil || version == 0 {
		http.Error(w, ErrNoActiveSnapshot.Error(), http.StatusNotFound)
		return
	}

	data, err := protojson.Marshal(snap)
	if err != nil {
		http.Error(w, "failed to marshal snapshot: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// Close gracefully stops the snapshot server.
func (s *SnapshotServer) Close() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}

// FetchPeerSnapshot connects via mTLS to a peer and downloads its active configuration snapshot.
func FetchPeerSnapshot(ctx context.Context, peerAddr string, cert *tls.Certificate) (*controlplanev1.Snapshot, error) {
	tlsConfig, err := PeerTLSConfig(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to create client peer mTLS config: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ResponseHeaderTimeout: 5 * time.Second,
		DialContext: (&net.Dialer{
			Timeout: 3 * time.Second,
		}).DialContext,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
	}

	url := fmt.Sprintf("https://%s/peer/snapshot", peerAddr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPeerFetchFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("%w: status %d: %s", ErrPeerFetchFailed, resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024)) // 32MB max
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot response body: %w", err)
	}

	var snap controlplanev1.Snapshot
	if err := protojson.Unmarshal(body, &snap); err != nil {
		return nil, fmt.Errorf("failed to parse peer snapshot: %w", err)
	}

	return &snap, nil
}

// PeerTLSConfig returns a tls.Config configured for peer-to-peer mTLS using the enrolled certificate.
func PeerTLSConfig(cert *tls.Certificate) (*tls.Config, error) {
	var certs []tls.Certificate
	if cert != nil {
		certs = append(certs, *cert)
	}

	return &tls.Config{
		Certificates: certs,
		ClientAuth:   tls.RequireAnyClientCert,
		// InsecureSkipVerify allows custom verification of peer certificates without external public CA.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("peer did not present a TLS certificate")
			}
			parsed, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse peer certificate: %w", err)
			}
			now := time.Now()
			if now.Before(parsed.NotBefore) || now.After(parsed.NotAfter) {
				return errors.New("peer TLS certificate has expired or is not yet valid")
			}
			// Verify Torana Gateway organization
			if len(parsed.Subject.Organization) == 0 || parsed.Subject.Organization[0] != "Torana Gateway" {
				return errors.New("peer TLS certificate organization is not Torana Gateway")
			}
			return nil
		},
	}, nil
}
