package plugins_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	pluginv1 "github.com/phaselume/torana/api/proto/plugin/v1"
	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/egress"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/plugins/process"
	"github.com/phaselume/torana/internal/plugins/wasm"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// TestHelperProcess runs as a child mock plugin process when GO_WANT_HELPER_PROCESS=1.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	socketPath := os.Getenv("TORANA_PLUGIN_SOCKET")
	if socketPath == "" {
		os.Exit(2)
	}

	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		os.Exit(3)
	}
	defer os.Remove(socketPath)

	server := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(server, &mockHelperPluginServer{})

	if err := server.Serve(listener); err != nil {
		os.Exit(4)
	}
	os.Exit(0)
}

type mockHelperPluginServer struct {
	pluginv1.UnimplementedPluginServiceServer
}

func (s *mockHelperPluginServer) Handshake(_ context.Context, req *pluginv1.HandshakeRequest) (*pluginv1.HandshakeResponse, error) {
	return &pluginv1.HandshakeResponse{Accepted: true}, nil
}

func (s *mockHelperPluginServer) Describe(_ context.Context, _ *pluginv1.DescribeRequest) (*pluginv1.DescribeResponse, error) {
	return &pluginv1.DescribeResponse{
		Name:     "mock-helper-plugin",
		Version:  "1.0.0",
		Phase:    pluginv1.Phase_PHASE_REQUEST_HEADERS,
		BodyMode: pluginv1.BodyMode_BODY_MODE_BUFFERED,
	}, nil
}

func (s *mockHelperPluginServer) OnRequest(_ context.Context, env *pluginv1.Envelope) (*pluginv1.Decision, error) {
	// Crash simulation
	if env.Headers["x-test-crash"] == "1" || env.Headers["X-Test-Crash"] == "1" {
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
		os.Exit(1)
	}

	// Hang simulation
	if env.Headers["x-test-hang"] == "1" || env.Headers["X-Test-Hang"] == "1" {
		time.Sleep(5 * time.Second)
	}

	return &pluginv1.Decision{
		Action:     pluginv1.Action_ACTION_MUTATE,
		StatusCode: 200,
		MutateHeaders: map[string]string{
			"X-Processed-By": "Torana-Process-Plugin/1.0",
		},
		MutateBody: []byte(`{"status":"mock_processed"}`),
	}, nil
}

func (s *mockHelperPluginServer) OnChunk(stream pluginv1.PluginService_OnChunkServer) error {
	for {
		chunkEnv, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := stream.Send(&pluginv1.ChunkDecision{
			Action:           pluginv1.Action_ACTION_CONTINUE,
			TransformedChunk: chunkEnv.Chunk,
		}); err != nil {
			return err
		}
	}
}

func computeSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Helper: generate test TLS credentials for remote mTLS testing
func generateRemoteTLSCredentials() (serverTLS *tls.Config, clientTLS *process.TLSConfig, cleanup func()) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "remote-plugin.internal",
			Organization: []string{"Torana Plugin"},
		},
		DNSNames:    []string{"remote-plugin.internal", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(privKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(certPEM)

	serverTLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}

	clientTLS = &process.TLSConfig{
		CertPEM:    string(certPEM),
		KeyPEM:     string(keyPEM),
		CAPEM:      string(certPEM),
		ServerName: "localhost",
	}

	return serverTLS, clientTLS, func() {}
}

// Test 1: Standard Local Process Plugin Execution over Unix Domain Socket
func TestLocalProcessPlugin_StandardExecution(t *testing.T) {
	selfExec, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get executable path: %v", err)
	}

	checksum, err := computeSHA256(selfExec)
	if err != nil {
		t.Fatalf("failed to compute checksum: %v", err)
	}

	manifest := process.DefaultManifest("helper-plugin", process.TierLocalProcess)
	manifest.BinaryPath = selfExec
	manifest.SHA256Checksum = checksum
	manifest.Args = []string{"-test.run=TestHelperProcess", "--"}
	manifest.Env = map[string]string{"GO_WANT_HELPER_PROCESS": "1"}

	mgr := process.NewProcessPluginManager(nil)
	defer mgr.Close()

	filter, err := mgr.RegisterPlugin(manifest)
	if err != nil {
		t.Fatalf("failed to register process plugin: %v", err)
	}
	defer filter.Close()

	headers := make(http.Header)
	headers.Set("X-Original-Header", "value1")
	env := pipeline.GetEnvelope("req-test-1", pipeline.PhaseRequestHeaders, "POST", "/api/v1", headers, nil)
	defer pipeline.PutEnvelope(env)

	decision, err := filter.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("process filter returned unexpected error: %v", err)
	}

	if decision.Action != pipeline.ActionMutate {
		t.Errorf("expected mutate action, got %v", decision.Action)
	}
	if decision.MutateHeaders["X-Processed-By"] != "Torana-Process-Plugin/1.0" {
		t.Errorf("expected mutated header, got %v", decision.MutateHeaders)
	}
}

// Test 2: Platform Security Verification (Checksum Mismatch & Path Allowlisting)
func TestPlatformSecurity_ChecksumAndPathValidation(t *testing.T) {
	selfExec, _ := os.Executable()

	// 1. Checksum Mismatch Test
	mWrongChecksum := process.DefaultManifest("tampered-plugin", process.TierLocalProcess)
	mWrongChecksum.BinaryPath = selfExec
	mWrongChecksum.SHA256Checksum = "0000000000000000000000000000000000000000000000000000000000000000" // fake checksum!

	mgr := process.NewProcessPluginManager(nil)
	defer mgr.Close()

	_, err := mgr.RegisterPlugin(mWrongChecksum)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("expected checksum mismatch error, got: %v", err)
	}

	// 2. Disallowed Binary Path Test
	mDisallowedPath := process.DefaultManifest("disallowed-path-plugin", process.TierLocalProcess)
	mDisallowedPath.BinaryPath = selfExec
	mDisallowedPath.AllowedBinaryDirs = []string{"/opt/torana/strictly_allowed_plugins_only"} // selfExec is not in here!

	_, err = mgr.RegisterPlugin(mDisallowedPath)
	if err == nil || !strings.Contains(err.Error(), "not in allowed directories") {
		t.Errorf("expected disallowed binary path error, got: %v", err)
	}
}

// Test 3: Remote Tier via gRPC with mTLS
func TestRemoteTier_mTLS(t *testing.T) {
	serverTLS, clientTLS, cleanup := generateRemoteTLSCredentials()
	defer cleanup()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on tcp: %v", err)
	}
	defer listener.Close()

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	pluginv1.RegisterPluginServiceServer(grpcServer, &mockHelperPluginServer{})
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	manifest := process.DefaultManifest("remote-plugin", process.TierRemote)
	manifest.RemoteEndpoint = listener.Addr().String()
	manifest.TLS = clientTLS

	mgr := process.NewProcessPluginManager(nil)
	defer mgr.Close()

	filter, err := mgr.RegisterPlugin(manifest)
	if err != nil {
		t.Fatalf("failed to register remote plugin: %v", err)
	}
	defer filter.Close()

	env := pipeline.GetEnvelope("req-remote", pipeline.PhaseRequestHeaders, "GET", "/remote", nil, nil)
	defer pipeline.PutEnvelope(env)

	decision, err := filter.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("remote plugin call failed: %v", err)
	}

	if decision.Action != pipeline.ActionMutate {
		t.Errorf("expected mutate, got %v", decision.Action)
	}
}

// Test 4: Child Process Crash & Supervisor Auto-Restart
func TestChildProcess_CrashAndAutoRestart(t *testing.T) {
	selfExec, _ := os.Executable()
	checksum, _ := computeSHA256(selfExec)

	manifest := process.DefaultManifest("crash-plugin", process.TierLocalProcess)
	manifest.BinaryPath = selfExec
	manifest.SHA256Checksum = checksum
	manifest.Args = []string{"-test.run=TestHelperProcess", "--"}
	manifest.Env = map[string]string{"GO_WANT_HELPER_PROCESS": "1"}
	manifest.RestartBackoff = 30 * time.Millisecond
	manifest.MaxRestartAttempts = 3

	mgr := process.NewProcessPluginManager(nil)
	defer mgr.Close()

	filter, err := mgr.RegisterPlugin(manifest)
	if err != nil {
		t.Fatalf("failed to register plugin: %v", err)
	}
	defer filter.Close()

	// 1. Send request triggering crash
	crashHeaders := make(http.Header)
	crashHeaders.Set("X-Test-Crash", "1")
	envCrash := pipeline.GetEnvelope("req-crash", pipeline.PhaseRequestHeaders, "POST", "/crash", crashHeaders, nil)
	_, _ = filter.Process(context.Background(), envCrash)
	pipeline.PutEnvelope(envCrash)

	// 2. Wait for supervisor auto-restart
	time.Sleep(300 * time.Millisecond)

	// 3. Subsequent request should succeed after restart
	okHeaders := make(http.Header)
	envOK := pipeline.GetEnvelope("req-after-restart", pipeline.PhaseRequestHeaders, "POST", "/ok", okHeaders, nil)
	dec, err := filter.Process(context.Background(), envOK)
	pipeline.PutEnvelope(envOK)

	if err != nil || dec.Action != pipeline.ActionMutate {
		t.Errorf("expected recovery after restart, got err=%v, dec=%v", err, dec)
	}
}

// Test 5: Child Process Hang & Per-Call Timeout
func TestChildProcess_HangAndTimeout(t *testing.T) {
	selfExec, _ := os.Executable()
	checksum, _ := computeSHA256(selfExec)

	manifest := process.DefaultManifest("hang-plugin", process.TierLocalProcess)
	manifest.BinaryPath = selfExec
	manifest.SHA256Checksum = checksum
	manifest.Args = []string{"-test.run=TestHelperProcess", "--"}
	manifest.Env = map[string]string{"GO_WANT_HELPER_PROCESS": "1"}
	manifest.Timeout = 100 * time.Millisecond // 100ms timeout
	manifest.FailurePolicy = pipeline.FailurePolicyFailClosed

	mgr := process.NewProcessPluginManager(nil)
	defer mgr.Close()

	filter, err := mgr.RegisterPlugin(manifest)
	if err != nil {
		t.Fatalf("failed to register plugin: %v", err)
	}
	defer filter.Close()

	hangHeaders := make(http.Header)
	hangHeaders.Set("X-Test-Hang", "1")
	envHang := pipeline.GetEnvelope("req-hang", pipeline.PhaseRequestHeaders, "POST", "/hang", hangHeaders, nil)
	defer pipeline.PutEnvelope(envHang)

	start := time.Now()
	decision, err := filter.Process(context.Background(), envHang)
	duration := time.Since(start)

	if err == nil {
		t.Fatalf("expected timeout error on hang, got nil (dec: %v)", decision)
	}
	if decision.Action != pipeline.ActionHalt || decision.StatusCode != 504 {
		t.Errorf("expected 504 Gateway Timeout, got action=%v status=%d", decision.Action, decision.StatusCode)
	}
	if duration > 500*time.Millisecond {
		t.Errorf("call took %v, expected under 500ms", duration)
	}
}

// Test 6: Slow Plugin & Circuit Breaker Tripping
func TestSlowPlugin_CircuitBreakerTripping(t *testing.T) {
	selfExec, _ := os.Executable()
	checksum, _ := computeSHA256(selfExec)

	manifest := process.DefaultManifest("slow-plugin", process.TierLocalProcess)
	manifest.BinaryPath = selfExec
	manifest.SHA256Checksum = checksum
	manifest.Args = []string{"-test.run=TestHelperProcess", "--"}
	manifest.Env = map[string]string{"GO_WANT_HELPER_PROCESS": "1"}
	manifest.Timeout = 50 * time.Millisecond
	manifest.CircuitBreakerThreshold = 2 // Trips after 2 failures!
	manifest.CircuitBreakerCooldown = 5 * time.Second
	manifest.FailurePolicy = pipeline.FailurePolicyFailClosed

	mgr := process.NewProcessPluginManager(nil)
	defer mgr.Close()

	filter, err := mgr.RegisterPlugin(manifest)
	if err != nil {
		t.Fatalf("failed to register plugin: %v", err)
	}
	defer filter.Close()

	hangHeaders := make(http.Header)
	hangHeaders.Set("X-Test-Hang", "1")

	// Trigger 2 consecutive timeouts to trip circuit breaker
	for i := 0; i < 2; i++ {
		env := pipeline.GetEnvelope(fmt.Sprintf("req-cb-%d", i), pipeline.PhaseRequestHeaders, "POST", "/hang", hangHeaders, nil)
		_, _ = filter.Process(context.Background(), env)
		pipeline.PutEnvelope(env)
	}

	// 3rd request should fail fast with 503 Circuit Open without waiting for timeout
	start := time.Now()
	envFast := pipeline.GetEnvelope("req-circuit-open", pipeline.PhaseRequestHeaders, "POST", "/fast", nil, nil)
	dec, err := filter.Process(context.Background(), envFast)
	pipeline.PutEnvelope(envFast)
	duration := time.Since(start)

	if err == nil || dec.StatusCode != 503 {
		t.Errorf("expected 503 Circuit Open, got status=%d, err=%v", dec.StatusCode, err)
	}
	if duration > 20*time.Millisecond {
		t.Errorf("circuit breaker did not fail fast, took %v", duration)
	}
}

// Test 7: Failure Policy (Fail Open vs Fail Closed)
func TestFailurePolicy_FailOpenVsFailClosed(t *testing.T) {
	selfExec, _ := os.Executable()
	checksum, _ := computeSHA256(selfExec)

	// 1. Fail Closed (halts pipeline)
	mClosed := process.DefaultManifest("fail-closed", process.TierLocalProcess)
	mClosed.BinaryPath = selfExec
	mClosed.SHA256Checksum = checksum
	mClosed.Args = []string{"-test.run=TestHelperProcess", "--"}
	mClosed.Env = map[string]string{"GO_WANT_HELPER_PROCESS": "1"}
	mClosed.Timeout = 50 * time.Millisecond
	mClosed.FailurePolicy = pipeline.FailurePolicyFailClosed

	mgr := process.NewProcessPluginManager(nil)
	defer mgr.Close()

	fClosed, err := mgr.RegisterPlugin(mClosed)
	if err != nil {
		t.Fatalf("failed to register fClosed: %v", err)
	}
	defer fClosed.Close()

	hangHeaders := make(http.Header)
	hangHeaders.Set("X-Test-Hang", "1")
	envClosed := pipeline.GetEnvelope("req-fc", pipeline.PhaseRequestHeaders, "POST", "/", hangHeaders, nil)
	decClosed, errClosed := fClosed.Process(context.Background(), envClosed)
	pipeline.PutEnvelope(envClosed)

	if errClosed == nil || decClosed.Action != pipeline.ActionHalt {
		t.Errorf("expected fail-closed halt, got %v (err: %v)", decClosed, errClosed)
	}

	// 2. Fail Open (continues pipeline despite timeout)
	mOpen := process.DefaultManifest("fail-open", process.TierLocalProcess)
	mOpen.BinaryPath = selfExec
	mOpen.SHA256Checksum = checksum
	mOpen.Args = []string{"-test.run=TestHelperProcess", "--"}
	mOpen.Env = map[string]string{"GO_WANT_HELPER_PROCESS": "1"}
	mOpen.Timeout = 50 * time.Millisecond
	mOpen.FailurePolicy = pipeline.FailurePolicyFailOpen

	fOpen, err := mgr.RegisterPlugin(mOpen)
	if err != nil {
		t.Fatalf("failed to register fOpen: %v", err)
	}
	defer fOpen.Close()

	envOpen := pipeline.GetEnvelope("req-fo", pipeline.PhaseRequestHeaders, "POST", "/", hangHeaders, nil)
	decOpen, errOpen := fOpen.Process(context.Background(), envOpen)
	pipeline.PutEnvelope(envOpen)

	if errOpen != nil || decOpen.Action != pipeline.ActionContinue {
		t.Errorf("expected fail-open continue, got action=%v (err: %v)", decOpen.Action, errOpen)
	}
}

// Test 8: Egress Connector Client Interface Execution
func TestEgressConnector_Execution(t *testing.T) {
	selfExec, _ := os.Executable()
	checksum, _ := computeSHA256(selfExec)

	manifest := process.DefaultManifest("egress-conn", process.TierLocalProcess)
	manifest.Kind = process.KindEgress
	manifest.BinaryPath = selfExec
	manifest.SHA256Checksum = checksum
	manifest.Args = []string{"-test.run=TestHelperProcess", "--"}
	manifest.Env = map[string]string{"GO_WANT_HELPER_PROCESS": "1"}

	mgr := process.NewProcessPluginManager(nil)
	defer mgr.Close()

	connector, err := mgr.RegisterEgress(manifest)
	if err != nil {
		t.Fatalf("failed to register egress connector: %v", err)
	}
	defer connector.Close()

	req := &egress.Request{
		Method:  "POST",
		Path:    "/v1/models/predict",
		Headers: http.Header{"Authorization": []string{"Bearer token"}},
		Body:    strings.NewReader(`{"input":"hello egress"}`),
		Timeout: 2 * time.Second,
	}

	cluster := &config.UpstreamCluster{
		ID:       "mock-egress-cluster",
		Protocol: "mock-egress",
	}

	resp, err := connector.Execute(context.Background(), cluster, req)
	if err != nil {
		t.Fatalf("egress connector Execute failed: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(bodyBytes), "mock_processed") {
		t.Errorf("unexpected egress response: code=%d, body=%s", resp.StatusCode, string(bodyBytes))
	}
}

// Test 9: Wasm Plugins Allowed to Trigger Logs
func TestWasmPlugin_LoggingTriggered(t *testing.T) {
	// Build minimal Wasm module that calls torana:host.log
	b := NewWasmBuilder()
	typeAlloc := b.AddType([]byte{0x7F}, []byte{0x7F})
	typeProcess := b.AddType([]byte{0x7F, 0x7F}, []byte{0x7E})
	typeLog := b.AddType([]byte{0x7F, 0x7F, 0x7F}, nil) // log(level, msg_ptr, msg_len)

	impLog := b.AddImport("torana:host", "log", typeLog)
	b.AddMemory(1, nil)

	logMsg := []byte("wasm plugin audit message triggered")
	b.AddDataSegment(1024, logMsg)

	// alloc(size) -> 2048
	funcAlloc := b.AddFunction(typeAlloc, []byte{0x41, 0x80, 0x10})
	b.AddExport("alloc", 0, funcAlloc)

	// process: calls log(2, 1024, len(logMsg)) -> returns continue
	var procCode []byte
	procCode = append(procCode, 0x41, 0x02)                   // level 2 (Info)
	procCode = append(procCode, 0x41, 0x80, 0x08)             // i32.const 1024
	procCode = append(procCode, 0x41, byte(len(logMsg)))      // len
	procCode = append(procCode, 0x10, byte(impLog))           // call log

	// return continue (3000 << 32 | len)
	respBytes := []byte(`{"action":0,"status_code":200}`)
	b.AddDataSegment(3000, respBytes)
	packed := (uint64(3000) << 32) | uint64(len(respBytes))
	procCode = append(procCode, 0x42)
	procCode = append(procCode, encodeIleb128(int64(packed))...)

	funcProcess := b.AddFunction(typeProcess, procCode)
	b.AddExport("process", 0, funcProcess)

	wasmBytes := b.Build()

	manifest := wasm.DefaultManifest("wasm-logging-test", "1.0.0")
	manifest.Capabilities.Log.Allowed = true

	pool, err := wasm.NewInstancePool(context.Background(), wasmBytes, manifest, nil)
	if err != nil {
		t.Fatalf("failed to create pool for logging test: %v", err)
	}
	defer pool.Close(context.Background())

	filter := wasm.NewWasmFilter(manifest, pool, nil)
	defer filter.Close()

	env := pipeline.GetEnvelope("req-wasm-log", pipeline.PhaseRequestHeaders, "GET", "/test", nil, nil)
	defer pipeline.PutEnvelope(env)

	decision, err := filter.Process(context.Background(), env)
	if err != nil || decision.Action != pipeline.ActionContinue {
		t.Errorf("wasm logging test failed: %v, dec=%v", err, decision)
	}
}
