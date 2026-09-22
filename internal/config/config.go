package config

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	// ErrNilSnapshot is returned when attempting to store a nil snapshot.
	ErrNilSnapshot = errors.New("snapshot cannot be nil")
	// ErrNoSnapshotAvailable is returned when loading from an uninitialized holder.
	ErrNoSnapshotAvailable = errors.New("no active configuration snapshot available")
)

// CompileError represents a structured error returned when a snapshot fails validation or compilation.
type CompileError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *CompileError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// BootstrapConfig contains static configuration loaded once at process startup from flags/env.
type BootstrapConfig struct {
	Namespace          string
	PlatformURL        string
	EnrollTokenFile    string
	ListenHTTP         string
	ListenGRPC         string
	PeersDNS           string
	ConfigBundle       string
	LKGPath            string
	Environment        string
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	IdleTimeout        time.Duration
	DrainTimeout       time.Duration
	TelemetryQueueSize int
}

// LoadBootstrapConfig loads startup configuration from environment variables with defaults.
func LoadBootstrapConfig() *BootstrapConfig {
	readSec, _ := strconv.Atoi(getEnv("READ_TIMEOUT_SEC", "15"))
	writeSec, _ := strconv.Atoi(getEnv("WRITE_TIMEOUT_SEC", "15"))
	idleSec, _ := strconv.Atoi(getEnv("IDLE_TIMEOUT_SEC", "60"))
	drainSec, _ := strconv.Atoi(getEnv("DRAIN_TIMEOUT_SEC", "30"))
	queueSize, _ := strconv.Atoi(getEnv("TELEMETRY_QUEUE_SIZE", "10000"))

	listenHTTP := getEnv("LISTEN_HTTP", ":8080")
	if !strings.Contains(listenHTTP, ":") {
		listenHTTP = ":" + listenHTTP
	}

	listenGRPC := getEnv("LISTEN_GRPC", ":9090")
	if !strings.Contains(listenGRPC, ":") {
		listenGRPC = ":" + listenGRPC
	}

	defaultLKG := filepath.Join(os.TempDir(), "torana_lkg.json")

	return &BootstrapConfig{
		Namespace:          getEnv("GATEWAY_NAMESPACE", "default"),
		PlatformURL:        getEnv("PLATFORM_URL", ""),
		EnrollTokenFile:    getEnv("ENROLL_TOKEN_FILE", ""),
		ListenHTTP:         listenHTTP,
		ListenGRPC:         listenGRPC,
		PeersDNS:           getEnv("PEERS_DNS", ""),
		ConfigBundle:       getEnv("CONFIG_BUNDLE", ""),
		LKGPath:            getEnv("LKG_PATH", defaultLKG),
		Environment:        getEnv("ENV", "development"),
		ReadTimeout:        time.Duration(readSec) * time.Second,
		WriteTimeout:       time.Duration(writeSec) * time.Second,
		IdleTimeout:        time.Duration(idleSec) * time.Second,
		DrainTimeout:       time.Duration(drainSec) * time.Second,
		TelemetryQueueSize: queueSize,
	}
}

// ParseFlags parses command line arguments and populates a BootstrapConfig.
func ParseFlags(args []string) (*BootstrapConfig, bool, error) {
	fs := flag.NewFlagSet("gateway-data", flag.ContinueOnError)

	cfg := LoadBootstrapConfig()

	fs.StringVar(&cfg.Namespace, "namespace", cfg.Namespace, "Deployment namespace identity")
	fs.StringVar(&cfg.PlatformURL, "platform-url", cfg.PlatformURL, "Platform control plane gRPC service URL")
	fs.StringVar(&cfg.EnrollTokenFile, "enroll-token-file", cfg.EnrollTokenFile, "Path to node enrollment token file")
	fs.StringVar(&cfg.ListenHTTP, "listen-http", cfg.ListenHTTP, "HTTP ingress listen address (default :8080)")
	fs.StringVar(&cfg.ListenGRPC, "listen-grpc", cfg.ListenGRPC, "gRPC ingress listen address (default :9090)")
	fs.StringVar(&cfg.PeersDNS, "peers-dns", cfg.PeersDNS, "DNS SRV / headless service name for peer discovery")
	fs.StringVar(&cfg.ConfigBundle, "config-bundle", cfg.ConfigBundle, "Path to local static configuration bundle JSON file")

	showVersion := fs.Bool("version", false, "Print binary version and exit")

	if err := fs.Parse(args); err != nil {
		return nil, false, err
	}

	return cfg, *showVersion, nil
}

// HTTPAddress returns the listen address for the HTTP ingress.
func (b *BootstrapConfig) HTTPAddress() string {
	return b.ListenHTTP
}

// GRPCAddress returns the listen address for the gRPC ingress.
func (b *BootstrapConfig) GRPCAddress() string {
	return b.ListenGRPC
}

// SecretRef represents an indirect reference to a secret stored in a local vault/k8s secret.
// Plaintext secrets never appear in snapshots or logs.
type SecretRef struct {
	Name     string `json:"name"`
	Provider string `json:"provider"` // e.g. "env", "vault", "k8s"
	Key      string `json:"key"`
}

// PolicyRule defines an individual policy attached to a route.
type PolicyRule struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Type          string            `json:"type"` // e.g. "authn", "authz", "ratelimit", "cel"
	CELExpression string            `json:"cel_expression,omitempty"`
	Action        string            `json:"action"`
	Parameters    map[string]string `json:"parameters,omitempty"`
}

// WeightedUpstream represents a split traffic destination with weight.
type WeightedUpstream struct {
	UpstreamID string `json:"upstream_id"`
	Weight     int    `json:"weight"`
}

// RetryPolicy defines automatic retry configuration for upstream calls.
type RetryPolicy struct {
	MaxRetries          int           `json:"max_retries"`
	RetryOnStatusCodes  []int         `json:"retry_on_status_codes"`
	PerTryTimeout       time.Duration `json:"per_try_timeout"`
	Backoff             time.Duration `json:"backoff"`
}

// UpstreamCluster defines an egress backend target.
type UpstreamCluster struct {
	ID         string        `json:"id"`
	Protocol   string        `json:"protocol"` // "http", "grpc", "postgres", "llm", "mcp"
	Endpoints  []string      `json:"endpoints"`
	Timeout    time.Duration `json:"timeout"`
	MaxConns   int           `json:"max_conns"`
	SecretRefs []SecretRef   `json:"secret_refs,omitempty"`
}

// RouteRule defines multi-criteria matching and upstream destination.
type RouteRule struct {
	ID                string             `json:"id"`
	Host              string             `json:"host,omitempty"`
	Path              string             `json:"path"`
	PathPrefix        bool               `json:"path_prefix"`
	Method            string             `json:"method"`
	Headers           map[string]string  `json:"headers,omitempty"`
	Claims            map[string]string  `json:"claims,omitempty"`
	UpstreamID        string             `json:"upstream_id,omitempty"`
	WeightedUpstreams []WeightedUpstream `json:"weighted_upstreams,omitempty"`
	RetryPolicy       *RetryPolicy       `json:"retry_policy,omitempty"`
	Policies          []PolicyRule       `json:"policies,omitempty"`
	Timeout           time.Duration      `json:"timeout"`
}

// Snapshot is an immutable configuration snapshot received from the platform control plane.
type Snapshot struct {
	Version   uint64                     `json:"version"`
	Signature string                     `json:"signature,omitempty"`
	Timestamp time.Time                  `json:"timestamp"`
	Routes    []RouteRule                `json:"routes"`
	Upstreams map[string]UpstreamCluster `json:"upstreams"`
}

// Validate performs structural and integrity verification on a snapshot.
func (s *Snapshot) Validate() error {
	if s == nil {
		return &CompileError{Code: "ERR_NIL_SNAPSHOT", Message: "snapshot cannot be nil"}
	}
	if s.Version == 0 {
		return &CompileError{Code: "ERR_INVALID_VERSION", Message: "config_version must be greater than 0"}
	}
	for i, r := range s.Routes {
		if r.Path == "" {
			return &CompileError{
				Code:    "ERR_EMPTY_PATH",
				Message: fmt.Sprintf("route index %d (id: %s) has empty path", i, r.ID),
			}
		}
		if r.UpstreamID == "" && len(r.WeightedUpstreams) == 0 {
			return &CompileError{
				Code:    "ERR_NO_UPSTREAM",
				Message: fmt.Sprintf("route %s must have either upstream_id or weighted_upstreams defined", r.ID),
			}
		}
	}
	return nil
}

// LoadBundleFromFile reads and parses a static configuration bundle JSON file.
func LoadBundleFromFile(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config bundle %s: %w", path, err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("failed to parse config bundle: %w", err)
	}

	if snap.Timestamp.IsZero() {
		snap.Timestamp = time.Now()
	}

	return &snap, nil
}

// SaveLKG writes the Last-Known-Good snapshot to disk atomically using a temp file.
func SaveLKG(path string, snap *Snapshot) error {
	if path == "" || snap == nil {
		return nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create lkg directory: %w", err)
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal lkg snapshot: %w", err)
	}

	tmpFile := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write tmp lkg file: %w", err)
	}

	if err := os.Rename(tmpFile, path); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to atomic rename lkg file: %w", err)
	}

	return nil
}

// LoadLKG reads and parses the Last-Known-Good snapshot from disk.
func LoadLKG(path string) (*Snapshot, error) {
	if path == "" {
		return nil, errors.New("lkg path not specified")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read lkg file %s: %w", path, err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("failed to parse lkg file %s: %w", path, err)
	}

	return &snap, nil
}

// RouteFilterChain holds the configured policies and filters attached to a route.
type RouteFilterChain struct {
	RouteID  string       `json:"route_id"`
	Policies []PolicyRule `json:"policies"`
}

// CompiledRoute holds a pre-processed route rule with precompiled regexes and filter chains.
type CompiledRoute struct {
	Rule          *RouteRule
	PathSegments  []string
	PathRegex     *regexp.Regexp
	HostRegex     *regexp.Regexp
	HeaderRegexes map[string]*regexp.Regexp
	ClaimRegexes  map[string]*regexp.Regexp
	FilterChain   *RouteFilterChain
}

// RouteTrieNode represents a node in the route trie.
type RouteTrieNode struct {
	Segment       string
	IsPrefix      bool
	Routes        []*CompiledRoute
	Children      map[string]*RouteTrieNode
	WildcardChild *RouteTrieNode
}

// RouteTrie provides hierarchical path matching for route rules.
type RouteTrie struct {
	root *RouteTrieNode
}

// NewRouteTrie initializes an empty route trie.
func NewRouteTrie() *RouteTrie {
	return &RouteTrie{
		root: &RouteTrieNode{
			Children: make(map[string]*RouteTrieNode),
		},
	}
}

// Insert adds a compiled route to the trie.
func (t *RouteTrie) Insert(cr *CompiledRoute) {
	if t.root == nil {
		t.root = &RouteTrieNode{Children: make(map[string]*RouteTrieNode)}
	}

	cleanPath := strings.Trim(cr.Rule.Path, "/")
	var segments []string
	if cleanPath != "" {
		segments = strings.Split(cleanPath, "/")
	}
	cr.PathSegments = segments

	curr := t.root
	for _, seg := range segments {
		if seg == "*" || strings.HasPrefix(seg, "{") {
			if curr.WildcardChild == nil {
				curr.WildcardChild = &RouteTrieNode{
					Segment:  seg,
					Children: make(map[string]*RouteTrieNode),
				}
			}
			curr = curr.WildcardChild
		} else {
			child, exists := curr.Children[seg]
			if !exists {
				child = &RouteTrieNode{
					Segment:  seg,
					Children: make(map[string]*RouteTrieNode),
				}
				curr.Children[seg] = child
			}
			curr = child
		}
	}

	if cr.Rule.PathPrefix {
		curr.IsPrefix = true
	}
	curr.Routes = append(curr.Routes, cr)
}

// Match finds all matching routes in the trie for a given path.
func (t *RouteTrie) Match(path string) []*CompiledRoute {
	if t == nil || t.root == nil {
		return nil
	}

	cleanPath := strings.Trim(path, "/")
	var segments []string
	if cleanPath != "" {
		segments = strings.Split(cleanPath, "/")
	}

	var matched []*CompiledRoute
	curr := t.root

	// Check root-level prefix routes (e.g. "/")
	if curr.IsPrefix && len(curr.Routes) > 0 {
		matched = append(matched, curr.Routes...)
	}

	for i, seg := range segments {
		var next *RouteTrieNode
		if child, ok := curr.Children[seg]; ok {
			next = child
		} else if curr.WildcardChild != nil {
			next = curr.WildcardChild
		}

		if next == nil {
			break
		}
		curr = next

		// If intermediate node is a prefix route and matches
		if curr.IsPrefix && i < len(segments)-1 && len(curr.Routes) > 0 {
			matched = append(matched, curr.Routes...)
		}
	}

	if curr != nil && len(curr.Routes) > 0 {
		matched = append(matched, curr.Routes...)
	}

	return matched
}

// CompiledConfig holds the compiled, immutable runtime configuration structures.
type CompiledConfig struct {
	Snapshot     *Snapshot
	RouteTrie    *RouteTrie
	Routes       []*CompiledRoute
	RouteMap     map[string]*CompiledRoute
	Regexes      map[string]*regexp.Regexp
	FilterChains map[string]*RouteFilterChain
	Upstreams    map[string]*UpstreamCluster
}

// CompileSnapshot validates and compiles a Snapshot into its immutable runtime form.
func CompileSnapshot(s *Snapshot) (*CompiledConfig, error) {
	if s == nil {
		return nil, &CompileError{Code: "ERR_NIL_SNAPSHOT", Message: "snapshot cannot be nil"}
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}

	compiled := &CompiledConfig{
		Snapshot:     s,
		RouteTrie:    NewRouteTrie(),
		Routes:       make([]*CompiledRoute, 0, len(s.Routes)),
		RouteMap:     make(map[string]*CompiledRoute, len(s.Routes)),
		Regexes:      make(map[string]*regexp.Regexp),
		FilterChains: make(map[string]*RouteFilterChain, len(s.Routes)),
		Upstreams:    make(map[string]*UpstreamCluster, len(s.Upstreams)),
	}

	for id, u := range s.Upstreams {
		clusterCopy := u
		compiled.Upstreams[id] = &clusterCopy
	}

	for i := range s.Routes {
		r := &s.Routes[i]
		cr := &CompiledRoute{
			Rule:          r,
			HeaderRegexes: make(map[string]*regexp.Regexp),
			ClaimRegexes:  make(map[string]*regexp.Regexp),
		}

		// Compile path regex if applicable
		if strings.HasPrefix(r.Path, "^") || strings.Contains(r.Path, "(") {
			re, err := regexp.Compile(r.Path)
			if err != nil {
				return nil, &CompileError{
					Code:    "ERR_INVALID_PATH_REGEX",
					Message: fmt.Sprintf("invalid path regex for route %s: %s", r.ID, r.Path),
					Details: err.Error(),
				}
			}
			cr.PathRegex = re
			compiled.Regexes["path:"+r.ID] = re
		}

		// Compile host wildcard or regex
		if strings.HasPrefix(r.Host, "^") {
			re, err := regexp.Compile(r.Host)
			if err != nil {
				return nil, &CompileError{
					Code:    "ERR_INVALID_HOST_REGEX",
					Message: fmt.Sprintf("invalid host regex for route %s: %s", r.ID, r.Host),
					Details: err.Error(),
				}
			}
			cr.HostRegex = re
			compiled.Regexes["host:"+r.ID] = re
		}

		// Compile header matchers
		for k, v := range r.Headers {
			if strings.HasPrefix(v, "^") {
				re, err := regexp.Compile(v)
				if err != nil {
					return nil, &CompileError{
						Code:    "ERR_INVALID_HEADER_REGEX",
						Message: fmt.Sprintf("invalid header regex for route %s, header %s: %s", r.ID, k, v),
						Details: err.Error(),
					}
				}
				cr.HeaderRegexes[k] = re
				compiled.Regexes["header:"+r.ID+":"+k] = re
			}
		}

		// Compile claim matchers
		for k, v := range r.Claims {
			if strings.HasPrefix(v, "^") {
				re, err := regexp.Compile(v)
				if err != nil {
					return nil, &CompileError{
						Code:    "ERR_INVALID_CLAIM_REGEX",
						Message: fmt.Sprintf("invalid claim regex for route %s, claim %s: %s", r.ID, k, v),
						Details: err.Error(),
					}
				}
				cr.ClaimRegexes[k] = re
				compiled.Regexes["claim:"+r.ID+":"+k] = re
			}
		}

		// Compile per-route filter chains
		chain := &RouteFilterChain{
			RouteID:  r.ID,
			Policies: r.Policies,
		}
		cr.FilterChain = chain
		compiled.FilterChains[r.ID] = chain

		// Insert into route trie
		compiled.RouteTrie.Insert(cr)
		compiled.Routes = append(compiled.Routes, cr)
		compiled.RouteMap[r.ID] = cr
	}

	return compiled, nil
}

// SnapshotHolder provides lock-free atomic read/write access to the current Snapshot and compiled runtime form.
type SnapshotHolder struct {
	current  atomic.Pointer[Snapshot]
	compiled atomic.Pointer[CompiledConfig]
	lkgPath  atomic.Pointer[string]
}

// NewSnapshotHolder creates a new holder.
func NewSnapshotHolder() *SnapshotHolder {
	return &SnapshotHolder{}
}

// SetLKGPath sets the disk path for persisting Last-Known-Good snapshots.
func (h *SnapshotHolder) SetLKGPath(path string) {
	if path != "" {
		h.lkgPath.Store(&path)
	}
}

// Apply validates, compiles into runtime structures, and atomically swaps the active snapshot.
// It also persists the new snapshot to disk as Last-Known-Good if LKG path is set.
// On validation or compilation failure, returns a structured *CompileError (for NACK),
// leaving the previous active snapshot and runtime form completely untouched.
func (h *SnapshotHolder) Apply(s *Snapshot) error {
	if s == nil {
		return &CompileError{Code: "ERR_NIL_SNAPSHOT", Message: "snapshot cannot be nil"}
	}

	compiled, err := CompileSnapshot(s)
	if err != nil {
		return err
	}

	// Atomically swap both snapshot and compiled runtime form
	h.compiled.Store(compiled)
	h.current.Store(s)

	// Persist LKG to disk asynchronously/safely
	if p := h.lkgPath.Load(); p != nil && *p != "" {
		_ = SaveLKG(*p, s)
	}

	return nil
}

// Store atomically replaces the active snapshot.
func (h *SnapshotHolder) Store(s *Snapshot) error {
	if s == nil {
		return ErrNilSnapshot
	}
	if compiled, err := CompileSnapshot(s); err == nil {
		h.compiled.Store(compiled)
	}
	h.current.Store(s)
	return nil
}

// Load returns the active snapshot without any lock acquisition.
func (h *SnapshotHolder) Load() (*Snapshot, error) {
	s := h.current.Load()
	if s == nil {
		return nil, ErrNoSnapshotAvailable
	}
	return s, nil
}

// LoadCompiled returns the compiled runtime configuration without any lock acquisition.
func (h *SnapshotHolder) LoadCompiled() (*CompiledConfig, error) {
	c := h.compiled.Load()
	if c == nil {
		return nil, ErrNoSnapshotAvailable
	}
	return c, nil
}

// HasSnapshot returns true if a valid snapshot has been loaded.
func (h *SnapshotHolder) HasSnapshot() bool {
	return h.current.Load() != nil
}

// LoadStartupLKG loads the Last-Known-Good snapshot from disk at startup if the platform is unreachable.
func (h *SnapshotHolder) LoadStartupLKG(path string) (*Snapshot, error) {
	snap, err := LoadLKG(path)
	if err != nil {
		return nil, err
	}
	if err := h.Apply(snap); err != nil {
		return nil, fmt.Errorf("failed to apply startup LKG snapshot: %w", err)
	}
	return snap, nil
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
