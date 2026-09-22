package router

import (
	"errors"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/phaselume/torana/internal/config"
)

var (
	// ErrNoRouteMatched is returned when no route matches the request criteria.
	ErrNoRouteMatched = errors.New("no route matched")
	// ErrUpstreamNotFound is returned when an upstream cluster is not found.
	ErrUpstreamNotFound = errors.New("upstream cluster not found")
)

// MatchCriteria represents the attributes of an incoming request evaluated for routing.
type MatchCriteria struct {
	Host    string
	Method  string
	Path    string
	Headers map[string]string // for string map matching
	Header  http.Header       // direct http.Header for zero-allocation hot path
	Claims  map[string]string
}

// RetryBudget tracks available retry tokens to prevent cascading retry storms.
type RetryBudget struct {
	maxRatio   float64
	minRetries int
	requests   atomic.Uint64
	retries    atomic.Uint64
}

// NewRetryBudget creates a token-bucket retry budget.
func NewRetryBudget(maxRatio float64, minRetries int) *RetryBudget {
	if maxRatio <= 0 {
		maxRatio = 0.2 // default 20% max retries
	}
	if minRetries <= 0 {
		minRetries = 10
	}
	return &RetryBudget{
		maxRatio:   maxRatio,
		minRetries: minRetries,
	}
}

// AllowRetry determines if a retry is allowed under the current budget.
func (rb *RetryBudget) AllowRetry() bool {
	if rb == nil {
		return true
	}
	reqs := rb.requests.Load()
	rets := rb.retries.Load()
	if int(rets) < rb.minRetries {
		rb.retries.Add(1)
		return true
	}
	if float64(rets)/float64(reqs+1) < rb.maxRatio {
		rb.retries.Add(1)
		return true
	}
	return false
}

// RecordRequest tracks an incoming request in the retry budget.
func (rb *RetryBudget) RecordRequest() {
	if rb != nil {
		rb.requests.Add(1)
	}
}

// MatchResult contains the resolved route, target upstream cluster, and active policies.
type MatchResult struct {
	Route        *config.RouteRule
	Upstream     *config.UpstreamCluster
	RetryPolicy  *config.RetryPolicy
	RetryBudget  *RetryBudget
	TotalTimeout int64
}

type compiledRoute struct {
	rule          *config.RouteRule
	upstream      *config.UpstreamCluster
	weightedPool  []weightedTarget
	totalWeight   int
	hostRegex     *regexp.Regexp
	pathRegex     *regexp.Regexp
	headerRegexes map[string]*regexp.Regexp
	claimRegexes  map[string]*regexp.Regexp
	retryBudget   *RetryBudget
}

type weightedTarget struct {
	upstream *config.UpstreamCluster
	weight   int
}

type pathNode struct {
	prefix   string
	routes   []*compiledRoute
	children []*pathNode
}

// Router holds pre-compiled immutable lookup structures for a single Snapshot.
type Router struct {
	// methodPathLookup maps method -> path -> []*compiledRoute (0 alloc exact lookup!)
	methodPathLookup map[string]map[string][]*compiledRoute
	// prefixRoot root node for path prefix matching
	prefixRoot *pathNode
	// routeTrie segment-based route trie from config
	routeTrie *config.RouteTrie
	// regexRoutes holds routes with regex path matchers
	regexRoutes []*compiledRoute
	// upstreams holds all configured upstream clusters
	upstreams map[string]*config.UpstreamCluster
	// counter for deterministic weighted selection
	counter atomic.Uint64
}

// Compile builds a high-performance, immutable Router from a given Snapshot.
func Compile(s *config.Snapshot) *Router {
	r := &Router{
		methodPathLookup: make(map[string]map[string][]*compiledRoute),
		prefixRoot:       &pathNode{},
		routeTrie:        config.NewRouteTrie(),
		upstreams:        make(map[string]*config.UpstreamCluster, len(s.Upstreams)),
	}

	for id, u := range s.Upstreams {
		clusterCopy := u
		r.upstreams[id] = &clusterCopy
	}

	for i := range s.Routes {
		route := &s.Routes[i]
		cr := &compiledRoute{
			rule:          route,
			headerRegexes: make(map[string]*regexp.Regexp),
			claimRegexes:  make(map[string]*regexp.Regexp),
		}

		// Compile path regex if applicable
		if strings.HasPrefix(route.Path, "^") || strings.Contains(route.Path, "(") {
			if re, err := regexp.Compile(route.Path); err == nil {
				cr.pathRegex = re
				r.regexRoutes = append(r.regexRoutes, cr)
			}
		}

		// Compile host regex if applicable
		if strings.HasPrefix(route.Host, "^") {
			if re, err := regexp.Compile(route.Host); err == nil {
				cr.hostRegex = re
			}
		}

		// Compile header regexes
		for hk, hv := range route.Headers {
			if strings.HasPrefix(hv, "^") {
				if re, err := regexp.Compile(hv); err == nil {
					cr.headerRegexes[hk] = re
				}
			}
		}

		// Compile claim regexes
		for ck, cv := range route.Claims {
			if strings.HasPrefix(cv, "^") {
				if re, err := regexp.Compile(cv); err == nil {
					cr.claimRegexes[ck] = re
				}
			}
		}

		if route.UpstreamID != "" {
			if u, ok := r.upstreams[route.UpstreamID]; ok {
				cr.upstream = u
			} else {
				cr.upstream = &config.UpstreamCluster{ID: route.UpstreamID, Protocol: "http"}
			}
		}

		if len(route.WeightedUpstreams) > 0 {
			total := 0
			for _, wu := range route.WeightedUpstreams {
				u, ok := r.upstreams[wu.UpstreamID]
				if !ok {
					u = &config.UpstreamCluster{ID: wu.UpstreamID, Protocol: "http"}
				}
				cr.weightedPool = append(cr.weightedPool, weightedTarget{
					upstream: u,
					weight:   wu.Weight,
				})
				total += wu.Weight
			}
			cr.totalWeight = total
			if cr.upstream == nil && len(cr.weightedPool) > 0 {
				cr.upstream = cr.weightedPool[0].upstream
			}
		}

		if route.RetryPolicy != nil {
			cr.retryBudget = NewRetryBudget(0.2, 10)
		}

		methodKey := normalizeMethod(route.Method)

		if !route.PathPrefix && cr.pathRegex == nil {
			mMap, ok := r.methodPathLookup[methodKey]
			if !ok {
				mMap = make(map[string][]*compiledRoute)
				r.methodPathLookup[methodKey] = mMap
			}
			mMap[route.Path] = append(mMap[route.Path], cr)
		} else if route.PathPrefix {
			r.addPrefixRoute(route.Path, cr)
		}

		// Also insert into RouteTrie
		cfgCompiledRoute := &config.CompiledRoute{
			Rule:      route,
			PathRegex: cr.pathRegex,
			HostRegex: cr.hostRegex,
		}
		r.routeTrie.Insert(cfgCompiledRoute)
	}

	return r
}

func (r *Router) addPrefixRoute(prefix string, cr *compiledRoute) {
	current := r.prefixRoot
	for _, child := range current.children {
		if child.prefix == prefix {
			child.routes = append(child.routes, cr)
			return
		}
	}

	newNode := &pathNode{
		prefix: prefix,
		routes: []*compiledRoute{cr},
	}
	current.children = append(current.children, newNode)
}

// Match evaluates an incoming request criteria against the routing table.
func (r *Router) Match(criteria MatchCriteria) (MatchResult, error) {
	method := normalizeMethod(criteria.Method)
	path := criteria.Path

	// 1. Try Exact Path Lookups (Specific Method -> Wildcard Method)
	if mMap, ok := r.methodPathLookup[method]; ok {
		if routes, ok := mMap[path]; ok {
			for _, cr := range routes {
				if r.matchesCriteria(cr, criteria) {
					return r.buildResult(cr), nil
				}
			}
		}
	}

	if method != "*" {
		if mMap, ok := r.methodPathLookup["*"]; ok {
			if routes, ok := mMap[path]; ok {
				for _, cr := range routes {
					if r.matchesCriteria(cr, criteria) {
						return r.buildResult(cr), nil
					}
				}
			}
		}
	}

	// 2. Try Prefix Tree Lookup
	if cr := r.matchPrefix(criteria); cr != nil {
		return r.buildResult(cr), nil
	}

	// 3. Try Regex Path Lookups
	for _, cr := range r.regexRoutes {
		if cr.pathRegex != nil && cr.pathRegex.MatchString(criteria.Path) {
			if r.matchesCriteria(cr, criteria) {
				return r.buildResult(cr), nil
			}
		}
	}

	return MatchResult{}, ErrNoRouteMatched
}

func (r *Router) matchPrefix(criteria MatchCriteria) *compiledRoute {
	var bestNode *pathNode
	longest := -1

	for _, child := range r.prefixRoot.children {
		if strings.HasPrefix(criteria.Path, child.prefix) {
			if len(child.prefix) > longest {
				longest = len(child.prefix)
				bestNode = child
			}
		}
	}

	if bestNode != nil {
		for _, cr := range bestNode.routes {
			if r.matchesCriteria(cr, criteria) {
				return cr
			}
		}
	}

	return nil
}

func (r *Router) matchesCriteria(cr *compiledRoute, criteria MatchCriteria) bool {
	rule := cr.rule

	// Host check
	if rule.Host != "" && rule.Host != "*" {
		if cr.hostRegex != nil {
			if !cr.hostRegex.MatchString(criteria.Host) {
				return false
			}
		} else if !matchHost(rule.Host, criteria.Host) {
			return false
		}
	}

	// Method check
	if rule.Method != "" && rule.Method != "*" {
		if !strings.EqualFold(rule.Method, criteria.Method) {
			return false
		}
	}

	// Header checks
	if len(rule.Headers) > 0 {
		if criteria.Header == nil && criteria.Headers == nil {
			return false
		}

		for k, expectedVal := range rule.Headers {
			var actualVal string
			var exists bool

			if criteria.Header != nil {
				actualVal = criteria.Header.Get(k)
				if actualVal != "" {
					exists = true
				} else {
					actualVal = criteria.Header.Get(strings.ToLower(k))
					exists = (actualVal != "")
				}
			} else if criteria.Headers != nil {
				actualVal, exists = criteria.Headers[k]
				if !exists {
					actualVal, exists = criteria.Headers[strings.ToLower(k)]
				}
			}

			if !exists {
				return false
			}

			if re, ok := cr.headerRegexes[k]; ok {
				if !re.MatchString(actualVal) {
					return false
				}
			} else if actualVal != expectedVal {
				return false
			}
		}
	}

	// Identity claim checks
	if len(rule.Claims) > 0 {
		if criteria.Claims == nil {
			return false
		}
		for k, expectedVal := range rule.Claims {
			actualVal, exists := criteria.Claims[k]
			if !exists {
				return false
			}
			if re, ok := cr.claimRegexes[k]; ok {
				if !re.MatchString(actualVal) {
					return false
				}
			} else if actualVal != expectedVal {
				return false
			}
		}
	}

	return true
}

func (r *Router) buildResult(cr *compiledRoute) MatchResult {
	targetUpstream := cr.upstream

	// Handle weighted traffic splits
	if len(cr.weightedPool) > 0 && cr.totalWeight > 0 {
		val := int(r.counter.Add(1) % uint64(cr.totalWeight))
		acc := 0
		for _, wt := range cr.weightedPool {
			acc += wt.weight
			if val < acc {
				targetUpstream = wt.upstream
				break
			}
		}
	}

	if cr.retryBudget != nil {
		cr.retryBudget.RecordRequest()
	}

	return MatchResult{
		Route:        cr.rule,
		Upstream:     targetUpstream,
		RetryPolicy:  cr.rule.RetryPolicy,
		RetryBudget:  cr.retryBudget,
		TotalTimeout: cr.rule.Timeout.Milliseconds(),
	}
}

func matchHost(pattern, host string) bool {
	pattern = normalizeHost(pattern)
	host = normalizeHost(host)

	if pattern == host || pattern == "*" || pattern == "" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // e.g. ".internal.net"
		return strings.HasSuffix(host, suffix)
	}
	return false
}

func normalizeHost(host string) string {
	if host == "" {
		return "*"
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return strings.ToLower(host)
}

func normalizeMethod(method string) string {
	switch method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "*":
		return method
	case "":
		return "*"
	}
	return strings.ToUpper(method)
}

// SelectWeightedUpstream is a helper selecting an upstream cluster based on weight.
func SelectWeightedUpstream(pool []weightedTarget, totalWeight int) *config.UpstreamCluster {
	if len(pool) == 0 {
		return nil
	}
	if totalWeight <= 0 {
		return pool[0].upstream
	}
	n := rand.Intn(totalWeight)
	acc := 0
	for _, target := range pool {
		acc += target.weight
		if n < acc {
			return target.upstream
		}
	}
	return pool[0].upstream
}
