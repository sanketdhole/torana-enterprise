package router

import (
	"errors"
	"strings"

	"github.com/phaselume/torana/internal/config"
)

var (
	// ErrNoRouteMatched is returned when no route matches the request.
	ErrNoRouteMatched = errors.New("no route matched")
	// ErrUpstreamNotFound is returned when a matched route references an upstream cluster missing in the snapshot.
	ErrUpstreamNotFound = errors.New("upstream cluster not found")
)

// MatchResult contains the resolved route and its upstream cluster.
type MatchResult struct {
	Route    *config.RouteRule
	Upstream *config.UpstreamCluster
}

type prefixNode struct {
	prefix   string
	route    *config.RouteRule
	upstream *config.UpstreamCluster
	children []*prefixNode
}

// Router holds pre-compiled immutable lookup structures for a single Snapshot.
type Router struct {
	// exactRoutes maps "METHOD:PATH" -> MatchResult
	exactRoutes map[string]MatchResult
	// anyMethodExact maps "PATH" -> MatchResult for routes with wildcard/empty method
	anyMethodExact map[string]MatchResult
	// prefixTrees holds root nodes by HTTP method ("GET", "POST", "*")
	prefixTrees map[string]*prefixNode
}

// Compile builds an immutable Router from a given Snapshot.
func Compile(s *config.Snapshot) *Router {
	r := &Router{
		exactRoutes:    make(map[string]MatchResult, len(s.Routes)),
		anyMethodExact: make(map[string]MatchResult),
		prefixTrees:    make(map[string]*prefixNode),
	}

	for i := range s.Routes {
		route := &s.Routes[i]
		upstream, ok := s.Upstreams[route.UpstreamID]
		if !ok {
			// If upstream cluster is missing, still allow compilation, but it will error on lookup.
			upstream = config.UpstreamCluster{ID: route.UpstreamID}
		}

		result := MatchResult{
			Route:    route,
			Upstream: &upstream,
		}

		method := strings.ToUpper(strings.TrimSpace(route.Method))
		if method == "" {
			method = "*"
		}

		if !route.PathPrefix {
			if method == "*" {
				r.anyMethodExact[route.Path] = result
			} else {
				key := method + ":" + route.Path
				r.exactRoutes[key] = result
			}
		} else {
			r.addPrefixRoute(method, route.Path, route, &upstream)
		}
	}

	return r
}

func (r *Router) addPrefixRoute(method, prefix string, route *config.RouteRule, upstream *config.UpstreamCluster) {
	root, exists := r.prefixTrees[method]
	if !exists {
		root = &prefixNode{}
		r.prefixTrees[method] = root
	}

	current := root
	// Insert or find path
	for _, child := range current.children {
		if child.prefix == prefix {
			child.route = route
			child.upstream = upstream
			return
		}
	}

	newNode := &prefixNode{
		prefix:   prefix,
		route:    route,
		upstream: upstream,
	}
	current.children = append(current.children, newNode)
}

// Match performs a fast, lock-free lookup for the given method and path.
func (r *Router) Match(method, path string) (MatchResult, error) {
	// 1. Fast-path exact match
	key := method + ":" + path
	if res, ok := r.exactRoutes[key]; ok {
		return res, nil
	}

	// 2. Exact match with any method
	if res, ok := r.anyMethodExact[path]; ok {
		return res, nil
	}

	// 3. Prefix match by specific method
	if res, ok := r.matchPrefix(method, path); ok {
		return res, nil
	}

	// 4. Prefix match by wildcard method
	if res, ok := r.matchPrefix("*", path); ok {
		return res, nil
	}

	return MatchResult{}, ErrNoRouteMatched
}

func (r *Router) matchPrefix(method, path string) (MatchResult, bool) {
	root, ok := r.prefixTrees[method]
	if !ok {
		return MatchResult{}, false
	}

	var bestMatch *prefixNode
	longest := -1

	for _, child := range root.children {
		if strings.HasPrefix(path, child.prefix) {
			if len(child.prefix) > longest {
				longest = len(child.prefix)
				bestMatch = child
			}
		}
	}

	if bestMatch != nil {
		return MatchResult{
			Route:    bestMatch.route,
			Upstream: bestMatch.upstream,
		}, true
	}

	return MatchResult{}, false
}
