package peers

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
)

// DNSDiscoverer periodically resolves a Kubernetes headless service DNS name to discover and join peers.
type DNSDiscoverer struct {
	dnsName     string
	defaultPort int
	ml          *memberlist.Memberlist
	interval    time.Duration
	logger      *slog.Logger
	stopChan    chan struct{}
	wg          sync.WaitGroup
	knownAddrs  map[string]bool
	mu          sync.Mutex
}

// NewDNSDiscoverer creates a new DNSDiscoverer for headless Kubernetes services.
func NewDNSDiscoverer(dnsName string, defaultPort int, ml *memberlist.Memberlist, interval time.Duration, logger *slog.Logger) *DNSDiscoverer {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &DNSDiscoverer{
		dnsName:     dnsName,
		defaultPort: defaultPort,
		ml:          ml,
		interval:    interval,
		logger:      logger,
		stopChan:    make(chan struct{}),
		knownAddrs:  make(map[string]bool),
	}
}

// Start begins the background DNS resolution worker.
func (d *DNSDiscoverer) Start() {
	if d.dnsName == "" {
		return
	}

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()

		// Run immediate initial discovery
		d.discoverOnce()

		ticker := time.NewTicker(d.interval)
		defer ticker.Stop()

		for {
			select {
			case <-d.stopChan:
				return
			case <-ticker.C:
				d.discoverOnce()
			}
		}
	}()
}

func (d *DNSDiscoverer) discoverOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := net.DefaultResolver
	ips, err := resolver.LookupIP(ctx, "ip", d.dnsName)
	if err != nil {
		if d.logger != nil {
			d.logger.Debug("headless DNS peer lookup failed or returned no results", "dns", d.dnsName, "error", err)
		}
		return
	}

	var newAddrs []string
	d.mu.Lock()
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(d.defaultPort))
		if !d.knownAddrs[addr] {
			d.knownAddrs[addr] = true
			newAddrs = append(newAddrs, addr)
		}
	}
	d.mu.Unlock()

	if len(newAddrs) > 0 && d.ml != nil {
		joined, err := d.ml.Join(newAddrs)
		if err != nil {
			if d.logger != nil {
				d.logger.Warn("error joining discovered peer addrs", "attempted", len(newAddrs), "joined", joined, "error", err)
			}
		} else if d.logger != nil && joined > 0 {
			d.logger.Info("discovered and joined peers via headless DNS", "joined", joined, "dns", d.dnsName)
		}
	}
}

// Stop gracefully shuts down the discovery loop.
func (d *DNSDiscoverer) Stop() {
	close(d.stopChan)
	d.wg.Wait()
}
