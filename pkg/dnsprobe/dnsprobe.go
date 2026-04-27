package dnsprobe

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

type Record struct {
	Host        string   `json:"host"`
	CNAMEs      []string `json:"cnames,omitempty"`
	Addresses   []string `json:"addresses,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	Dangling    bool     `json:"dangling"`
	Error       string   `json:"error,omitempty"`
}

type Resolver struct {
	resolver *net.Resolver
	timeout  time.Duration
	servers  []string
	next     atomic.Uint64
}

func New(servers []string, timeout time.Duration) *Resolver {
	clean := make([]string, 0, len(servers))
	for _, server := range servers {
		if normalized := normalizeResolver(server); normalized != "" {
			clean = append(clean, normalized)
		}
	}

	r := &Resolver{timeout: timeout, servers: clean}
	if len(clean) == 0 {
		r.resolver = net.DefaultResolver
		return r
	}

	r.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			idx := r.next.Add(1)
			server := clean[int(idx-1)%len(clean)]
			dialer := net.Dialer{Timeout: timeout}
			return dialer.DialContext(ctx, network, server)
		},
	}
	return r
}

func (r *Resolver) Lookup(ctx context.Context, host string) Record {
	host = normalizeName(host)
	record := Record{Host: host}
	if host == "" {
		record.Error = "empty host"
		return record
	}

	if r.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}

	record.CNAMEs = r.lookupCNAMEChain(ctx, host)

	addresses, err := r.resolver.LookupHost(ctx, host)
	if err != nil {
		record.Error = err.Error()
		if len(record.CNAMEs) > 0 && isNotFound(err) {
			record.Dangling = true
		}
	} else {
		record.Addresses = uniqueStrings(addresses)
	}

	if nameservers, err := r.resolver.LookupNS(ctx, host); err == nil {
		for _, ns := range nameservers {
			record.Nameservers = append(record.Nameservers, normalizeName(ns.Host))
		}
		record.Nameservers = uniqueStrings(record.Nameservers)
	}

	return record
}

func (r *Resolver) lookupCNAMEChain(ctx context.Context, host string) []string {
	var chain []string
	seen := map[string]struct{}{host: {}}
	current := host

	for i := 0; i < 8; i++ {
		cname, err := r.resolver.LookupCNAME(ctx, current)
		if err != nil {
			break
		}

		cname = normalizeName(cname)
		if cname == "" || cname == current {
			break
		}
		if _, ok := seen[cname]; ok {
			break
		}

		chain = append(chain, cname)
		seen[cname] = struct{}{}
		current = cname
	}

	return chain
}

func normalizeName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.TrimSuffix(name, ".")
	return name
}

func normalizeResolver(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	if ip := net.ParseIP(strings.Trim(server, "[]")); ip != nil {
		return net.JoinHostPort(ip.String(), "53")
	}
	return net.JoinHostPort(server, "53")
}

func isNotFound(err error) bool {
	if dnsErr, ok := err.(*net.DNSError); ok {
		return dnsErr.IsNotFound
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
