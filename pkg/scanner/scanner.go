package scanner

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Jvr2022/subby/pkg/config"
	"github.com/Jvr2022/subby/pkg/dnsprobe"
	"github.com/Jvr2022/subby/pkg/httpprobe"
	"github.com/Jvr2022/subby/pkg/signature"
)

type Scanner struct {
	opts       config.Options
	resolver   *dnsprobe.Resolver
	http       *httpprobe.Probe
	signatures []signature.Signature
}

type Result struct {
	Target   string          `json:"target"`
	DNS      dnsprobe.Record `json:"dns"`
	HTTP     []HTTPResult    `json:"http,omitempty"`
	Findings []Finding       `json:"findings,omitempty"`
	Errors   []string        `json:"errors,omitempty"`
	Duration string          `json:"duration"`
}

type HTTPResult struct {
	URL        string `json:"url"`
	FinalURL   string `json:"final_url,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Title      string `json:"title,omitempty"`
	Duration   string `json:"duration,omitempty"`
	Error      string `json:"error,omitempty"`
}

type Finding struct {
	Target      string               `json:"target"`
	State       string               `json:"state"`
	Service     string               `json:"service"`
	SignatureID string               `json:"signature_id,omitempty"`
	Severity    string               `json:"severity"`
	Confidence  string               `json:"confidence"`
	Description string               `json:"description,omitempty"`
	CNAMEs      []string             `json:"cnames,omitempty"`
	Addresses   []string             `json:"addresses,omitempty"`
	URLs        []string             `json:"urls,omitempty"`
	Evidence    []signature.Evidence `json:"evidence,omitempty"`
	References  []string             `json:"references,omitempty"`
}

func New(opts config.Options, signatures []signature.Signature) (*Scanner, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if len(signatures) == 0 {
		return nil, fmt.Errorf("at least one signature is required")
	}

	return &Scanner{
		opts:       opts,
		resolver:   dnsprobe.New(opts.Resolvers, opts.DNSTimeout),
		http:       httpprobe.New(httpprobe.Options{Timeout: opts.HTTPTimeout, Retries: opts.Retries, MaxBodyBytes: opts.MaxBodyBytes, UserAgent: opts.UserAgent, TLSVerify: opts.TLSVerify}),
		signatures: signatures,
	}, nil
}

func (s *Scanner) Run(ctx context.Context, rawTargets []string) ([]Result, error) {
	targets := NormalizeTargets(rawTargets)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets provided")
	}

	workers := s.opts.Concurrency
	if workers > len(targets) {
		workers = len(targets)
	}

	jobs := make(chan string)
	results := make(chan Result, len(targets))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				results <- s.scanOne(ctx, target)
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, target := range targets {
			select {
			case <-ctx.Done():
				return
			case jobs <- target:
			}
		}
	}()

	wg.Wait()
	close(results)

	out := make([]Result, 0, len(targets))
	for result := range results {
		out = append(out, result)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Target < out[j].Target
	})

	if err := ctx.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func (s *Scanner) scanOne(ctx context.Context, target string) Result {
	start := time.Now()
	dnsRecord := s.resolver.Lookup(ctx, target)
	var httpResponses []httpprobe.Response
	if !s.opts.SkipHTTP {
		httpResponses = s.http.FetchHost(ctx, target, s.opts.Schemes)
	}

	result := Result{
		Target: target,
		DNS:    dnsRecord,
		HTTP:   publicHTTP(httpResponses),
	}
	if dnsRecord.Error != "" {
		result.Errors = append(result.Errors, "dns: "+dnsRecord.Error)
	}
	for _, response := range httpResponses {
		if response.Error != "" {
			result.Errors = append(result.Errors, response.URL+": "+response.Error)
		}
	}

	surface := signature.Surface{
		Target:      target,
		CNAMEs:      dnsRecord.CNAMEs,
		Nameservers: dnsRecord.Nameservers,
		Addresses:   dnsRecord.Addresses,
		Dangling:    dnsRecord.Dangling,
		HTTP:        observations(httpResponses),
	}

	for _, sig := range s.signatures {
		match := sig.Match(surface)
		if !match.Matched && !(s.opts.IncludeFingerprints && match.Partial) {
			continue
		}
		result.Findings = append(result.Findings, findingFromMatch(target, dnsRecord, httpResponses, sig, match))
	}

	if dnsRecord.Dangling && !hasState(result.Findings, "dangling") {
		result.Findings = append(result.Findings, Finding{
			Target:      target,
			State:       "dangling",
			Service:     "unknown",
			Severity:    "medium",
			Confidence:  "medium",
			Description: "CNAME chain exists but the target does not resolve.",
			CNAMEs:      dnsRecord.CNAMEs,
			Evidence: []signature.Evidence{{
				Source:  "dns",
				Matcher: "dangling",
				Value:   dnsRecord.Error,
			}},
		})
	}

	sort.Slice(result.Findings, func(i, j int) bool {
		return findingRank(result.Findings[i]) < findingRank(result.Findings[j])
	})
	result.Duration = time.Since(start).String()
	return result
}

func findingFromMatch(target string, dnsRecord dnsprobe.Record, responses []httpprobe.Response, sig signature.Signature, match signature.MatchResult) Finding {
	state := "matched"
	severity := withDefault(sig.Severity, "info")
	confidence := withDefault(sig.Confidence, "medium")

	if sig.Takeover && match.Matched {
		state = "vulnerable"
	} else if match.Partial {
		state = "fingerprint"
		severity = "info"
		confidence = "low"
	}
	if contains(match.Groups, "dangling") && state != "vulnerable" {
		state = "dangling"
	}

	return Finding{
		Target:      target,
		State:       state,
		Service:     sig.Service,
		SignatureID: sig.ID,
		Severity:    severity,
		Confidence:  confidence,
		Description: sig.Description,
		CNAMEs:      dnsRecord.CNAMEs,
		Addresses:   dnsRecord.Addresses,
		URLs:        responseURLs(responses),
		Evidence:    match.Evidence,
		References:  sig.References,
	}
}

func publicHTTP(responses []httpprobe.Response) []HTTPResult {
	out := make([]HTTPResult, 0, len(responses))
	for _, response := range responses {
		out = append(out, HTTPResult{
			URL:        response.URL,
			FinalURL:   response.FinalURL,
			StatusCode: response.StatusCode,
			Title:      response.Title,
			Duration:   response.Duration,
			Error:      response.Error,
		})
	}
	return out
}

func observations(responses []httpprobe.Response) []signature.HTTPObservation {
	out := make([]signature.HTTPObservation, 0, len(responses))
	for _, response := range responses {
		out = append(out, signature.HTTPObservation{
			URL:        response.URL,
			StatusCode: response.StatusCode,
			Headers:    map[string][]string(response.Headers),
			Body:       response.Body,
			Title:      response.Title,
			Error:      response.Error,
		})
	}
	return out
}

func responseURLs(responses []httpprobe.Response) []string {
	seen := map[string]struct{}{}
	var urls []string
	for _, response := range responses {
		for _, value := range []string{response.URL, response.FinalURL} {
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			urls = append(urls, value)
		}
	}
	sort.Strings(urls)
	return urls
}

func NormalizeTargets(rawTargets []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, raw := range rawTargets {
		target, ok := NormalizeTarget(raw)
		if !ok {
			continue
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	sort.Strings(out)
	return out
}

func NormalizeTarget(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return "", false
	}

	host := raw
	if strings.Contains(host, "://") {
		parsed, err := url.Parse(host)
		if err != nil {
			return "", false
		}
		host = parsed.Hostname()
	} else {
		if idx := strings.IndexAny(host, "/?#"); idx >= 0 {
			host = host[:idx]
		}
		host = strings.Trim(host, "[]")
		if splitHost, _, err := net.SplitHostPort(host); err == nil {
			host = splitHost
		} else if withoutPort, ok := stripPlainPort(host); ok {
			host = withoutPort
		}
	}

	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimPrefix(host, "*.")
	host = strings.TrimSuffix(host, ".")
	if host == "" || strings.ContainsAny(host, " \t\r\n") {
		return "", false
	}
	return host, true
}

func stripPlainPort(host string) (string, bool) {
	idx := strings.LastIndex(host, ":")
	if idx <= 0 || idx == len(host)-1 || strings.Count(host, ":") != 1 {
		return "", false
	}
	if _, err := strconv.Atoi(host[idx+1:]); err != nil {
		return "", false
	}
	return host[:idx], true
}

func HasActionableFindings(results []Result) bool {
	for _, result := range results {
		for _, finding := range result.Findings {
			if finding.State == "vulnerable" || finding.State == "dangling" {
				return true
			}
		}
	}
	return false
}

func WithFindings(results []Result) []Result {
	out := make([]Result, 0, len(results))
	for _, result := range results {
		if len(result.Findings) == 0 {
			continue
		}
		out = append(out, result)
	}
	return out
}

func hasState(findings []Finding, state string) bool {
	for _, finding := range findings {
		if finding.State == state {
			return true
		}
	}
	return false
}

func withDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func findingRank(f Finding) int {
	switch f.State {
	case "vulnerable":
		return 0
	case "dangling":
		return 1
	case "matched":
		return 2
	default:
		return 3
	}
}
