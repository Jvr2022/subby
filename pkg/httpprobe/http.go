package httpprobe

import (
	"context"
	"crypto/tls"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Options struct {
	Timeout      time.Duration
	Retries      int
	MaxBodyBytes int64
	UserAgent    string
	TLSVerify    bool
}

type Response struct {
	URL        string      `json:"url"`
	FinalURL   string      `json:"final_url,omitempty"`
	StatusCode int         `json:"status_code,omitempty"`
	Headers    http.Header `json:"headers,omitempty"`
	Body       string      `json:"-"`
	Title      string      `json:"title,omitempty"`
	Duration   string      `json:"duration,omitempty"`
	Error      string      `json:"error,omitempty"`
}

type Probe struct {
	client       *http.Client
	retries      int
	maxBodyBytes int64
	userAgent    string
}

func New(opts Options) *Probe {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: !opts.TLSVerify}

	return &Probe{
		client: &http.Client{
			Timeout:   opts.Timeout,
			Transport: transport,
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		retries:      opts.Retries,
		maxBodyBytes: opts.MaxBodyBytes,
		userAgent:    opts.UserAgent,
	}
}

func (p *Probe) FetchHost(ctx context.Context, host string, schemes []string) []Response {
	responses := make([]Response, 0, len(schemes))
	for _, scheme := range schemes {
		scheme = strings.TrimSpace(strings.ToLower(scheme))
		if scheme == "" {
			continue
		}
		responses = append(responses, p.Fetch(ctx, scheme+"://"+host))
	}
	return responses
}

func (p *Probe) Fetch(ctx context.Context, rawURL string) Response {
	var last Response
	for attempt := 0; attempt <= p.retries; attempt++ {
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return Response{URL: rawURL, Error: err.Error()}
		}
		req.Header.Set("User-Agent", p.userAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := p.client.Do(req)
		if err != nil {
			last = Response{URL: rawURL, Duration: time.Since(start).String(), Error: err.Error()}
			if attempt < p.retries {
				sleep(ctx, attempt)
			}
			continue
		}

		body, readErr := readBody(resp.Body, p.maxBodyBytes)
		_ = resp.Body.Close()

		out := Response{
			URL:        rawURL,
			FinalURL:   resp.Request.URL.String(),
			StatusCode: resp.StatusCode,
			Headers:    resp.Header.Clone(),
			Body:       body,
			Title:      extractTitle(body),
			Duration:   time.Since(start).String(),
		}
		if readErr != nil {
			out.Error = readErr.Error()
		}
		return out
	}
	return last
}

func readBody(body io.Reader, limit int64) (string, error) {
	if limit <= 0 {
		limit = 2 << 20
	}
	data, err := io.ReadAll(io.LimitReader(body, limit))
	return string(data), err
}

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(body string) string {
	match := titlePattern.FindStringSubmatch(body)
	if len(match) != 2 {
		return ""
	}
	title := html.UnescapeString(match[1])
	return strings.Join(strings.Fields(title), " ")
}

func sleep(ctx context.Context, attempt int) {
	delay := time.Duration(attempt+1) * 150 * time.Millisecond
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
