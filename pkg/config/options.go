package config

import (
	"errors"
	"time"
)

type Options struct {
	Concurrency         int
	DNSTimeout          time.Duration
	HTTPTimeout         time.Duration
	Retries             int
	MaxBodyBytes        int64
	UserAgent           string
	Resolvers           []string
	Schemes             []string
	TLSVerify           bool
	SkipHTTP            bool
	IncludeFingerprints bool
}

func DefaultOptions() Options {
	return Options{
		Concurrency:  32,
		DNSTimeout:   5 * time.Second,
		HTTPTimeout:  8 * time.Second,
		Retries:      1,
		MaxBodyBytes: 2 << 20,
		UserAgent:    "subby/dev (+https://github.com/Jvr2022/subby)",
		Schemes:      []string{"https", "http"},
	}
}

func (o Options) Validate() error {
	if o.Concurrency < 1 {
		return errors.New("concurrency must be greater than zero")
	}
	if o.DNSTimeout <= 0 {
		return errors.New("dns timeout must be greater than zero")
	}
	if o.HTTPTimeout <= 0 {
		return errors.New("http timeout must be greater than zero")
	}
	if o.Retries < 0 {
		return errors.New("retries cannot be negative")
	}
	if o.MaxBodyBytes < 1024 {
		return errors.New("max body size must be at least 1024 bytes")
	}
	if len(o.Schemes) == 0 {
		return errors.New("at least one scheme is required")
	}
	for _, scheme := range o.Schemes {
		if scheme != "http" && scheme != "https" {
			return errors.New("scheme must be http or https")
		}
	}
	return nil
}
