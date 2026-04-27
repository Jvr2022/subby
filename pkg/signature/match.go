package signature

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func (s Signature) Match(surface Surface) MatchResult {
	groups := map[string]bool{}
	var evidence []Evidence

	if !s.Matchers.CNAME.Empty() {
		if ev := s.Matchers.CNAME.Match("cname", surface.CNAMEs); len(ev) > 0 {
			groups["cname"] = true
			evidence = append(evidence, ev...)
		}
	}
	if !s.Matchers.NS.Empty() {
		if ev := s.Matchers.NS.Match("ns", surface.Nameservers); len(ev) > 0 {
			groups["ns"] = true
			evidence = append(evidence, ev...)
		}
	}
	if s.Matchers.Dangling && surface.Dangling {
		groups["dangling"] = true
		evidence = append(evidence, Evidence{Source: "dns", Matcher: "dangling", Value: "cname has no resolvable address"})
	}
	if !s.Matchers.HTTP.Empty() {
		if ev := s.Matchers.HTTP.Match(surface.HTTP); len(ev) > 0 {
			groups["http"] = true
			evidence = append(evidence, ev...)
		}
	}

	matched := requiredGroupsMatched(s.Requires, groups)
	return MatchResult{
		Matched:  matched,
		Partial:  !matched && len(evidence) > 0,
		Groups:   sortedGroups(groups),
		Evidence: evidence,
	}
}

func requiredGroupsMatched(required []string, groups map[string]bool) bool {
	if len(required) == 0 {
		return len(groups) > 0
	}
	for _, group := range required {
		if !groups[strings.ToLower(strings.TrimSpace(group))] {
			return false
		}
	}
	return true
}

func sortedGroups(groups map[string]bool) []string {
	out := make([]string, 0, len(groups))
	for group := range groups {
		out = append(out, group)
	}
	sort.Strings(out)
	return out
}

func (m TextMatcher) Empty() bool {
	return len(m.Contains) == 0 &&
		len(m.Equals) == 0 &&
		len(m.Prefix) == 0 &&
		len(m.Suffix) == 0 &&
		len(m.Regex) == 0
}

func (m TextMatcher) Match(source string, values []string) []Evidence {
	var evidence []Evidence
	for _, value := range values {
		for _, pattern := range m.Equals {
			if strings.EqualFold(value, pattern) {
				evidence = append(evidence, Evidence{Source: source, Matcher: "equals", Pattern: pattern, Value: clip(value)})
			}
		}
		for _, pattern := range m.Contains {
			if containsFold(value, pattern) {
				evidence = append(evidence, Evidence{Source: source, Matcher: "contains", Pattern: pattern, Value: snippet(value, pattern)})
			}
		}
		for _, pattern := range m.Prefix {
			if strings.HasPrefix(strings.ToLower(value), strings.ToLower(pattern)) {
				evidence = append(evidence, Evidence{Source: source, Matcher: "prefix", Pattern: pattern, Value: clip(value)})
			}
		}
		for _, pattern := range m.Suffix {
			if strings.HasSuffix(strings.ToLower(value), strings.ToLower(pattern)) {
				evidence = append(evidence, Evidence{Source: source, Matcher: "suffix", Pattern: pattern, Value: clip(value)})
			}
		}
		for _, pattern := range m.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			if match := re.FindString(value); match != "" {
				evidence = append(evidence, Evidence{Source: source, Matcher: "regex", Pattern: pattern, Value: clip(match)})
			}
		}
	}
	return evidence
}

func (m HTTPMatcher) Empty() bool {
	return len(m.Status) == 0 &&
		m.Body.Empty() &&
		m.Title.Empty() &&
		len(m.Headers) == 0
}

func (m HTTPMatcher) Match(responses []HTTPObservation) []Evidence {
	for _, response := range responses {
		if response.Error != "" && response.StatusCode == 0 {
			continue
		}

		var evidence []Evidence
		source := response.URL
		if source == "" {
			source = "http"
		}

		if len(m.Status) > 0 {
			if !statusMatches(m.Status, response.StatusCode) {
				continue
			}
			evidence = append(evidence, Evidence{
				Source:  source,
				Matcher: "status",
				Pattern: statusPattern(m.Status),
				Value:   strconv.Itoa(response.StatusCode),
			})
		}

		if !m.Body.Empty() {
			ev := m.Body.Match(source+" body", []string{response.Body})
			if len(ev) == 0 {
				continue
			}
			evidence = append(evidence, ev...)
		}

		if !m.Title.Empty() {
			ev := m.Title.Match(source+" title", []string{response.Title})
			if len(ev) == 0 {
				continue
			}
			evidence = append(evidence, ev...)
		}

		headerEvidence, ok := matchHeaders(m.Headers, response.Headers, source)
		if !ok {
			continue
		}
		evidence = append(evidence, headerEvidence...)

		if len(evidence) > 0 {
			return evidence
		}
	}
	return nil
}

func matchHeaders(matchers []HeaderMatcher, headers map[string][]string, source string) ([]Evidence, bool) {
	if len(matchers) == 0 {
		return nil, true
	}

	var evidence []Evidence
	for _, matcher := range matchers {
		values := headerValues(headers, matcher.Name)
		if len(values) == 0 {
			return nil, false
		}

		text := TextMatcher{
			Contains: matcher.Contains,
			Equals:   matcher.Equals,
			Prefix:   matcher.Prefix,
			Suffix:   matcher.Suffix,
			Regex:    matcher.Regex,
		}
		ev := text.Match(source+" header "+matcher.Name, values)
		if len(ev) == 0 {
			return nil, false
		}
		evidence = append(evidence, ev...)
	}
	return evidence, true
}

func headerValues(headers map[string][]string, name string) []string {
	if len(headers) == 0 {
		return nil
	}
	if values, ok := headers[name]; ok {
		return values
	}
	canonical := http.CanonicalHeaderKey(name)
	if values, ok := headers[canonical]; ok {
		return values
	}
	for key, values := range headers {
		if strings.EqualFold(key, name) {
			return values
		}
	}
	return nil
}

func statusMatches(allowed []int, status int) bool {
	for _, value := range allowed {
		if value == status {
			return true
		}
	}
	return false
}

func statusPattern(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ",")
}

func containsFold(value, pattern string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(pattern))
}

func clip(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) <= 180 {
		return value
	}
	return value[:177] + "..."
}

func snippet(value, pattern string) string {
	value = strings.Join(strings.Fields(value), " ")
	lowerValue := strings.ToLower(value)
	lowerPattern := strings.ToLower(pattern)
	idx := strings.Index(lowerValue, lowerPattern)
	if idx == -1 {
		return clip(value)
	}
	start := idx - 70
	if start < 0 {
		start = 0
	}
	end := idx + len(pattern) + 70
	if end > len(value) {
		end = len(value)
	}
	out := value[start:end]
	if start > 0 {
		out = "..." + out
	}
	if end < len(value) {
		out += "..."
	}
	return out
}

func (s Signature) Validate() error {
	if strings.TrimSpace(s.ID) == "" {
		return fmt.Errorf("signature id is required")
	}
	if strings.TrimSpace(s.Service) == "" {
		return fmt.Errorf("signature %q service is required", s.ID)
	}
	if s.Matchers.CNAME.Empty() && s.Matchers.NS.Empty() && !s.Matchers.Dangling && s.Matchers.HTTP.Empty() {
		return fmt.Errorf("signature %q has no matchers", s.ID)
	}
	for _, pattern := range s.Matchers.CNAME.Regex {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("signature %q cname regex: %w", s.ID, err)
		}
	}
	for _, pattern := range s.Matchers.NS.Regex {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("signature %q ns regex: %w", s.ID, err)
		}
	}
	for _, pattern := range s.Matchers.HTTP.Body.Regex {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("signature %q body regex: %w", s.ID, err)
		}
	}
	for _, pattern := range s.Matchers.HTTP.Title.Regex {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("signature %q title regex: %w", s.ID, err)
		}
	}
	for _, header := range s.Matchers.HTTP.Headers {
		for _, pattern := range header.Regex {
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("signature %q header regex: %w", s.ID, err)
			}
		}
	}
	return nil
}
