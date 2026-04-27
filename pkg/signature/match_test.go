package signature

import "testing"

func TestSignatureRequiresCNAMEAndHTTP(t *testing.T) {
	sig := Signature{
		ID:         "github-pages",
		Service:    "GitHub Pages",
		Takeover:   true,
		Requires:   []string{"cname", "http"},
		Severity:   "high",
		Confidence: "high",
		Matchers: Matchers{
			CNAME: TextMatcher{Contains: []string{"github.io"}},
			HTTP: HTTPMatcher{
				Status: []int{404},
				Body:   TextMatcher{Contains: []string{"There isn't a GitHub Pages site here."}},
			},
		},
	}

	result := sig.Match(Surface{
		CNAMEs: []string{"example.github.io"},
		HTTP: []HTTPObservation{{
			URL:        "https://docs.example.com",
			StatusCode: 404,
			Body:       "There isn't a GitHub Pages site here.",
		}},
	})

	if !result.Matched {
		t.Fatalf("expected full match")
	}
	if len(result.Groups) != 2 {
		t.Fatalf("expected cname and http groups, got %#v", result.Groups)
	}
}

func TestSignatureReportsPartialMatch(t *testing.T) {
	sig := Signature{
		ID:       "netlify",
		Service:  "Netlify",
		Requires: []string{"cname", "http"},
		Matchers: Matchers{
			CNAME: TextMatcher{Contains: []string{"netlify.app"}},
			HTTP:  HTTPMatcher{Body: TextMatcher{Contains: []string{"Not Found - Request ID"}}},
		},
	}

	result := sig.Match(Surface{CNAMEs: []string{"site.netlify.app"}})
	if result.Matched {
		t.Fatalf("did not expect full match")
	}
	if !result.Partial {
		t.Fatalf("expected partial fingerprint")
	}
}

func TestHTTPMatcherRequiresSameResponse(t *testing.T) {
	matcher := HTTPMatcher{
		Status: []int{404},
		Body:   TextMatcher{Contains: []string{"NoSuchBucket"}},
	}

	evidence := matcher.Match([]HTTPObservation{
		{URL: "https://a.example", StatusCode: 404, Body: "generic"},
		{URL: "http://a.example", StatusCode: 200, Body: "NoSuchBucket"},
	})

	if len(evidence) != 0 {
		t.Fatalf("expected no match across different responses")
	}
}
