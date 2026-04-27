package scanner

import "testing"

func TestNormalizeTarget(t *testing.T) {
	tests := map[string]string{
		"HTTPS://Docs.Example.COM/path?q=1": "docs.example.com",
		"*.Api.Example.com.":                "api.example.com",
		"example.com:8443":                  "example.com",
		"  # comment":                       "",
	}

	for input, expected := range tests {
		got, ok := NormalizeTarget(input)
		if expected == "" {
			if ok {
				t.Fatalf("expected %q to be rejected, got %q", input, got)
			}
			continue
		}
		if !ok || got != expected {
			t.Fatalf("NormalizeTarget(%q) = %q, %v; want %q, true", input, got, ok, expected)
		}
	}
}

func TestNormalizeTargetsDeduplicates(t *testing.T) {
	got := NormalizeTargets([]string{"A.Example.com", "a.example.com.", "b.example.com"})
	want := []string{"a.example.com", "b.example.com"}
	if len(got) != len(want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func TestWithFindings(t *testing.T) {
	got := WithFindings([]Result{
		{Target: "clean.example.com"},
		{Target: "hit.example.com", Findings: []Finding{{State: "vulnerable"}}},
	})
	if len(got) != 1 || got[0].Target != "hit.example.com" {
		t.Fatalf("unexpected filtered results: %#v", got)
	}
}
