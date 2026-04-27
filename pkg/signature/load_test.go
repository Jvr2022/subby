package signature

import (
	"testing"
	"testing/fstest"
)

func TestLoadFS(t *testing.T) {
	fsys := fstest.MapFS{
		"takeover/example.yaml": &fstest.MapFile{Data: []byte(`
id: example
service: Example
severity: high
confidence: high
requires:
  - cname
matchers:
  cname:
    contains:
      - example.net
`)},
	}

	signatures, err := LoadFS(fsys, "takeover")
	if err != nil {
		t.Fatalf("LoadFS returned error: %v", err)
	}
	if len(signatures) != 1 {
		t.Fatalf("expected one signature, got %d", len(signatures))
	}
	if signatures[0].ID != "example" {
		t.Fatalf("unexpected signature id %q", signatures[0].ID)
	}
}

func TestMergeOverridesByID(t *testing.T) {
	base := []Signature{{ID: "same", Service: "Old", Matchers: Matchers{Dangling: true}}}
	overrides := []Signature{{ID: "same", Service: "New", Matchers: Matchers{Dangling: true}}}

	merged := Merge(base, overrides)
	if len(merged) != 1 {
		t.Fatalf("expected one signature, got %d", len(merged))
	}
	if merged[0].Service != "New" {
		t.Fatalf("expected override to win, got %q", merged[0].Service)
	}
}
