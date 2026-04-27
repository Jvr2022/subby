package signature

import (
	"testing"

	embedded "github.com/Jvr2022/subby/signatures"
)

func TestBundledSignaturesLoad(t *testing.T) {
	signatures, err := LoadFS(embedded.FS, "takeover")
	if err != nil {
		t.Fatalf("LoadFS returned error: %v", err)
	}
	if len(signatures) < 20 {
		t.Fatalf("expected expanded signature set, got %d", len(signatures))
	}
}
