package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Jvr2022/subby/pkg/scanner"
)

func TestWriteTextNoFindings(t *testing.T) {
	var buf bytes.Buffer
	err := Write(&buf, "text", []scanner.Result{{Target: "example.com"}})
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "No takeover findings") {
		t.Fatalf("unexpected output: %s", buf.String())
	}
}

func TestSummary(t *testing.T) {
	summary := NewSummary([]scanner.Result{{
		Target: "example.com",
		Findings: []scanner.Finding{
			{State: "vulnerable"},
			{State: "dangling"},
			{State: "fingerprint"},
		},
	}})
	if summary.Findings != 3 || summary.Vulnerable != 1 || summary.Dangling != 1 || summary.Fingerprints != 1 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func TestWriteCSV(t *testing.T) {
	var buf bytes.Buffer
	err := Write(&buf, "csv", []scanner.Result{{
		Target: "docs.example.com",
		Findings: []scanner.Finding{{
			Target:      "docs.example.com",
			State:       "vulnerable",
			Service:     "Example",
			SignatureID: "example",
			Severity:    "high",
			Confidence:  "high",
		}},
	}})
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "docs.example.com,vulnerable,Example") {
		t.Fatalf("unexpected csv: %s", buf.String())
	}
}
