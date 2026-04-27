package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Jvr2022/subby/pkg/scanner"
)

type Document struct {
	GeneratedAt string           `json:"generated_at"`
	Summary     Summary          `json:"summary"`
	Results     []scanner.Result `json:"results"`
}

type Summary struct {
	Targets      int `json:"targets"`
	Findings     int `json:"findings"`
	Vulnerable   int `json:"vulnerable"`
	Dangling     int `json:"dangling"`
	Fingerprints int `json:"fingerprints"`
}

func Write(w io.Writer, format string, results []scanner.Result) error {
	switch strings.ToLower(format) {
	case "json":
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(Document{GeneratedAt: time.Now().UTC().Format(time.RFC3339), Summary: NewSummary(results), Results: results})
	case "jsonl":
		encoder := json.NewEncoder(w)
		for _, result := range results {
			for _, finding := range result.Findings {
				if err := encoder.Encode(finding); err != nil {
					return err
				}
			}
		}
		return nil
	case "csv":
		return writeCSV(w, results)
	case "text", "":
		return writeText(w, results)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeCSV(w io.Writer, results []scanner.Result) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	if err := writer.Write([]string{"target", "state", "service", "signature_id", "severity", "confidence", "cnames", "urls"}); err != nil {
		return err
	}
	for _, result := range results {
		for _, finding := range result.Findings {
			if err := writer.Write([]string{
				finding.Target,
				finding.State,
				finding.Service,
				finding.SignatureID,
				finding.Severity,
				finding.Confidence,
				strings.Join(finding.CNAMEs, " -> "),
				strings.Join(finding.URLs, " "),
			}); err != nil {
				return err
			}
		}
	}
	return writer.Error()
}

func NewSummary(results []scanner.Result) Summary {
	summary := Summary{Targets: len(results)}
	for _, result := range results {
		for _, finding := range result.Findings {
			summary.Findings++
			switch finding.State {
			case "vulnerable":
				summary.Vulnerable++
			case "dangling":
				summary.Dangling++
			case "fingerprint":
				summary.Fingerprints++
			}
		}
	}
	return summary
}

func writeText(w io.Writer, results []scanner.Result) error {
	summary := NewSummary(results)
	if summary.Findings == 0 {
		_, err := fmt.Fprintf(w, "No takeover findings across %d target(s).\n", summary.Targets)
		return err
	}

	for _, result := range results {
		for _, finding := range result.Findings {
			if _, err := fmt.Fprintf(w, "%s [%s] %s", finding.Target, strings.ToUpper(finding.State), finding.Service); err != nil {
				return err
			}
			if finding.SignatureID != "" {
				if _, err := fmt.Fprintf(w, " (%s)", finding.SignatureID); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(w, " severity=%s confidence=%s\n", finding.Severity, finding.Confidence); err != nil {
				return err
			}
			if len(finding.CNAMEs) > 0 {
				if _, err := fmt.Fprintf(w, "  cname: %s\n", strings.Join(finding.CNAMEs, " -> ")); err != nil {
					return err
				}
			}
			for _, evidence := range finding.Evidence {
				line := evidence.Matcher
				if evidence.Pattern != "" {
					line += " " + evidence.Pattern
				}
				if evidence.Value != "" {
					line += " => " + evidence.Value
				}
				if _, err := fmt.Fprintf(w, "  evidence: %s: %s\n", evidence.Source, line); err != nil {
					return err
				}
			}
		}
	}

	_, err := fmt.Fprintf(w, "\nSummary: %d finding(s), %d vulnerable, %d dangling, %d fingerprint(s), %d target(s).\n", summary.Findings, summary.Vulnerable, summary.Dangling, summary.Fingerprints, summary.Targets)
	return err
}
