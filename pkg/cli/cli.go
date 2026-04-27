package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	embedded "github.com/Jvr2022/subby/signatures"

	"github.com/Jvr2022/subby/pkg/config"
	"github.com/Jvr2022/subby/pkg/report"
	"github.com/Jvr2022/subby/pkg/scanner"
	"github.com/Jvr2022/subby/pkg/signature"
	"github.com/Jvr2022/subby/pkg/version"
)

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "scan":
			return runScan(args[1:], stdin, stdout, stderr)
		case "signatures":
			return runSignatures(stdout, stderr)
		case "validate":
			return runValidate(args[1:], stdout, stderr)
		case "version":
			fmt.Fprintln(stdout, version.String())
			return 0
		case "help", "-h", "--help":
			printRootUsage(stdout)
			return 0
		default:
			if !strings.HasPrefix(args[0], "-") {
				fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
				printRootUsage(stderr)
				return 2
			}
		}
	}
	return runScan(args, stdin, stdout, stderr)
}

func runScan(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts := config.DefaultOptions()
	var targets listFlag
	var listPath string
	var signaturePaths listFlag
	var outputPath string
	var format string
	var failOnFindings bool
	var onlyFindings bool
	var showVersion bool
	schemes := schemeFlag{values: append([]string{}, opts.Schemes...)}

	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Var(&targets, "target", "target hostname, URL, or comma-separated list")
	flags.Var(&targets, "t", "shorthand for -target")
	flags.StringVar(&listPath, "list", "", "file containing targets, one per line")
	flags.StringVar(&listPath, "l", "", "shorthand for -list")
	flags.Var(&signaturePaths, "signature", "custom signature file or directory")
	flags.Var(&signaturePaths, "s", "shorthand for -signature")
	flags.Var((*listFlag)(&opts.Resolvers), "resolver", "DNS resolver, repeatable")
	flags.Var((*listFlag)(&opts.Resolvers), "r", "shorthand for -resolver")
	flags.Var(&schemes, "scheme", "HTTP scheme to probe: http or https, repeatable")
	flags.IntVar(&opts.Concurrency, "concurrency", opts.Concurrency, "number of concurrent targets")
	flags.IntVar(&opts.Concurrency, "c", opts.Concurrency, "shorthand for -concurrency")
	flags.DurationVar(&opts.DNSTimeout, "dns-timeout", opts.DNSTimeout, "DNS lookup timeout")
	flags.DurationVar(&opts.HTTPTimeout, "http-timeout", opts.HTTPTimeout, "HTTP request timeout")
	flags.IntVar(&opts.Retries, "retries", opts.Retries, "HTTP retry count per scheme")
	flags.Int64Var(&opts.MaxBodyBytes, "max-body", opts.MaxBodyBytes, "maximum response bytes inspected")
	flags.StringVar(&opts.UserAgent, "user-agent", opts.UserAgent, "HTTP user agent")
	flags.BoolVar(&opts.TLSVerify, "tls-verify", opts.TLSVerify, "verify TLS certificates")
	flags.BoolVar(&opts.SkipHTTP, "dns-only", opts.SkipHTTP, "skip HTTP probing and only evaluate DNS evidence")
	flags.BoolVar(&opts.IncludeFingerprints, "include-fingerprints", opts.IncludeFingerprints, "include partial service fingerprints")
	flags.StringVar(&format, "format", "text", "output format: text, json, jsonl, csv")
	flags.StringVar(&outputPath, "output", "", "write report to file")
	flags.StringVar(&outputPath, "o", "", "shorthand for -output")
	flags.BoolVar(&onlyFindings, "only-findings", false, "omit targets with no findings from structured reports")
	flags.BoolVar(&failOnFindings, "fail-on-findings", false, "exit with code 2 when vulnerable or dangling findings exist")
	flags.BoolVar(&showVersion, "version", false, "print version and exit")
	flags.Usage = func() { printScanUsage(stderr) }

	if err := flags.Parse(args); err != nil {
		return 2
	}
	if showVersion {
		fmt.Fprintln(stdout, version.String())
		return 0
	}
	opts.Schemes = schemes.Values()

	allTargets := append([]string{}, targets...)
	if listPath != "" {
		fromFile, err := readTargetFile(listPath)
		if err != nil {
			fmt.Fprintf(stderr, "read target list: %v\n", err)
			return 1
		}
		allTargets = append(allTargets, fromFile...)
	}
	if len(allTargets) == 0 && stdinHasData(stdin) {
		fromStdin, err := readTargets(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "read stdin: %v\n", err)
			return 1
		}
		allTargets = append(allTargets, fromStdin...)
	}
	if len(allTargets) == 0 {
		printScanUsage(stderr)
		return 2
	}

	builtin, err := signature.LoadFS(embedded.FS, "takeover")
	if err != nil {
		fmt.Fprintf(stderr, "load built-in signatures: %v\n", err)
		return 1
	}
	custom, err := signature.LoadPaths(signaturePaths)
	if err != nil {
		fmt.Fprintf(stderr, "load custom signatures: %v\n", err)
		return 1
	}

	engine, err := scanner.New(opts, signature.Merge(builtin, custom))
	if err != nil {
		fmt.Fprintf(stderr, "configure scanner: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	results, err := engine.Run(ctx, allTargets)
	if err != nil && len(results) == 0 {
		fmt.Fprintf(stderr, "scan failed: %v\n", err)
		return 1
	}
	if onlyFindings {
		results = scanner.WithFindings(results)
	}

	writer := stdout
	var output *os.File
	if outputPath != "" {
		output, err = os.Create(outputPath)
		if err != nil {
			fmt.Fprintf(stderr, "create output: %v\n", err)
			return 1
		}
		defer output.Close()
		writer = output
	}

	if err := report.Write(writer, format, results); err != nil {
		fmt.Fprintf(stderr, "write report: %v\n", err)
		return 1
	}
	if err != nil {
		fmt.Fprintf(stderr, "scan interrupted: %v\n", err)
		return 1
	}
	if failOnFindings && scanner.HasActionableFindings(results) {
		return 2
	}
	return 0
}

func runSignatures(stdout, stderr io.Writer) int {
	sigs, err := signature.LoadFS(embedded.FS, "takeover")
	if err != nil {
		fmt.Fprintf(stderr, "load built-in signatures: %v\n", err)
		return 1
	}
	for _, sig := range sigs {
		fmt.Fprintf(stdout, "%-24s %-22s severity=%-7s confidence=%s\n", sig.ID, sig.Service, sig.Severity, sig.Confidence)
	}
	return 0
}

func runValidate(args []string, stdout, stderr io.Writer) int {
	var signaturePaths listFlag
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Var(&signaturePaths, "signature", "custom signature file or directory")
	flags.Var(&signaturePaths, "s", "shorthand for -signature")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage:")
		fmt.Fprintln(stderr, "  subby validate")
		fmt.Fprintln(stderr, "  subby validate -signature ./my-signatures")
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}

	builtin, err := signature.LoadFS(embedded.FS, "takeover")
	if err != nil {
		fmt.Fprintf(stderr, "load built-in signatures: %v\n", err)
		return 1
	}
	custom, err := signature.LoadPaths(signaturePaths)
	if err != nil {
		fmt.Fprintf(stderr, "load custom signatures: %v\n", err)
		return 1
	}
	all := signature.Merge(builtin, custom)
	fmt.Fprintf(stdout, "validated %d signature(s)\n", len(all))
	return 0
}

func printRootUsage(w io.Writer) {
	fmt.Fprintln(w, "subby is a template-driven subdomain takeover scanner.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  subby scan -target docs.example.com")
	fmt.Fprintln(w, "  subby -list targets.txt -format jsonl")
	fmt.Fprintln(w, "  subby signatures")
	fmt.Fprintln(w, "  subby validate")
	fmt.Fprintln(w, "  subby version")
}

func printScanUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  subby scan -target docs.example.com")
	fmt.Fprintln(w, "  subby scan -list targets.txt -resolver 1.1.1.1 -format json")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  -target, -t               target hostname, URL, or comma-separated list")
	fmt.Fprintln(w, "  -list, -l                 file containing targets, one per line")
	fmt.Fprintln(w, "  -signature, -s            custom signature file or directory")
	fmt.Fprintln(w, "  -resolver, -r             DNS resolver, repeatable")
	fmt.Fprintln(w, "  -concurrency, -c          concurrent target count")
	fmt.Fprintln(w, "  -scheme                   HTTP scheme to probe: http or https")
	fmt.Fprintln(w, "  -dns-only                 skip HTTP probing")
	fmt.Fprintln(w, "  -format                   text, json, jsonl, or csv")
	fmt.Fprintln(w, "  -only-findings            omit clean targets from structured reports")
	fmt.Fprintln(w, "  -include-fingerprints     include partial service fingerprints")
	fmt.Fprintln(w, "  -fail-on-findings         return exit code 2 for vulnerable or dangling findings")
}

type listFlag []string

func (f *listFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(*f, ",")
}

func (f *listFlag) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		*f = append(*f, part)
	}
	return nil
}

type schemeFlag struct {
	values []string
	set    bool
}

func (f *schemeFlag) String() string {
	return strings.Join(f.Values(), ",")
}

func (f *schemeFlag) Set(value string) error {
	if !f.set {
		f.values = nil
		f.set = true
	}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		f.values = append(f.values, part)
	}
	return nil
}

func (f schemeFlag) Values() []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(f.values))
	for _, value := range f.values {
		if value != "http" && value != "https" {
			out = append(out, value)
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func readTargetFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readTargets(file)
}

func readTargets(reader io.Reader) ([]string, error) {
	var targets []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	return targets, scanner.Err()
}

func stdinHasData(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice == 0
}
