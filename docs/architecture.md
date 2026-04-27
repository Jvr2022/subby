# Architecture

Subby is split into small packages with narrow responsibilities:

- `cmd/subby`: process entrypoint.
- `pkg/cli`: flags, subcommands, input loading, exit codes.
- `pkg/scanner`: concurrent target orchestration and result shaping.
- `pkg/dnsprobe`: DNS lookups, CNAME chains, dangling DNS detection.
- `pkg/httpprobe`: HTTP and HTTPS probing with bounded response bodies.
- `pkg/signature`: YAML loading, validation, matching, and evidence.
- `pkg/report`: text, JSON, JSONL, and CSV output.
- `signatures/takeover`: bundled takeover signatures embedded into releases.

The scanner treats DNS and HTTP observations as evidence. A takeover finding
requires every group listed in a signature's `requires` field. Partial matches
can be shown with `-include-fingerprints`.

Release archives are produced by GoReleaser from `v*` tags through
`.github/workflows/release.yml`. The Go command install path is
`github.com/Jvr2022/subby/cmd/subby`.
