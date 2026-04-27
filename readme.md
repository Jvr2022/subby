<p align="center">
  <img src="assets/banner.webp" alt="Project Banner" width="100%" />
</p>


Subby is a Go CLI for finding subdomain takeover risk with DNS evidence,
bounded HTTP probing, and YAML signatures. It is built for authorized testing:
fast enough for asset inventories, strict enough to avoid noisy single-signal
alerts, and simple to extend when a provider changes its error page.

## Install

```sh
go install github.com/Jvr2022/subby/cmd/subby@latest
```

Pinned release install:

```sh
go install github.com/Jvr2022/subby/cmd/subby@v0.1.0
```

From this repository:

```sh
make build
./bin/subby version
```

On Arch Linux, the package files are in `packaging/aur`.

## Usage

```sh
subby scan -target docs.example.com
subby scan -list targets.txt -resolver 1.1.1.1 -resolver 8.8.8.8
subby scan -list targets.txt -format jsonl -output findings.jsonl
subby scan -list targets.txt -format csv -only-findings
subby scan -list targets.txt -scheme https
subby scan -list targets.txt -dns-only
subby scan -list targets.txt -include-fingerprints
subby signatures
subby validate
```

Subby only reports likely takeovers when all required signature groups match.
Use `-include-fingerprints` when you also want partial provider fingerprints.

## Custom Signatures

```sh
subby scan -list targets.txt -signature ./my-signatures
```

See [docs/signatures.md](docs/signatures.md) for the YAML schema.

## Development

```sh
make fmt
make test
make build
```

Project layout is documented in [docs/architecture.md](docs/architecture.md).


## Responsible Use

Only scan assets you own or have permission to test. Subby validates exposure;
it does not claim services or perform takeover actions.
