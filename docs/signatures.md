# Signatures

Signatures are YAML files. Built-in signatures live in `signatures/takeover`,
and custom files can be loaded with `-signature path`.

Validate the bundled set and any custom additions before committing them:

```sh
subby validate -signature ./my-signatures
```

```yaml
id: example-service
name: Example missing project
service: Example
severity: high
confidence: high
description: A custom domain points at Example but the project is missing.
takeover: true
requires:
  - cname
  - http
matchers:
  cname:
    contains:
      - example-cdn.net
  http:
    status:
      - 404
    body:
      contains:
        - project not found
references:
  - https://docs.example.com/custom-domains
```

Matcher groups:

- `cname`: matches the discovered CNAME chain.
- `ns`: matches nameservers returned for the target.
- `dangling`: matches when DNS returns a CNAME chain with no address.
- `http`: matches one HTTP response. Status, body, title, and headers must
  match the same response when they are present together.

Text matchers support `contains`, `equals`, `prefix`, `suffix`, and `regex`.
Plain text matchers are case-insensitive.
