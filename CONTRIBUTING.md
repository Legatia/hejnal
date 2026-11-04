# Contributing to Hejnal

Thank you for helping. The most useful contributions are new fingerprint
rules, fixes to existing ones and Polish or English wording that is clearer to
the people who read the reports.

## Ground rules

Hejnal must stay safe to point at production systems. We will not merge:

- exploit code or payloads, even "harmless" proof-of-concept ones;
- checks that log in, guess passwords, brute-force paths or fuzz parameters;
- requests to new paths in the default scan. The opt-in `-checks` mode may
  request a short, fixed list of well-known paths with ordinary `GET`
  requests, never following redirects; a new one needs a strong case and must
  not store secrets it finds;
- anything that contacts hosts outside the scope or weakens the scope checks;
- new third-party Go dependencies without a strong reason. Hejnal uses only
  the Go standard library, so anyone can audit what it does.

## Development

You need Go 1.26 or newer.

```sh
go test -race ./...
go vet ./...
gofmt -l .        # must print nothing
```

Tests never touch the internet. They use recorded data in `testdata/` and
local test servers.

## Adding a product

Rules live in [`fingerprint/rules.json`](fingerprint/rules.json).
A rule recognises a product from the response to one ordinary `GET /`, after
any redirects inside the scope:

```json
{
  "id": "example-gateway",
  "name": "Example Secure Gateway",
  "category": "edge",
  "path": "^/sslvpn/login",
  "headers": {"Server": "^ExampleGW"},
  "cookies": ["^EXGW_SESSION$"],
  "title": "^Example Secure Gateway - Sign In$",
  "generator": "^ExampleCMS",
  "body": ["/exgw/static/", "exgwLogin\\("],
  "versions": [{"source": "header:Server", "regex": "ExampleGW/([0-9.]+)"}],
  "packaged": [{"source": "header:Server", "regex": "\\((Debian|Ubuntu)\\)"}],
  "kev": [{"vendor": "^Example Corp$", "product": "Secure Gateway"}],
  "cpe": ["examplecorp:secure_gateway"]
}
```

- Any one signal is enough, so pick markers that only this product produces:
  paths, script names, element IDs, JavaScript variables, cookie names. Never
  use the product's name on its own, because resellers' and blogs' pages
  name products they do not run. Anchor title patterns to the product's real
  login page title. The tests check that a page that only names products
  matches nothing.
- An empty header pattern (`""`) means "this header is present".
- Patterns are Go regular expressions and are matched case-insensitively.
- `admin: true` marks admin interfaces, which are reported when reachable.
- `kev` maps the rule to entries in CISA's Known Exploited Vulnerabilities
  catalog by their `vendorProject` and `product` fields. For entries CISA
  files under "Multiple Products", add `text` so that only entries whose name
  or description mention this product match.
- `cpe` lists the product's NVD names as `vendor:product`, the third and
  fourth parts of its CPE names (for example `apache:http_server`). With it,
  Hejnal compares a version it sees with NVD's affected version ranges. List
  every name NVD has used for the product, such as `f5:nginx` and
  `nginx:nginx`.
- `packaged` marks versions that come from a Linux distribution package.
  Distributions backport fixes without changing the version, so Hejnal never
  treats such a version as confirmed affected.
- Categories: `edge` and `remote-access` raise the score, because attackers
  go for internet-facing gateways first. Use the existing categories (the
  tests list them).

Check your rule against the real catalog before opening a pull request. Every
entry it maps to should be a flaw in this product. Add a test case to
`fingerprint/fingerprint_test.go` with a realistic response.

## Commits and pull requests

Keep pull requests focused. Describe what changed and how you tested it. By
contributing you agree that your work is licensed under the Apache License 2.0.
