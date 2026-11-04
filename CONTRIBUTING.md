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
- `editions` tells apart software editions that NVD lists separately, by the
  form of the version. Jenkins, for example, maps `2.426.3` to its `lts`
  edition and `2.441` to its weekly one (`-`).
- `packaged` marks versions that may carry fixes the version number does not
  show: Linux distribution packages, which backport fixes, and products whose
  hotfixes keep the version number. Hejnal never treats such a version as
  confirmed affected, but still rules out flaws fixed in an older version. A
  pattern that always matches (as for Serv-U) marks every version this way.
- Hejnal reads a letter right after a version as a pre-release (`1.2.0b2`).
  If a product's maintenance releases add a letter instead (ProFTPD's
  `1.3.5a` comes after `1.3.5`), make the version pattern require what
  follows the number, so that such versions are not read at all rather than
  misread.
- `banners` recognises services that are not web servers by the greeting
  they send as soon as Hejnal connects, such as
  `220 mail.example.com ESMTP Exim 4.96`. A greeting is matched by banner
  patterns only, and a version can be read from it with
  `{"source": "banner", ...}`. Hejnal only reads the greeting; it never logs
  in.
- Categories: `edge`, `remote-access`, `network` and `camera` raise the
  score, because attackers go for internet-facing gateways and devices
  first. Use the existing categories (the tests list them).

Check your rule against the real catalog before opening a pull request. Every
entry it maps to should be a flaw in this product.

Add at least one sample to
[`fingerprint/testdata/samples.json`](fingerprint/testdata/samples.json): a
realistic, minimal copy of what the product really sends, with the version
the rule should read from it. Use `headers`, `path` and `body` for a web
response, or `banner` for a greeting; join several values of one header with
`\n`. The tests require a sample for every rule.

ProjectDiscovery's [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
(MIT License) are a good place to confirm a product's markers. Use a marker
only if the product's root page carries it, since Hejnal requests nothing
else.

## Commits and pull requests

Keep pull requests focused. Describe what changed and how you tested it. By
contributing you agree that your work is licensed under the Apache License 2.0.
