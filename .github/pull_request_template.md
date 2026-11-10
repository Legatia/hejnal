<!-- What changed, and why. -->

**How I tested it:**

- [ ] `go test -race ./...`, `go vet ./...` and `gofmt -l .` pass.
- [ ] No new third-party dependencies.
- [ ] No new requests in the default scan, and nothing that contacts hosts outside the scope.
- [ ] Each new or changed fingerprint rule has a sample in `fingerprint/testdata/samples.json`.
