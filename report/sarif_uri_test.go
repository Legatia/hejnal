package report

import (
	"net/url"
	"testing"
)

func TestSarifURIIsRelative(t *testing.T) {
	for file, want := range map[string]string{
		"nginx:1.25:/var/lib/dpkg/status":            "nginx%3A1.25%3A/var/lib/dpkg/status",
		"ghcr.io/acme/api:v2:/app/package-lock.json": "ghcr.io/acme/api%3Av2%3A/app/package-lock.json",
		"web/package-lock.json":                      "web/package-lock.json",
		"/etc/app config.yaml":                       "etc/app%20config.yaml",
	} {
		got := sarifURI(file)
		if got != want {
			t.Errorf("sarifURI(%q) = %q, want %q", file, got, want)
		}
		u, err := url.Parse(got)
		if err != nil || u.Scheme != "" || u.IsAbs() {
			t.Errorf("sarifURI(%q) = %q is not a relative reference (scheme %q, %v)", file, got, u.Scheme, err)
		}
	}
}
