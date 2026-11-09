package discover

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/Legatia/hejnal/inventory"
)

// Opt-in checks send a few more ordinary GET requests to fixed, well-known
// paths of a web service that already answered. They never send payloads,
// guess passwords or follow redirects, and every request goes through the
// same scope-checked connection guard as discovery.
//
// Per service there are at most three exposure checks, one version check
// per recognised product that did not show its version, and up to eight
// scripts the front page loads from the same site, read for server secrets.

// maxCheckBody limits how much of a check response is read.
const maxCheckBody = 64 << 10

// Exposure kinds.
const (
	ExposureGit          = "git"
	ExposureEnv          = "env"
	ExposureServerStatus = "server-status"
)

type exposureCheck struct {
	kind string
	path string
	// test inspects the start of a 200 response and returns evidence that
	// is safe to store, or "" when the file is not exposed.
	test func(header http.Header, body []byte) string
}

var (
	gitHeadRE = regexp.MustCompile(`\A(?:ref: refs/[^\s]+|[0-9a-f]{40})\s*\z`)
	envLineRE = regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]{1,63}=`)
)

var exposureChecks = []exposureCheck{
	{ExposureGit, "/.git/HEAD", func(h http.Header, body []byte) string {
		if gitHeadRE.Match(body) {
			return "the repository's HEAD file is readable"
		}
		return ""
	}},
	{ExposureEnv, "/.env", func(h http.Header, body []byte) string {
		if strings.Contains(strings.ToLower(h.Get("Content-Type")), "html") || isHTML(body) {
			return ""
		}
		// Count variables without keeping any value.
		if n := len(envLineRE.FindAll(body, -1)); n >= 2 {
			return fmt.Sprintf("an environment file with %d or more settings (contents not stored)", n)
		}
		return ""
	}},
	{ExposureServerStatus, "/server-status", func(h http.Header, body []byte) string {
		if strings.Contains(string(body), "Apache Server Status for") {
			return "Apache's status page with live requests and client addresses"
		}
		return ""
	}},
}

func isHTML(b []byte) bool {
	s := strings.ToLower(strings.TrimSpace(string(b[:min(len(b), 512)])))
	return strings.HasPrefix(s, "<!doctype") || strings.HasPrefix(s, "<html") || strings.Contains(s, "<body")
}

// versionCheck reads a version a product publishes at a fixed public path.
type versionCheck struct {
	path string
	re   *regexp.Regexp
}

var versionChecks = map[string]versionCheck{
	// WordPress names its version in the RSS generator tag even when the
	// page's generator tag is removed.
	"wordpress": {"/feed/", regexp.MustCompile(`<generator>https?://wordpress\.org/\?v=([0-9]+(?:\.[0-9]+)+)</generator>`)},
	// Grafana's health endpoint is public by design.
	"grafana": {"/api/health", regexp.MustCompile(`"version"\s*:\s*"([0-9]+(?:\.[0-9]+)+)"`)},
	// Joomla ships its version in a public manifest.
	"joomla": {"/administrator/manifests/files/joomla.xml", regexp.MustCompile(`<version>([0-9]+(?:\.[0-9]+)+)</version>`)},
	// Drupal 7 publishes its changelog at the web root.
	"drupal": {"/CHANGELOG.txt", regexp.MustCompile(`(?m)^Drupal ([0-9]+\.[0-9]+(?:\.[0-9]+)?), [0-9]{4}-[0-9]{2}-[0-9]{2}`)},
	// Outlook on the web loads its scripts from a path with the build number.
	"exchange-owa": {"/owa/auth/logon.aspx", regexp.MustCompile(`/owa/(?:auth/)?([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)/`)},
}

// runChecks performs the opt-in checks for a web service that answered.
func (w *webClient) runChecks(ctx context.Context, host string, port int, svc *inventory.Service) {
	if svc.Scheme != "http" && svc.Scheme != "https" {
		return
	}
	for _, c := range exposureChecks {
		status, header, body, err := w.get(ctx, host, port, svc.Scheme, c.path)
		if err != nil || status != http.StatusOK {
			continue
		}
		if ev := c.test(header, body); ev != "" {
			svc.Exposures = append(svc.Exposures, inventory.Exposure{Kind: c.kind, Path: c.path, Evidence: ev})
		}
	}
	w.scriptSecrets(ctx, host, port, svc)
	for i := range svc.Technologies {
		t := &svc.Technologies[i]
		vc, ok := versionChecks[t.ID]
		if !ok || t.Version != "" {
			continue
		}
		status, _, body, err := w.get(ctx, host, port, svc.Scheme, vc.path)
		if err != nil || status != http.StatusOK {
			continue
		}
		if m := vc.re.FindSubmatch(body); m != nil {
			t.Version = string(m[1])
			t.Evidence += "; version from " + vc.path
		}
	}
}

// get sends one GET request for a fixed path and reads the start of the
// answer. Redirects are never followed.
func (w *webClient) get(ctx context.Context, host string, port int, scheme, path string) (int, http.Header, []byte, error) {
	return w.getN(ctx, host, port, scheme, path, maxCheckBody)
}

// getN is get, reading up to limit bytes. path may carry a query.
func (w *webClient) getN(ctx context.Context, host string, port int, scheme, path string, limit int64) (int, http.Header, []byte, error) {
	u := &url.URL{Scheme: scheme, Host: hostPort(host, port, scheme)}
	if p, q, ok := strings.Cut(path, "?"); ok {
		u.RawPath, u.RawQuery = p, q
		u.Path, _ = url.PathUnescape(p)
	} else {
		u.Path = path
	}
	client := &http.Client{
		Transport:     w.transport,
		Timeout:       2 * w.r.opts.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", w.r.opts.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	return resp.StatusCode, resp.Header, body, nil
}
