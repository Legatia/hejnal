package discover

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// CrtShURL is the public certificate transparency search service.
const CrtShURL = "https://crt.sh"

// CrtSh finds subdomains in certificate transparency logs through crt.sh.
// Every publicly trusted certificate is logged, so this lists names an
// organisation may have forgotten about.
type CrtSh struct {
	Client    *http.Client
	BaseURL   string
	UserAgent string
	// Wait is the pause before asking again after crt.sh fails to answer
	// (default 3 seconds).
	Wait time.Duration
}

// crtShTries is how often a lookup is sent while crt.sh answers with an
// error. It often does for a moment, with 502, 503 and even 404, and for a
// domain it has no certificates for it answers 200 and an empty list.
const crtShTries = 3

// Subdomains returns the names under domain seen in certificates.
func (c *CrtSh) Subdomains(ctx context.Context, domain string) ([]string, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = CrtShURL
	}
	client := &http.Client{Timeout: 90 * time.Second}
	if c.Client != nil {
		copied := *c.Client
		client = &copied
	}
	// The service has no reason to send Hejnal anywhere else.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Host != via[0].URL.Host {
			return errors.New("unexpected redirect")
		}
		return nil
	}
	u := base + "/?q=" + url.QueryEscape("%."+domain) + "&output=json"
	wait := c.Wait
	if wait <= 0 {
		wait = 3 * time.Second
	}
	for try := 1; ; try++ {
		names, again, err := c.lookup(ctx, client, u, domain)
		if !again || try == crtShTries {
			return names, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// lookup sends one query. It reports again when crt.sh answered with an
// error status, which is worth another try.
func (c *CrtSh) lookup(ctx context.Context, client *http.Client, u, domain string) (names []string, again bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("crt.sh: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, true, fmt.Errorf("crt.sh: %s", resp.Status)
	}
	var rows []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&rows); err != nil {
		return nil, false, fmt.Errorf("crt.sh: decode: %w", err)
	}
	var raw []string
	for _, r := range rows {
		raw = append(raw, r.CommonName)
		raw = append(raw, strings.Split(r.NameValue, "\n")...)
	}
	return namesUnder(domain, raw), false, nil
}

// namesUnder normalises names, drops wildcard labels and keeps the ones that
// are domain or below it.
func namesUnder(domain string, names []string) []string {
	domain = normalizeHost(domain)
	set := map[string]bool{}
	for _, n := range names {
		n = normalizeHost(strings.TrimPrefix(strings.TrimSpace(n), "*."))
		if n == "" || strings.ContainsAny(n, "*@ /") {
			continue
		}
		if n == domain || strings.HasSuffix(n, "."+domain) {
			set[n] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}
