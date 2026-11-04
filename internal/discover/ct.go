package discover

import (
	"context"
	"encoding/json"
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
}

// Subdomains returns the names under domain seen in certificates.
func (c *CrtSh) Subdomains(ctx context.Context, domain string) ([]string, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = CrtShURL
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	u := base + "/?q=" + url.QueryEscape("%."+domain) + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh: %s", resp.Status)
	}
	var rows []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&rows); err != nil {
		return nil, fmt.Errorf("crt.sh: decode: %w", err)
	}
	var raw []string
	for _, r := range rows {
		raw = append(raw, r.CommonName)
		raw = append(raw, strings.Split(r.NameValue, "\n")...)
	}
	return namesUnder(domain, raw), nil
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
