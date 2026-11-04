package leaks

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultHIBPBaseURL is version 3 of the Have I Been Pwned API.
const DefaultHIBPBaseURL = "https://haveibeenpwned.com/api/v3"

const (
	defaultHIBPUserAgent = "hejnal (+https://github.com/Legatia/hejnal)"
	maxHIBPBody          = 32 << 20
	maxRetryWait         = 10 * time.Second
	defaultRetryWait     = 2 * time.Second
)

// ErrHIBPAccess is returned, wrapped, when HIBP refuses the API key or the
// domain.
var ErrHIBPAccess = errors.New("leaks: HIBP refused access")

// ErrHIBPRateLimited is returned, wrapped, when HIBP still limits requests
// after one wait.
var ErrHIBPRateLimited = errors.New("leaks: HIBP rate limit exceeded")

var domainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// HIBP is a client for the Have I Been Pwned API. Domain search needs an API
// key with a subscription, and HIBP only answers it for domains verified in
// its dashboard. Every request carries the hibp-api-key header, when APIKey
// is set, and a user-agent header, without which HIBP rejects requests.
// Errors never include the API key.
type HIBP struct {
	APIKey string
	// BaseURL defaults to DefaultHIBPBaseURL.
	BaseURL string
	// UserAgent names the caller. Empty means a Hejnal default.
	UserAgent string
	// Client defaults to a client with a 60-second timeout.
	Client *http.Client
}

// Breach describes one data breach as HIBP reports it. HIBP's own field
// names, such as "PwnCount", decode into it too.
type Breach struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Domain      string   `json:"domain"`
	BreachDate  string   `json:"breachDate"`
	AddedDate   string   `json:"addedDate"`
	PwnCount    int64    `json:"pwnCount"`
	DataClasses []string `json:"dataClasses"`
	IsVerified  bool     `json:"isVerified"`
	IsSensitive bool     `json:"isSensitive"`
	IsSpamList  bool     `json:"isSpamList"`
}

// BreachedDomain lists the addresses on domain that appear in breaches. The
// map goes from each alias, the part of the address before the @, to the
// names of the breaches it appears in. A domain without breached addresses
// gives an empty map and no error.
func (h HIBP) BreachedDomain(ctx context.Context, domain string) (map[string][]string, error) {
	d, err := normaliseDomain(domain)
	if err != nil {
		return nil, err
	}
	if h.APIKey == "" {
		return nil, errors.New("leaks: HIBP domain search needs an API key")
	}
	status, body, err := h.get(ctx, "/breacheddomain/"+url.PathEscape(d))
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
		var out map[string][]string
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("leaks: decode HIBP domain search: %w", err)
		}
		if out == nil {
			out = map[string][]string{}
		}
		return out, nil
	case http.StatusNotFound:
		return map[string][]string{}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("%w (%d %s): check that the API key is right, and that %s is verified in the HIBP domain search dashboard",
			ErrHIBPAccess, status, http.StatusText(status), d)
	}
	return nil, statusError(status)
}

// Breach fetches the details of the breach with this name, such as "Adobe".
func (h HIBP) Breach(ctx context.Context, name string) (Breach, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Breach{}, errors.New("leaks: empty breach name")
	}
	status, body, err := h.get(ctx, "/breach/"+url.PathEscape(name))
	if err != nil {
		return Breach{}, err
	}
	switch status {
	case http.StatusOK:
		var b Breach
		if err := json.Unmarshal(body, &b); err != nil {
			return Breach{}, fmt.Errorf("leaks: decode HIBP breach %q: %w", name, err)
		}
		b.Name = cmp.Or(b.Name, name)
		return b, nil
	case http.StatusNotFound:
		return Breach{}, fmt.Errorf("leaks: HIBP has no breach named %q", name)
	case http.StatusUnauthorized, http.StatusForbidden:
		return Breach{}, fmt.Errorf("%w (%d %s): check the API key and the user agent", ErrHIBPAccess, status, http.StatusText(status))
	}
	return Breach{}, statusError(status)
}

// get fetches path. When HIBP answers 429 Too Many Requests, it waits as long
// as Retry-After asks, up to 10 seconds, and tries once more.
func (h HIBP) get(ctx context.Context, path string) (int, []byte, error) {
	status, wait, body, err := h.do(ctx, path)
	if err != nil || status != http.StatusTooManyRequests {
		return status, body, err
	}
	t := time.NewTimer(wait)
	select {
	case <-ctx.Done():
		t.Stop()
		return 0, nil, ctx.Err()
	case <-t.C:
	}
	status, _, body, err = h.do(ctx, path)
	if err == nil && status == http.StatusTooManyRequests {
		return 0, nil, fmt.Errorf("%w: still limited after waiting %s; try again later", ErrHIBPRateLimited, wait)
	}
	return status, body, err
}

// do sends one request. It reads the body only for 200 OK and returns the
// wait asked for by a 429 answer.
func (h HIBP) do(ctx context.Context, path string) (int, time.Duration, []byte, error) {
	base := strings.TrimRight(cmp.Or(h.BaseURL, DefaultHIBPBaseURL), "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("leaks: HIBP request: %w", err)
	}
	if h.APIKey != "" {
		req.Header.Set("hibp-api-key", h.APIKey)
	}
	req.Header.Set("user-agent", cmp.Or(h.UserAgent, defaultHIBPUserAgent))
	req.Header.Set("accept", "application/json")
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, 0, nil, ctx.Err()
		}
		return 0, 0, nil, fmt.Errorf("leaks: HIBP request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return resp.StatusCode, retryDelay(resp.Header.Get("Retry-After")), nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHIBPBody+1))
	if err != nil {
		return 0, 0, nil, fmt.Errorf("leaks: read HIBP response: %w", err)
	}
	if len(body) > maxHIBPBody {
		return 0, 0, nil, fmt.Errorf("leaks: HIBP response is larger than %d MiB", maxHIBPBody>>20)
	}
	return resp.StatusCode, 0, body, nil
}

// retryDelay reads a Retry-After header, in seconds or as a date, and caps
// the wait at 10 seconds.
func retryDelay(v string) time.Duration {
	d := defaultRetryWait
	if s, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
		d = time.Duration(min(s, 3600)) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = time.Until(t)
	}
	return min(max(d, 0), maxRetryWait)
}

func statusError(status int) error {
	return fmt.Errorf("leaks: HIBP answered %d %s", status, http.StatusText(status))
}

// normaliseDomain checks that d is a registered domain name, such as
// example.com, and returns it in lower case.
func normaliseDomain(d string) (string, error) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	bad := func(why string) error { return fmt.Errorf("leaks: %q is not a valid domain: %s", d, why) }
	if d == "" {
		return "", bad("it is empty")
	}
	if len(d) > 253 {
		return "", bad("it is longer than 253 characters")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", bad("give a registered domain such as example.com")
	}
	for _, l := range labels {
		if !domainLabel.MatchString(l) {
			return "", bad(fmt.Sprintf("%q is not a valid label", l))
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", bad("it looks like an IP address")
	}
	return d, nil
}
