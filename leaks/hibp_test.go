package leaks

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const hibpKey = "0123456789abcdef0123456789abcdef"

// hibpServer imitates the HIBP API under /api/v3 and counts requests. It
// checks the headers that every request must carry.
func hibpServer(t *testing.T, handle func(w http.ResponseWriter, r *http.Request, n int32)) (HIBP, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := n.Add(1)
		if r.Header.Get("hibp-api-key") != hibpKey || r.Header.Get("user-agent") == "" {
			t.Errorf("request without the API key or a user agent: %v", r.Header)
		}
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api/v3")
		r.URL.RawPath = strings.TrimPrefix(r.URL.RawPath, "/api/v3")
		handle(w, r, count)
	}))
	t.Cleanup(srv.Close)
	return HIBP{APIKey: hibpKey, BaseURL: srv.URL + "/api/v3/", Client: srv.Client()}, &n
}

func TestBreachedDomain(t *testing.T) {
	h, _ := hibpServer(t, func(w http.ResponseWriter, r *http.Request, _ int32) {
		switch r.URL.Path {
		case "/breacheddomain/acme.pl":
			io.WriteString(w, `{"alice": ["Adobe", "LinkedIn"], "bob": ["Adobe"]}`)
		case "/breacheddomain/clean.pl":
			http.NotFound(w, r)
		case "/breacheddomain/unverified.pl":
			http.Error(w, "Forbidden", http.StatusForbidden)
		case "/breacheddomain/badkey.pl":
			http.Error(w, "Unauthorised", http.StatusUnauthorized)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	ctx := context.Background()

	got, err := h.BreachedDomain(ctx, " ACME.pl. ")
	want := map[string][]string{"alice": {"Adobe", "LinkedIn"}, "bob": {"Adobe"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("200: got %v, %v; want %v", got, err, want)
	}
	if got, err := h.BreachedDomain(ctx, "clean.pl"); err != nil || got == nil || len(got) != 0 {
		t.Errorf("404: got %v, %v; want an empty map", got, err)
	}
	for _, d := range []string{"badkey.pl", "unverified.pl"} {
		_, err := h.BreachedDomain(ctx, d)
		if !errors.Is(err, ErrHIBPAccess) || !strings.Contains(err.Error(), "API key") || !strings.Contains(err.Error(), "verified") {
			t.Errorf("%s: got %v, want an access error explaining the key and verification", d, err)
		}
		if err != nil && strings.Contains(err.Error(), hibpKey) {
			t.Errorf("%s: the error contains the API key", d)
		}
	}
}

func TestBreachedDomainChecksInput(t *testing.T) {
	h, n := hibpServer(t, func(w http.ResponseWriter, r *http.Request, _ int32) {})
	for _, d := range []string{"", "localhost", "exa mple.com", "1.2.3.4", "-acme.pl", "acme..pl", "acme.pl/../x", strings.Repeat("a", 64) + ".pl"} {
		if _, err := h.BreachedDomain(context.Background(), d); err == nil {
			t.Errorf("BreachedDomain(%q) succeeded", d)
		}
	}
	h.APIKey = ""
	if _, err := h.BreachedDomain(context.Background(), "acme.pl"); err == nil || !strings.Contains(err.Error(), "API key") {
		t.Errorf("no API key: got %v", err)
	}
	if n.Load() != 0 {
		t.Errorf("%d requests were sent for invalid input", n.Load())
	}
}

func TestBreachedDomainRateLimit(t *testing.T) {
	limited := func(w http.ResponseWriter) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
	}
	h, n := hibpServer(t, func(w http.ResponseWriter, r *http.Request, count int32) {
		if count == 1 {
			limited(w)
			return
		}
		io.WriteString(w, `{"alice": ["Adobe"]}`)
	})
	start := time.Now()
	got, err := h.BreachedDomain(context.Background(), "acme.pl")
	if err != nil || len(got) != 1 || n.Load() != 2 {
		t.Errorf("got %v, %v after %d requests; want the result after a retry", got, err, n.Load())
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Errorf("retried after %v, want the 1 s that Retry-After asked for", elapsed)
	}

	h, n = hibpServer(t, func(w http.ResponseWriter, r *http.Request, _ int32) { limited(w) })
	if _, err := h.BreachedDomain(context.Background(), "acme.pl"); !errors.Is(err, ErrHIBPRateLimited) || n.Load() != 2 {
		t.Errorf("got %v after %d requests, want a rate limit error after one retry", err, n.Load())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start = time.Now()
	if _, err := h.BreachedDomain(ctx, "acme.pl"); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 900*time.Millisecond {
		t.Errorf("got %v after %v, want the context's error without waiting", err, time.Since(start))
	}
}

func TestBreach(t *testing.T) {
	h, _ := hibpServer(t, func(w http.ResponseWriter, r *http.Request, _ int32) {
		switch r.URL.EscapedPath() {
		case "/breach/Adobe":
			// HIBP's own format, shortened.
			io.WriteString(w, `{"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
				"AddedDate": "2013-12-04T00:00:00Z", "PwnCount": 152445165, "Description": "...",
				"DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
				"IsVerified": true, "IsSensitive": false, "IsSpamList": false, "IsMalware": false}`)
		case "/breach/a%2Fb%20c":
			http.NotFound(w, r)
		default:
			t.Errorf("unexpected path %s", r.URL.EscapedPath())
		}
	})
	b, err := h.Breach(context.Background(), "Adobe")
	want := Breach{Name: "Adobe", Title: "Adobe", Domain: "adobe.com", BreachDate: "2013-10-04", AddedDate: "2013-12-04T00:00:00Z",
		PwnCount: 152445165, DataClasses: []string{"Email addresses", "Password hints", "Passwords", "Usernames"}, IsVerified: true}
	if err != nil || !reflect.DeepEqual(b, want) {
		t.Errorf("got %+v, %v; want %+v", b, err, want)
	}
	if _, err := h.Breach(context.Background(), "a/b c"); err == nil || !strings.Contains(err.Error(), "no breach named") {
		t.Errorf("unknown breach: got %v", err)
	}
}

func TestSummarise(t *testing.T) {
	accounts := map[string][]string{
		"alice": {"Adobe", "LinkedIn"},
		"Bob":   {"Adobe", "Adobe"},
		"carol": {"SpamList2017"},
		"dave":  {},
		"erin":  {"Unknown"},
	}
	breaches := map[string]Breach{
		"Adobe": {Name: "Adobe", Title: "Adobe", BreachDate: "2013-10-04", AddedDate: "2013-12-04T00:00:00Z",
			DataClasses: []string{"Email addresses", "Passwords"}},
		"LinkedIn": {Name: "LinkedIn", Title: "LinkedIn", BreachDate: "2012-05-05", AddedDate: "2016-05-21T21:35:40Z",
			DataClasses: []string{"Email addresses", "Passwords"}},
		"SpamList2017": {Name: "SpamList2017", Title: "Spam list", BreachDate: "2017-08-28", AddedDate: "2017-08-29T00:00:00Z",
			DataClasses: []string{"Email addresses"}, IsSpamList: true},
	}
	got := Summarise(" ACME.pl ", accounts, breaches)
	want := DomainSummary{
		Domain:   "acme.pl",
		Accounts: 4,
		Breaches: []DomainBreach{
			{Name: "SpamList2017", Title: "Spam list", BreachDate: "2017-08-28", AddedDate: "2017-08-29", DataClasses: []string{"Email addresses"}, Accounts: 1, SpamList: true},
			{Name: "Adobe", Title: "Adobe", BreachDate: "2013-10-04", AddedDate: "2013-12-04", DataClasses: []string{"Email addresses", "Passwords"}, Accounts: 2, Passwords: true},
			{Name: "LinkedIn", Title: "LinkedIn", BreachDate: "2012-05-05", AddedDate: "2016-05-21", DataClasses: []string{"Email addresses", "Passwords"}, Accounts: 1, Passwords: true},
			{Name: "Unknown", Title: "Unknown", DataClasses: []string{}, Accounts: 1},
		},
		Aliases: []string{"alice", "bob", "carol", "erin"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}

	stored := got.WithoutAliases()
	stored.Breaches[0].DataClasses[0] = "changed"
	js, _ := json.Marshal(stored)
	if stored.Aliases != nil || strings.Contains(string(js), "alice") || strings.Contains(string(js), `"aliases"`) {
		t.Errorf("WithoutAliases kept aliases: %s", js)
	}
	if len(got.Aliases) != 4 || got.Breaches[0].DataClasses[0] != "Email addresses" || stored.Accounts != 4 {
		t.Errorf("WithoutAliases changed the original: %+v", got)
	}
}
