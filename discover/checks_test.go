package discover

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Legatia/hejnal/inventory"
)

// leakySite serves a WordPress page that hides its version, plus files that
// should not be public. It records the paths it is asked for.
func leakySite(t *testing.T) (*httptest.Server, func() []string) {
	var mu sync.Mutex
	var paths []string
	secret := "sek" + "ret-" + strings.Repeat("x7", 6) // never a literal secret in source
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			io.WriteString(w, `<html><head><title>Shop</title><script src="/wp-includes/js/jquery.js"></script></head></html>`)
		case "/feed/":
			io.WriteString(w, `<rss><channel><generator>https://wordpress.org/?v=6.8.1</generator></channel></rss>`)
		case "/.git/HEAD":
			io.WriteString(w, "ref: refs/heads/main\n")
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "APP_NAME=Shop\nDB_PASSWORD="+secret+"\nMAIL_HOST=smtp.example.test\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(paths)
	}
}

func onlyService(t *testing.T, inv *inventory.Inventory) inventory.Service {
	t.Helper()
	if len(inv.Assets) != 1 || len(inv.Assets[0].Services) != 1 {
		t.Fatalf("assets = %+v", inv.Assets)
	}
	return inv.Assets[0].Services[0]
}

func TestChecksFindExposedFilesAndVersions(t *testing.T) {
	srv, paths := leakySite(t)
	s := testScope(t, nil, []string{"127.0.0.1"}, []int{portOf(t, srv.URL)}, nil)
	inv, err := Run(context.Background(), Options{Scope: s, Engine: engine(t), Timeout: 2 * time.Second, Checks: true})
	if err != nil {
		t.Fatal(err)
	}
	svc := onlyService(t, inv)
	kinds := map[string]inventory.Exposure{}
	for _, x := range svc.Exposures {
		kinds[x.Kind] = x
	}
	if _, ok := kinds[ExposureGit]; !ok {
		t.Error("exposed .git not found")
	}
	env, ok := kinds[ExposureEnv]
	if !ok {
		t.Fatal("exposed .env not found")
	}
	if strings.Contains(env.Evidence, "sek") || strings.Contains(env.Evidence, "smtp") {
		t.Errorf(".env evidence leaks contents: %q", env.Evidence)
	}
	if _, ok := kinds[ExposureServerStatus]; ok {
		t.Error("server-status reported although it returned 404")
	}
	var wp inventory.Technology
	for _, tech := range svc.Technologies {
		if tech.ID == "wordpress" {
			wp = tech
		}
	}
	if wp.Version != "6.8.1" || !strings.Contains(wp.Evidence, "/feed/") {
		t.Errorf("wordpress = %+v, want version 6.8.1 from /feed/", wp)
	}
	// "/", the exposure checks, the page's one script and the version check.
	if len(paths()) > 1+len(exposureChecks)+1+1 {
		t.Errorf("too many requests: %v", paths())
	}

	// Without -checks, only "/" is requested.
	srv2, paths2 := leakySite(t)
	s2 := testScope(t, nil, []string{"127.0.0.1"}, []int{portOf(t, srv2.URL)}, nil)
	inv2, err := Run(context.Background(), Options{Scope: s2, Engine: engine(t), Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if got := paths2(); !slices.Equal(got, []string{"/"}) {
		t.Errorf("without checks Hejnal requested %v", got)
	}
	if len(onlyService(t, inv2).Exposures) != 0 {
		t.Error("exposures reported without checks")
	}
}

func TestChecksIgnorePagesThatAnswerEverything(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<!DOCTYPE html><html><body>Page not found</body></html>\nAPP_KEY=x\nDB_HOST=y\n")
	}))
	defer srv.Close()
	s := testScope(t, nil, []string{"127.0.0.1"}, []int{portOf(t, srv.URL)}, nil)
	inv, err := Run(context.Background(), Options{Scope: s, Engine: engine(t), Timeout: 2 * time.Second, Checks: true})
	if err != nil {
		t.Fatal(err)
	}
	if x := onlyService(t, inv).Exposures; len(x) != 0 {
		t.Errorf("a site answering every path with a page produced exposures: %+v", x)
	}
}

// nextSite serves a Next.js App Router page that names its version only in
// one of its scripts, as Next.js does.
func nextSite(t *testing.T, runtime string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Vary", "RSC, Next-Router-State-Tree, Next-Router-Prefetch")
			io.WriteString(w, `<html><head><title>Shop</title><script src="/_next/static/chunks/a.js" async></script>`+
				`<script src="/_next/static/chunks/b.js?dpl=1" async></script></head>`+
				`<body><script>(self.__next_f=self.__next_f||[]).push([0])</script></body></html>`)
		case "/_next/static/chunks/a.js":
			io.WriteString(w, `(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[1],{}]);`)
		case "/_next/static/chunks/b.js":
			io.WriteString(w, runtime)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestChecksReadNextVersionFromScripts(t *testing.T) {
	for _, c := range []struct {
		runtime, want string
		checks        bool
	}{
		{`e.exports=n,window.next={version:"16.4.5",appDir:!0};`, "16.4.5", true},
		{`window.next = { version: "15.2.3", appDir: true };`, "15.2.3", true},
		// Without -checks the scripts are not read.
		{`window.next={version:"16.4.5",appDir:!0};`, "", false},
		// A pre-release cannot be placed in NVD's ranges, and another
		// library's version is not Next.js's.
		{`window.next={version:"15.6.0-canary.57",appDir:!0};`, "", true},
		{`var React={version:"19.2.0"};window.nextTick={version:"1.0.0"};`, "", true},
	} {
		srv := nextSite(t, c.runtime)
		s := testScope(t, nil, []string{"127.0.0.1"}, []int{portOf(t, srv.URL)}, nil)
		inv, err := Run(context.Background(), Options{Scope: s, Engine: engine(t), Timeout: 2 * time.Second, Checks: c.checks})
		if err != nil {
			t.Fatal(err)
		}
		var next *inventory.Technology
		for _, tech := range onlyService(t, inv).Technologies {
			if tech.ID == "nextjs-app-router" {
				next = &tech
			}
		}
		if next == nil {
			t.Fatalf("%s: Next.js not recognised: %+v", c.runtime, onlyService(t, inv).Technologies)
		}
		if next.Version != c.want {
			t.Errorf("%s (checks %v): version %q, want %q", c.runtime, c.checks, next.Version, c.want)
		}
		if c.want != "" && !strings.Contains(next.Evidence, "version from /_next/static/chunks/b.js") || strings.Contains(next.Evidence, "dpl=") {
			t.Errorf("%s: evidence %q", c.runtime, next.Evidence)
		}
	}
}
