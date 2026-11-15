package engine

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/match"
)

// shop runs nginx 1.24, past its end of support, and PHP 8.2, whose support
// ends on 31 December 2026.
func shop(techs ...inventory.Technology) *inventory.Inventory {
	if techs == nil {
		techs = []inventory.Technology{
			{ID: "nginx", Name: "nginx", Category: "server", Version: "1.24.0", Evidence: "header Server: nginx/1.24.0"},
			{ID: "php", Name: "PHP", Category: "language", Version: "8.2.10", Evidence: "header X-Powered-By: PHP/8.2.10"},
		}
	}
	return &inventory.Inventory{Organization: "Sklep", Assets: []inventory.Asset{{Host: "shop.example.com", Services: []inventory.Service{{
		Port: 443, Scheme: "https", URL: "https://shop.example.com/", Technologies: techs,
	}}}}}
}

func eolKinds(fs []match.Finding) []string {
	var out []string
	for _, f := range fs {
		if f.Kind == match.KindEOL {
			out = append(out, f.Key)
		}
	}
	slices.Sort(out)
	return out
}

func TestMatchChecksEndOfSupport(t *testing.T) {
	srv := newFeedServer(t)
	dir := t.TempDir()
	var logs []string
	e, err := New(srv.config(dir, &logs))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := e.Match(context.Background(), shop())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"eol|shop.example.com|443|nginx|1.24", "eol|shop.example.com|443|php|8.2"}
	if got := eolKinds(snap.Findings); !slices.Equal(got, want) {
		t.Errorf("end-of-support findings %v, want %v", got, want)
	}
	if snap.EOLDate != "2026-11-14" || Meta(snap, "en").EOLDate != "2026-11-14" {
		t.Errorf("dates of %q", snap.EOLDate)
	}
	if !slices.ContainsFunc(logs, func(l string) bool {
		return strings.Contains(l, "end-of-support dates from endoflife.date (7 products)")
	}) {
		t.Errorf("download not logged: %q", logs)
	}
	if _, err := os.Stat(filepath.Join(dir, "cache", "eol.json")); err != nil {
		t.Errorf("dates not cached: %v", err)
	}
	// The saved copy is used for a day.
	if _, err := e.Match(context.Background(), shop()); err != nil {
		t.Fatal(err)
	}
	if n := srv.count("/eol"); n != 1 {
		t.Errorf("%d downloads, want 1", n)
	}

	// Offline, the saved copy is all there is.
	cfg := srv.config(dir, &logs)
	cfg.Offline, cfg.KEVFile = true, "../testdata/kev_sample.json"
	offline, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	snap, err = offline.Match(context.Background(), shop())
	if err != nil {
		t.Fatal(err)
	}
	if got := eolKinds(snap.Findings); !slices.Equal(got, want) || srv.count("/eol") != 1 {
		t.Errorf("offline: %v after %d downloads", got, srv.count("/eol"))
	}
}

func TestEndOfSupportIsOptional(t *testing.T) {
	srv := newFeedServer(t)
	var logs []string

	// Turned off: nothing is downloaded or found.
	cfg := srv.config(t.TempDir(), &logs)
	cfg.NoEOL = true
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := e.Match(context.Background(), shop())
	if err != nil {
		t.Fatal(err)
	}
	if got := eolKinds(snap.Findings); len(got) > 0 || snap.EOLDate != "" || srv.count("/eol") != 0 {
		t.Errorf("with NoEOL: %v, dates of %q, %d downloads", got, snap.EOLDate, srv.count("/eol"))
	}

	// No product shows a version the dates apply to: nothing to download.
	e, err = New(srv.config(t.TempDir(), &logs))
	if err != nil {
		t.Fatal(err)
	}
	packaged := inventory.Technology{ID: "nginx", Name: "nginx", Category: "server", Version: "1.18.0", Packaged: true}
	if _, err := e.Match(context.Background(), shop(packaged, inventory.Technology{ID: "nginx", Name: "nginx", Category: "server"})); err != nil {
		t.Fatal(err)
	}
	if n := srv.count("/eol"); n != 0 {
		t.Errorf("%d downloads for an inventory without versions to date", n)
	}

	// endoflife.date is down and nothing is saved: the run goes on without.
	cfg = srv.config(t.TempDir(), &logs)
	cfg.EOLURL = srv.URL + "/missing"
	e, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	snap, err = e.Match(context.Background(), shop())
	if err != nil {
		t.Fatal(err)
	}
	if got := eolKinds(snap.Findings); len(got) > 0 {
		t.Errorf("findings without dates: %v", got)
	}
	if !slices.ContainsFunc(logs, func(l string) bool { return strings.Contains(l, "continuing without them") }) {
		t.Errorf("failure not logged: %q", logs)
	}
}
