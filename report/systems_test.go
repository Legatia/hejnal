package report

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/inventory"
)

func systemChanges() inventory.Changes {
	first := now.AddDate(0, -3, 0)
	gone := now
	rec := func(host string, port int, source string, products ...inventory.Product) inventory.Record {
		return inventory.Record{Host: host, Port: port, Source: source, Products: products, FirstSeen: now, LastSeen: now}
	}
	grafana := inventory.Product{ID: "grafana", Name: "Grafana", Version: "10.2.3"}
	back := rec("vpn.example.com", 443, "domain")
	back.FirstSeen = first
	return inventory.Changes{
		New: []inventory.Record{
			rec("api.example.com", 80, "ct", grafana),
			rec("api.example.com", 443, "ct", grafana, inventory.Product{ID: "nginx", Name: "nginx"}),
			rec("bare.example.com", 8443, ""),
			back,
		},
		Gone: []inventory.Gone{
			{Record: inventory.Record{Host: "old.example.com", Port: 443, Gone: &gone}, Resolves: true},
			{Record: inventory.Record{Host: "old.example.com", Port: 80, Gone: &gone}},
			{Record: inventory.Record{Host: "retired.example.com", Port: 443, Gone: &gone}},
			{Record: inventory.Record{Host: "192.0.2.7", Port: 8443, Gone: &gone}},
		},
		Updated: []inventory.VersionChange{
			{Host: "shop.example.com", Port: 80, Product: "nginx", From: "1.24.0", To: "1.30.6", At: now},
			{Host: "shop.example.com", Port: 443, Product: "nginx", From: "1.24.0", To: "1.30.6", At: now},
		},
	}
}

func TestSystemLines(t *testing.T) {
	got := SystemLines(systemChanges(), "en")
	want := []string{
		"Systems · new: 3 · gone: 3 · updated: 1",
		"• New: api.example.com (80, 443) · Grafana 10.2.3, nginx · found in a certificate log",
		"• New: bare.example.com (8443) · no product recognised",
		"• Back: vpn.example.com (443) · answers again, first seen on " + now.AddDate(0, -3, 0).Format(time.DateOnly),
		"• Gone: old.example.com (80, 443) · no answer in the last two checks, but the name still resolves: if the system is retired, remove its DNS record",
		"• Gone: retired.example.com (443) · no answer in the last two checks, and the name no longer resolves",
		"• Gone: 192.0.2.7 (8443) · no answer in the last two checks",
		"• Updated: nginx 1.24.0 → 1.30.6 on shop.example.com (80, 443)",
	}
	if !slices.Equal(got, want) {
		t.Errorf("lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if SystemLines(inventory.Changes{}, "en") != nil {
		t.Error("lines without changes")
	}
}

func TestSystemLinesPolish(t *testing.T) {
	got := strings.Join(SystemLines(systemChanges(), "pl"), "\n")
	for _, want := range []string{
		"Systemy · nowe: 3 · zniknęły: 3 · zaktualizowane: 1",
		"• Nowy: api.example.com (80, 443) · Grafana 10.2.3, nginx · znaleziony w logu certyfikatów",
		"• Wrócił: vpn.example.com (443) · znów odpowiada",
		"• Zniknął: old.example.com (80, 443) · brak odpowiedzi w dwóch ostatnich sprawdzeniach, ale nazwa nadal się rozwiązuje: jeśli system wycofano, usuń jego rekord DNS",
		"• Zaktualizowany: nginx 1.24.0 → 1.30.6 na shop.example.com (80, 443)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestSystemLinesAreCapped(t *testing.T) {
	var ch inventory.Changes
	for i := range 14 {
		ch.New = append(ch.New, inventory.Record{Host: fmt.Sprintf("h%02d.example.com", i), Port: 443, Source: "ct", FirstSeen: now, LastSeen: now})
	}
	lines := SystemLines(ch, "en")
	if len(lines) != 1+maxSystemLines+1 || lines[0] != "Systems · new: 14 · gone: 0 · updated: 0" || !strings.Contains(lines[len(lines)-1], "4") {
		t.Errorf("lines:\n%s", strings.Join(lines, "\n"))
	}
}
