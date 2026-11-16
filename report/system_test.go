package report

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

func sysDay(d string) time.Time {
	t, _ := time.Parse(time.DateOnly, d)
	return t.Add(7 * time.Hour)
}

// systemRecords is a shop on two ports whose nginx was upgraded on 10
// November, a VPN gateway that went away on 12 November, and a host that
// answered on 2 November only.
func systemRecords() []inventory.Record {
	nginx := inventory.Product{ID: "nginx", Name: "nginx", Version: "1.30.6"}
	php := inventory.Product{ID: "php", Name: "PHP", Version: "8.3.14"}
	upgraded := []inventory.Event{{At: sysDay("2026-11-10"), Kind: inventory.EventVersion, Product: "nginx", From: "1.24.0", To: "1.30.6"}}
	gone := sysDay("2026-11-12")
	return []inventory.Record{
		{Host: "shop.example.com", Port: 80, Source: "domain", Products: []inventory.Product{nginx},
			FirstSeen: sysDay("2026-10-20"), LastSeen: sysDay("2026-11-28"), Events: upgraded},
		{Host: "shop.example.com", Port: 443, Source: "domain", Products: []inventory.Product{nginx, php},
			FirstSeen: sysDay("2026-10-20"), LastSeen: sysDay("2026-11-28"), Events: slices.Concat(upgraded, []inventory.Event{
				{At: sysDay("2026-11-10"), Kind: inventory.EventVersion, Product: "PHP", From: "8.3.12", To: "8.3.14"},
				{At: sysDay("2026-11-28"), Kind: "later-kind"},
			})},
		{Host: "shop.example.com", Port: 8443, Source: "domain", FirstSeen: sysDay("2026-11-02"), LastSeen: sysDay("2026-11-10"), Missed: 1},
		{Host: "vpn.example.com", Port: 443, Source: "ct", Products: []inventory.Product{{ID: "fortinet-fortigate", Name: "Fortinet FortiGate SSL VPN"}},
			FirstSeen: sysDay("2026-10-20"), LastSeen: sysDay("2026-11-02"), Missed: 2, Gone: &gone,
			Events: []inventory.Event{{At: gone, Kind: inventory.EventGone}}},
	}
}

// systemRuns has a PHP flaw on the shop from the first run, fixed by the
// run of 10 November, a second one found on 10 November and still open, an
// accepted Jenkins panel on another port of the shop, and a flaw on the VPN
// gateway that a version ruled out.
func systemRuns() []*state.Snapshot {
	old := kevFinding("shop.example.com", "CVE-2024-4577", match.High)
	old.Confidence = match.ConfidenceVersion
	fresh := match.Finding{Key: "tls-expiring|shop.example.com|443", Kind: match.KindTLSExpiring, Host: "shop.example.com", Port: 443,
		Subject: "shop.example.com", Score: 40, Severity: match.Medium, Confidence: match.ConfidenceObserved}
	panel := match.Finding{Key: "admin-exposed|shop.example.com|8443|jenkins", Kind: match.KindAdminExposed, Host: "shop.example.com",
		Port: 8443, TechID: "jenkins", Technology: "Jenkins", Score: 50, Severity: match.Medium, Confidence: match.ConfidenceObserved,
		Accepted: &match.Acceptance{Item: "a1b2c3d4", Reason: "office only", By: "IT lead", Until: "2027-04-01"}}
	vpn := match.Finding{Key: "kev|vpn.example.com|443|CVE-2018-13379", Kind: match.KindKEV, Host: "vpn.example.com", Port: 443,
		TechID: "fortinet-fortigate", Technology: "Fortinet FortiGate SSL VPN", CVE: "CVE-2018-13379", Score: 60, Severity: match.Medium,
		Confidence: match.ConfidenceProduct}
	ruled := vpn
	ruled.Confidence = match.ConfidenceRuledOut
	return []*state.Snapshot{
		snap("2026-10-20", 2, old, vpn),
		snap("2026-11-02", 2, old, panel, ruled),
		snap("2026-11-10", 2, fresh, panel),
		snap("2026-11-28", 1, fresh, panel),
	}
}

func TestSystems(t *testing.T) {
	all := Systems(systemRecords(), systemRuns(), "en")
	if len(all) != 2 || all[0].Host != "shop.example.com" || all[1].Host != "vpn.example.com" {
		t.Fatalf("systems %+v", all)
	}
	shop, vpn := all[0], all[1]
	if shop.Gone != nil || shop.Source != "domain" || !shop.FirstSeen.Equal(sysDay("2026-10-20")) || !shop.LastSeen.Equal(sysDay("2026-11-28")) {
		t.Errorf("shop %+v", shop)
	}
	if got := shop.Counts; got != (SystemCounts{Found: 3, Fixed: 1, Open: 1, Accepted: 1}) {
		t.Errorf("shop items %+v", got)
	}
	if len(shop.Services) != 3 || shop.Services[2].Port != 8443 || shop.Items != nil || shop.Events != nil {
		t.Errorf("shop in a list %+v", shop)
	}
	// The flaw a version ruled out was never confirmed.
	if vpn.Gone == nil || !vpn.Gone.Equal(sysDay("2026-11-12")) || vpn.Counts != (SystemCounts{}) {
		t.Errorf("vpn %+v", vpn)
	}
}

func TestSystemHistory(t *testing.T) {
	if _, ok := SystemHistory("unknown.example.com", systemRecords(), systemRuns(), "en"); ok {
		t.Error("history of a host that is not on record")
	}
	s, ok := SystemHistory(" Shop.Example.com. ", systemRecords(), systemRuns(), "en")
	if !ok || s.Host != "shop.example.com" {
		t.Fatalf("history %v %+v", ok, s)
	}
	var statuses []string
	for _, it := range s.Items {
		statuses = append(statuses, it.Status)
	}
	if !slices.Equal(statuses, []string{"open", "accepted", "fixed"}) || s.Items[2].Fixed == nil || !s.Items[2].BeforeMonitoring {
		t.Errorf("items %+v", s.Items)
	}
	var b strings.Builder
	if err := SystemReport(&b, s, meta("en")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# System history: shop.example.com",
		"- **First seen:** 2026-10-20",
		"- **Last seen:** 2026-11-28",
		"- **How it was found:** a domain in the scope",
		"- **Status:** answering",
		"- **Items:** found: 3 · fixed: 1 · open: 1 · accepted: 1",
		"| 443 | nginx 1.30.6, PHP 8.3.14 | 2026-10-20 | 2026-11-28 | answering |",
		"| 8443 | no product recognised | 2026-11-02 | 2026-11-10 | no answer in the latest check |",
		"| PHP on shop.example.com:443 | `" + match.ItemID("kev|shop.example.com|443|php") + "` | high | 2026-10-20 | 2026-11-10 | Fixed |",
		"- 2026-10-20 · First answer · port 80, 443\n",
		"- 2026-10-20 · Found in the first check, so it was there before: PHP on shop.example.com:443 · high",
		"- 2026-11-02 · First answer · port 8443\n",
		"- 2026-11-02 · Found: Jenkins admin interface reachable on shop.example.com:8443 · medium",
		"- 2026-11-10 · PHP 8.3.12 → 8.3.14 · port 443\n",
		"- 2026-11-10 · nginx 1.24.0 → 1.30.6 · port 80, 443\n",
		"- 2026-11-10 · Fixed: PHP on shop.example.com:443 · high · `" + match.ItemID("kev|shop.example.com|443|php") + "` · seen for 21.0 days",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "later-kind") {
		t.Errorf("an event kind this version does not know is shown:\n%s", out)
	}
	// Events are in the order they happened.
	if first, fixed := strings.Index(out, "First answer · port 80, 443"), strings.Index(out, "· Fixed:"); first < 0 || fixed < first {
		t.Errorf("timeline out of order:\n%s", out)
	}
}

func TestSystemHistoryGoneAndPolish(t *testing.T) {
	s, ok := SystemHistory("vpn.example.com", systemRecords(), systemRuns(), "pl")
	if !ok {
		t.Fatal("no history")
	}
	var b strings.Builder
	if err := SystemReport(&b, s, meta("pl")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# Historia systemu: vpn.example.com",
		"- **Stan:** zniknął 2026-11-12",
		"- **Jak go znaleziono:** znaleziony w logu certyfikatów",
		"- 2026-11-02 · Wykluczono na podstawie wersji: ",
		"- 2026-11-12 · Brak odpowiedzi w dwóch sprawdzeniach z rzędu: uznano, że zniknął · port 443",
		"| Wykluczone na podstawie wersji |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestSystemList(t *testing.T) {
	var b strings.Builder
	if err := SystemList(&b, Systems(systemRecords(), systemRuns(), "en"), meta("en")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# Systems: Przykład &lt;Sp. z o.o.&gt;",
		"**Systems: 2 · answering: 1 · gone: 1**",
		"| shop.example.com | 80, 443, 8443 | nginx 1.30.6, PHP 8.3.14 | 2026-10-20 | 2026-11-28 | 1 | answering |",
		"| vpn.example.com | 443 | Fortinet FortiGate SSL VPN | 2026-10-20 | 2026-11-02 | 0 | gone since 2026-11-12 |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	b.Reset()
	if err := SystemList(&b, nil, meta("en")); err != nil || !strings.Contains(b.String(), "No systems on record yet") {
		t.Errorf("empty list: %v\n%s", err, b.String())
	}
}

func TestSystemTimelineIsCapped(t *testing.T) {
	r := inventory.Record{Host: "busy.example.com", Port: 443, FirstSeen: sysDay("2026-01-01"), LastSeen: sysDay("2026-11-01")}
	for i := range 80 {
		r.Events = append(r.Events, inventory.Event{At: r.FirstSeen.AddDate(0, 0, i+1), Kind: inventory.EventVersion, Product: "nginx", From: "1", To: "2"})
	}
	s, _ := SystemHistory("busy.example.com", []inventory.Record{r}, nil, "en")
	var b strings.Builder
	if err := SystemReport(&b, s, meta("en")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "Earlier events not shown: 21.") || strings.Count(out, "nginx 1 → 2") != maxTimeline || strings.Contains(out, "First answer") {
		t.Errorf("timeline:\n%s", out)
	}
}

func TestEvidenceListsSystems(t *testing.T) {
	var b strings.Builder
	o := EvidenceOptions{Systems: systemRecords()}
	if err := Evidence(&b, systemRuns(), meta("en"), o); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"<h3>Systems on record</h3>",
		`<td class="item-title">shop.example.com</td><td class="num">2026-10-20</td><td class="num">2026-11-28</td><td class="num">3</td><td class="num">1</td><td class="num">1</td><td class="num">1</td>`,
		"gone since 2026-11-12",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// A system that stopped answering before the period is left out.
	b.Reset()
	o.Since = sysDay("2026-11-05")
	if err := Evidence(&b, systemRuns(), meta("en"), o); err != nil {
		t.Fatal(err)
	}
	if out := b.String(); strings.Contains(out, "vpn.example.com</td>") || !strings.Contains(out, "shop.example.com</td>") {
		t.Errorf("systems in a later period:\n%s", out)
	}
	// Without the record, the evidence has no such section.
	b.Reset()
	if err := Evidence(&b, systemRuns(), meta("en"), EvidenceOptions{}); err != nil || strings.Contains(b.String(), "Systems on record") {
		t.Errorf("section without records: %v", err)
	}

	b.Reset()
	if err := EvidenceJSON(&b, systemRuns(), meta("en"), EvidenceOptions{Systems: systemRecords()}); err != nil {
		t.Fatal(err)
	}
	var rec EvidenceRecord
	if err := json.Unmarshal([]byte(b.String()), &rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Systems) != 2 || rec.Systems[0].Counts.Found != 3 || rec.Systems[1].Gone == nil || rec.Systems[0].Events != nil {
		t.Errorf("systems in the record %+v", rec.Systems)
	}
}
