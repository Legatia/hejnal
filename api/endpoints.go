package api

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Legatia/hejnal/engine"
	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/report"
	"github.com/Legatia/hejnal/state"
	"github.com/Legatia/hejnal/version"
)

// kinds are the finding kinds the kind filter accepts.
var kinds = []match.Kind{
	match.KindKEV, match.KindTLSExpired, match.KindTLSExpiring, match.KindAdminExposed,
	match.KindExposedFile, match.KindTakeover, match.KindEmail, match.KindSecret, match.KindBreach,
}

func (h *handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}{"ok", version.Version})
}

type findingsResponse struct {
	Organization string          `json:"organization"`
	GeneratedAt  time.Time       `json:"generatedAt"`
	KEVVersion   string          `json:"kevVersion"`
	EUVDDate     string          `json:"euvdDate,omitempty"`
	EPSSDate     string          `json:"epssDate,omitempty"`
	Findings     []match.Finding `json:"findings"`
}

// findings serves GET /v1/findings: the latest findings, most urgent first,
// optionally filtered by min_severity, kind and host.
func (h *handler) findings(w http.ResponseWriter, r *http.Request) {
	q, err := params(r, "min_severity", "kind", "host")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	f, err := parseFilter(q)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	snap, ok := h.loadFindings(w)
	if !ok {
		return
	}
	out := []match.Finding{}
	for _, x := range snap.Findings {
		if f.keep(x) {
			out = append(out, x)
		}
	}
	writeJSON(w, http.StatusOK, findingsResponse{
		Organization: snap.Organization,
		GeneratedAt:  snap.GeneratedAt,
		KEVVersion:   snap.KEVVersion,
		EUVDDate:     snap.EUVDDate,
		EPSSDate:     snap.EPSSDate,
		Findings:     out,
	})
}

// groupItem is one item to fix, as in the fix list. Secrets have no host or
// port, and breaches have a domain as host and no port.
type groupItem struct {
	// ID is the item's short ID, as the fix list shows it and `hejnal
	// accept` takes it.
	ID string `json:"id"`
	// Key identifies the item across runs, for example to keep one ticket
	// per item.
	Key        string         `json:"key"`
	Kind       match.Kind     `json:"kind"`
	Host       string         `json:"host"`
	Port       int            `json:"port"`
	URL        string         `json:"url,omitempty"`
	Technology string         `json:"technology,omitempty"`
	Version    string         `json:"version,omitempty"`
	Severity   match.Severity `json:"severity"`
	Score      int            `json:"score"`
	// CVEs lists the item's known exploited flaws, most urgent first.
	CVEs []string `json:"cves"`
	// NewestDateAdded is when the newest of them was added to CISA's catalog,
	// or to ENISA's list for a flaw only ENISA lists.
	NewestDateAdded string `json:"newestDateAdded,omitempty"`
	// Forensics is set when CISA asks for forensic triage of any of them.
	Forensics bool `json:"forensics,omitempty"`
	// Expires is when the certificate of a TLS item expires.
	Expires *time.Time `json:"expires,omitempty"`
	// Accepted says who accepted an accepted item, why and until when.
	Accepted *match.Acceptance `json:"accepted,omitempty"`
	// AcceptanceExpired is set on an item that is open again because its
	// acceptance expired.
	AcceptanceExpired *match.Acceptance `json:"acceptanceExpired,omitempty"`
}

type severityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

func (c *severityCounts) add(s match.Severity) {
	switch s {
	case match.Critical:
		c.Critical++
	case match.High:
		c.High++
	case match.Medium:
		c.Medium++
	case match.Low:
		c.Low++
	}
}

type groupsResponse struct {
	Organization string         `json:"organization"`
	GeneratedAt  time.Time      `json:"generatedAt"`
	KEVVersion   string         `json:"kevVersion"`
	EUVDDate     string         `json:"euvdDate,omitempty"`
	Counts       severityCounts `json:"counts"`
	Groups       []groupItem    `json:"groups"`
	// AcceptedGroups are the items people accepted with `hejnal accept`.
	// They are not items to fix until the acceptance expires; an item with
	// new findings since is also in Groups, with the new ones.
	AcceptedGroups []groupItem `json:"acceptedGroups"`
	// RuledOut counts the findings left out because the version check shows
	// the flaw is fixed in the version seen.
	RuledOut int `json:"ruledOut"`
}

// groups serves GET /v1/groups: the items to fix, as in the fix list, most
// urgent first, and the accepted items. Flaws the version check rules out are
// not items to fix.
func (h *handler) groups(w http.ResponseWriter, r *http.Request) {
	q, err := params(r, "min_severity")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	minSev, err := match.ParseSeverity(q.Get("min_severity"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	snap, ok := h.loadFindings(w)
	if !ok {
		return
	}
	active := match.Active(snap.Findings)
	resp := groupsResponse{
		Organization:   snap.Organization,
		GeneratedAt:    snap.GeneratedAt,
		KEVVersion:     snap.KEVVersion,
		EUVDDate:       snap.EUVDDate,
		Groups:         []groupItem{},
		AcceptedGroups: []groupItem{},
		RuledOut:       len(snap.Findings) - len(active),
	}
	for _, g := range match.Groups(match.Open(snap.Findings)) {
		if g.Severity.Rank() < minSev.Rank() {
			continue
		}
		resp.Groups = append(resp.Groups, newGroupItem(g))
		resp.Counts.add(g.Severity)
	}
	_, accepted := match.SplitAccepted(snap.Findings)
	for _, g := range match.Groups(accepted) {
		if g.Severity.Rank() >= minSev.Rank() {
			resp.AcceptedGroups = append(resp.AcceptedGroups, newGroupItem(g))
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func newGroupItem(g match.Group) groupItem {
	item := groupItem{
		ID:              g.ID(),
		Key:             g.Key,
		Kind:            g.Kind,
		Host:            g.Host,
		Port:            g.Port,
		URL:             g.URL,
		Technology:      g.Technology,
		Version:         g.Version,
		Severity:        g.Severity,
		Score:           g.Score,
		CVEs:            []string{},
		NewestDateAdded: g.Newest(),
		Forensics:       g.Forensics(),
	}
	item.Accepted, item.AcceptanceExpired = g.Acceptance(), g.ExpiredAcceptance()
	for _, f := range g.Findings {
		if f.CVE != "" {
			item.CVEs = append(item.CVEs, f.CVE)
		}
		if f.Expires != nil && item.Expires == nil {
			item.Expires = f.Expires
		}
	}
	return item
}

// inventory serves GET /v1/inventory: the hosts, services and products the
// last discovery found.
func (h *handler) inventory(w http.ResponseWriter, r *http.Request) {
	if _, err := params(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	inv, err := h.store.LoadInventory()
	switch {
	case errors.Is(err, state.ErrNoInventory):
		writeError(w, http.StatusNotFound, h.notYet(err))
		return
	case err != nil:
		h.logf("api: reading the inventory: %v", err)
		writeError(w, http.StatusInternalServerError, "could not read the inventory; see the server log")
		return
	}
	if inv.Assets == nil {
		inv.Assets = []inventory.Asset{}
	}
	writeJSON(w, http.StatusOK, inv)
}

type changesResponse struct {
	Organization string    `json:"organization"`
	GeneratedAt  time.Time `json:"generatedAt"`
	KEVVersion   string    `json:"kevVersion"`
	EUVDDate     string    `json:"euvdDate,omitempty"`
	// First is true before anything was reported; then every finding the
	// version check does not rule out counts as added.
	First    bool            `json:"first"`
	Added    []match.Finding `json:"added"`
	Resolved []match.Finding `json:"resolved"`
}

// changes serves GET /v1/changes: what is new and what was resolved since the
// last report. Reading it does not mark anything as reported.
func (h *handler) changes(w http.ResponseWriter, r *http.Request) {
	if _, err := params(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	snap, ok := h.loadFindings(w)
	if !ok {
		return
	}
	ch, err := h.changeEngine.Changes(snap)
	if err != nil {
		h.logf("api: comparing with the last report: %v", err)
		writeError(w, http.StatusInternalServerError, "could not compare the findings with the last report; see the server log")
		return
	}
	writeJSON(w, http.StatusOK, changesResponse{
		Organization: snap.Organization,
		GeneratedAt:  snap.GeneratedAt,
		KEVVersion:   snap.KEVVersion,
		EUVDDate:     snap.EUVDDate,
		First:        ch.First,
		Added:        nonNil(ch.Added),
		Resolved:     nonNil(ch.Resolved),
	})
}

// report serves a Markdown report of the latest findings in the language
// given by the lang parameter, English by default.
func (h *handler) report(write func(io.Writer, []match.Finding, report.Meta) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q, err := params(r, "lang")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		lang := strings.ToLower(strings.TrimSpace(q.Get("lang")))
		if lang == "" {
			lang = "en"
		}
		if !report.ValidLang(lang) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown language %q: use %s", q.Get("lang"), strings.Join(report.Languages, " or ")))
			return
		}
		snap, ok := h.loadFindings(w)
		if !ok {
			return
		}
		var buf bytes.Buffer
		if err := write(&buf, snap.Findings, engine.Meta(snap, lang)); err != nil {
			h.logf("api: writing a report: %v", err)
			writeError(w, http.StatusInternalServerError, "could not write the report; see the server log")
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Language", lang)
		w.WriteHeader(http.StatusOK)
		w.Write(buf.Bytes())
	}
}

// loadFindings reads the latest findings, marked with the acceptances that
// hold now, or answers the request with an error and returns false.
func (h *handler) loadFindings(w http.ResponseWriter) (*state.Snapshot, bool) {
	snap, err := h.store.LoadFindings()
	switch {
	case errors.Is(err, state.ErrNoFindings):
		writeError(w, http.StatusNotFound, h.notYet(err))
		return nil, false
	case err != nil:
		h.logf("api: reading the findings: %v", err)
		writeError(w, http.StatusInternalServerError, "could not read the findings; see the server log")
		return nil, false
	}
	// Acceptances made since the run apply at once. The API only reads
	// them: people accept items with `hejnal accept`.
	if err := h.store.MarkAccepted(snap, h.now()); err != nil {
		h.logf("api: reading the accepted items: %v", err)
		writeError(w, http.StatusInternalServerError, "could not read the accepted items; see the server log")
		return nil, false
	}
	return snap, true
}

// notYet explains that there are no results yet and how to get them.
func (h *handler) notYet(err error) string {
	msg := err.Error()
	if h.allowRuns {
		msg += ", or start one with POST /v1/runs"
	}
	return msg
}

// params parses the query string. It rejects parameters the endpoint does
// not take and parameters given twice, so a typo cannot silently widen a
// filter.
func params(r *http.Request, allowed ...string) (url.Values, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("cannot read the query string: %v", err)
	}
	for _, k := range slices.Sorted(maps.Keys(q)) {
		switch {
		case !slices.Contains(allowed, k) && len(allowed) == 0:
			return nil, fmt.Errorf("unknown parameter %q: this endpoint takes no parameters", k)
		case !slices.Contains(allowed, k):
			return nil, fmt.Errorf("unknown parameter %q: use %s", k, strings.Join(allowed, ", "))
		case len(q[k]) > 1:
			return nil, fmt.Errorf("parameter %q is given more than once", k)
		}
	}
	return q, nil
}

type filter struct {
	minSeverity match.Severity
	kind        match.Kind
	host        string
}

func parseFilter(q url.Values) (filter, error) {
	var f filter
	var err error
	if f.minSeverity, err = match.ParseSeverity(q.Get("min_severity")); err != nil {
		return f, err
	}
	if k := match.Kind(strings.ToLower(strings.TrimSpace(q.Get("kind")))); k != "" {
		if !slices.Contains(kinds, k) {
			names := make([]string, len(kinds))
			for i, k := range kinds {
				names[i] = string(k)
			}
			return f, fmt.Errorf("unknown kind %q: use %s or %s", q.Get("kind"), strings.Join(names[:len(names)-1], ", "), names[len(names)-1])
		}
		f.kind = k
	}
	f.host = normalizeHost(q.Get("host"))
	return f, nil
}

func (f filter) keep(x match.Finding) bool {
	return x.Severity.Rank() >= f.minSeverity.Rank() &&
		(f.kind == "" || x.Kind == f.kind) &&
		(f.host == "" || x.Host == f.host)
}

// normalizeHost writes a host the way findings do: lower case, without a
// trailing dot or brackets, and IP addresses in their canonical form.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if ip, err := netip.ParseAddr(h); err == nil {
		return ip.WithZone("").Unmap().String()
	}
	return h
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
