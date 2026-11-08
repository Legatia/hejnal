package report

import (
	"encoding/json"
	"io"
	"math"
	"time"

	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

// EvidenceRecord is the evidence report as data, for compliance tools and
// audit workpapers: the same runs, exposures and controls as the page.
type EvidenceRecord struct {
	Schema       string    `json:"schema"`
	Organization string    `json:"organization"`
	GeneratedAt  time.Time `json:"generatedAt"`
	PreparedBy   string    `json:"preparedBy,omitempty"`
	Period       struct {
		From time.Time `json:"from"`
		To   time.Time `json:"to"`
	} `json:"period"`
	Runs struct {
		Count             int     `json:"count"`
		AverageDaysApart  float64 `json:"averageDaysApart"`
		LongestGapDays    float64 `json:"longestGapDays"`
		UnreachableRuns   int     `json:"unreachableRuns,omitempty"`
		LatestKEVVersion  string  `json:"latestKevVersion,omitempty"`
		LatestEUVDDate    string  `json:"latestEuvdDate,omitempty"`
		LatestFlawsListed int     `json:"latestFlawsListed,omitempty"`
	} `json:"runs"`
	Exploited []EvidenceItem `json:"exploited"`
	Other     []EvidenceItem `json:"other"`
	Controls  []struct {
		Framework string `json:"framework"`
		ID        string `json:"id"`
		Topic     string `json:"topic"`
		Support   string `json:"support"`
	} `json:"controls"`
	Fingerprint string `json:"fingerprint"`
}

// EvidenceItem is one item's exposure.
type EvidenceItem struct {
	ID          string     `json:"id"`
	Kind        match.Kind `json:"kind"`
	Title       string     `json:"title"`
	Host        string     `json:"host"`
	Port        int        `json:"port,omitempty"`
	Severity    string     `json:"severity"`
	CVEs        []string   `json:"cves,omitempty"`
	Listed      string     `json:"listedAsExploited,omitempty"`
	FirstSeen   time.Time  `json:"firstSeen"`
	Fixed       *time.Time `json:"fixed,omitempty"`
	DaysExposed float64    `json:"daysExposed"`
	// BeforeMonitoring is set when the item was there in the first run.
	BeforeMonitoring bool              `json:"beforeMonitoring,omitempty"`
	Status           string            `json:"status"` // open, fixed or accepted
	Acceptance       *match.Acceptance `json:"acceptance,omitempty"`
}

// EvidenceSchema names the EvidenceRecord format.
const EvidenceSchema = "https://github.com/Legatia/hejnal/evidence/v1"

// EvidenceJSON writes the evidence as an EvidenceRecord.
func EvidenceJSON(w io.Writer, history []*state.Snapshot, m Meta, o EvidenceOptions) error {
	tr := newTranslator(m.Lang)
	rec := EvidenceRecord{Schema: EvidenceSchema, Organization: m.Organization, GeneratedAt: m.GeneratedAt.UTC(), PreparedBy: o.By,
		Exploited: []EvidenceItem{}, Other: []EvidenceItem{}}
	var in []*state.Snapshot
	for _, s := range history {
		if o.Since.IsZero() || !s.GeneratedAt.Before(o.Since) {
			in = append(in, s)
		}
	}
	runs, unreachable, exps := Exposures(in)
	for _, c := range evidenceControls {
		rec.Controls = append(rec.Controls, struct {
			Framework string `json:"framework"`
			ID        string `json:"id"`
			Topic     string `json:"topic"`
			Support   string `json:"support"`
		}{c.framework, c.id, tr("ev.c." + c.key + ".topic"), tr("ev.c." + c.key + ".how")})
	}
	if len(runs) > 0 {
		first, last := runs[0], runs[len(runs)-1]
		rec.Period.From, rec.Period.To = first.GeneratedAt.UTC(), last.GeneratedAt.UTC()
		rec.Runs.Count, rec.Runs.UnreachableRuns = len(runs), unreachable
		rec.Runs.LatestKEVVersion, rec.Runs.LatestEUVDDate, rec.Runs.LatestFlawsListed = last.KEVVersion, last.EUVDDate, last.KEVFlaws
		for i := 1; i < len(runs); i++ {
			rec.Runs.LongestGapDays = max(rec.Runs.LongestGapDays, runs[i].GeneratedAt.Sub(runs[i-1].GeneratedAt).Hours()/24)
		}
		if len(runs) > 1 {
			rec.Runs.AverageDaysApart = last.GeneratedAt.Sub(first.GeneratedAt).Hours() / 24 / float64(len(runs)-1)
		}
		rec.Runs.AverageDaysApart, rec.Runs.LongestGapDays = round1(rec.Runs.AverageDaysApart), round1(rec.Runs.LongestGapDays)
		rec.Fingerprint = runsFingerprint(runs)
		for _, e := range exps {
			g := e.Group
			it := EvidenceItem{ID: g.ID(), Kind: g.Kind, Title: itemTitle(tr, g), Host: g.Host, Port: g.Port,
				Severity: string(g.Severity), Listed: e.Listed, FirstSeen: e.FirstSeen.UTC(),
				DaysExposed: round1(e.Days(last.GeneratedAt)), BeforeMonitoring: e.AtStart, Status: "open"}
			if g.Kind == match.KindKEV {
				for _, f := range g.Findings {
					it.CVEs = append(it.CVEs, f.CVE)
				}
			}
			switch {
			case e.Accepted && e.Open():
				it.Status, it.Acceptance = "accepted", g.Acceptance()
			case !e.Open():
				fixed := e.Fixed.UTC()
				it.Status, it.Fixed = "fixed", &fixed
			}
			if g.Kind == match.KindKEV {
				rec.Exploited = append(rec.Exploited, it)
			} else {
				rec.Other = append(rec.Other, it)
			}
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rec)
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
