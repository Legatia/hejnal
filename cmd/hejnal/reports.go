package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Legatia/hejnal/engine"
	"github.com/Legatia/hejnal/fingerprint"
	"github.com/Legatia/hejnal/kev"
	"github.com/Legatia/hejnal/report"
	"github.com/Legatia/hejnal/state"
)

func (a *app) cmdReport(args []string) error {
	kind := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		kind, args = args[0], args[1:]
	}
	o := &options{}
	fs := a.flags("report", "fixlist|overview|evidence|nis2|monthly|weekly [flags]",
		"Print a report from the saved runs:\n  fixlist   what to fix, most urgent first\n  overview  one page for decision-makers, as HTML to view, print or save as PDF\n  evidence  proof of monitoring and time to fix, for insurers, auditors and\n            customers' security questionnaires (HTML)\n  nis2      a draft NIS2 early warning, for use if a system was compromised\n  monthly   exposure, new and fixed items and time to fix for one month\n  weekly    the last 7 days: checks, newly exploited flaws, fixed, open, coming up")
	o.stateFlags(fs)
	o.cacheFlag(fs)
	o.langFlag(fs)
	fs.StringVar(&o.out, "o", "", "write to this file instead of standard output")
	month := fs.String("month", "", "month for the monthly report, as YYYY-MM (default: this month)")
	by := fs.String("by", "", "who prepared the overview or evidence, such as your company's name")
	since := fs.String("since", "", "first day the evidence covers, as YYYY-MM-DD (default: all saved runs)")
	format := fs.String("format", "html", "evidence format: html, or json for compliance tools")
	if kind == "" {
		// Allow flags before the report name.
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return err
			}
			return errUsage
		}
		if fs.NArg() > 0 {
			kind, args = fs.Arg(0), fs.Args()[1:]
		} else {
			args = nil
		}
	}
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	switch kind {
	case "fixlist", "overview", "evidence", "nis2", "monthly", "weekly":
	case "":
		fs.Usage()
		return errUsage
	default:
		return fmt.Errorf("unknown report %q: use fixlist, overview, evidence, nis2, monthly or weekly", kind)
	}
	store := state.Store{Dir: o.stateDir}
	snap, err := store.LoadFindings()
	if err != nil {
		return err
	}
	if err := store.MarkAccepted(snap, a.now()); err != nil {
		return err
	}
	m := engine.Meta(snap, o.lang)
	var buf bytes.Buffer
	switch kind {
	case "fixlist":
		err = report.FixList(&buf, snap.Findings, m)
	case "overview":
		inv, ierr := store.LoadInventory()
		if ierr != nil && !errors.Is(ierr, state.ErrNoInventory) {
			return ierr
		}
		history, herr := store.History()
		if herr != nil {
			return herr
		}
		err = report.Overview(&buf, snap.Findings, m, report.OverviewOptions{By: *by, Inventory: inv, History: history})
	case "evidence":
		var from time.Time
		if *since != "" {
			if from, err = time.Parse("2006-01-02", *since); err != nil {
				return fmt.Errorf("-since must look like 2026-01-31")
			}
		}
		history, herr := store.History()
		if herr != nil {
			return herr
		}
		systems, serr := store.LoadSystems()
		if serr != nil {
			return serr
		}
		eo := report.EvidenceOptions{Since: from, By: *by, Systems: systems}
		switch *format {
		case "html":
			err = report.Evidence(&buf, history, m, eo)
		case "json":
			err = report.EvidenceJSON(&buf, history, m, eo)
		default:
			return fmt.Errorf("-format must be html or json")
		}
	case "nis2":
		err = report.NIS2(&buf, snap.Findings, m)
	case "monthly":
		at := a.now().UTC()
		if *month != "" {
			if at, err = time.Parse("2006-01", *month); err != nil {
				return fmt.Errorf("-month must look like 2026-11")
			}
		}
		history, herr := store.History()
		if herr != nil {
			return herr
		}
		err = report.Monthly(&buf, history, at, m)
	case "weekly":
		history, herr := store.History()
		if herr != nil {
			return herr
		}
		// Reports work offline: the dates flaws were listed come from the
		// cached catalogs, if there are any.
		o.offline = true
		var cat *kev.Catalog
		if e, eerr := a.engine(o); eerr == nil {
			if cat, eerr = e.Catalog(context.Background()); eerr != nil {
				cat = nil
			}
		}
		inv, ierr := store.LoadInventory()
		if ierr != nil && !errors.Is(ierr, state.ErrNoInventory) {
			return ierr
		}
		buf.WriteString(report.Weekly(history, cat, inv, time.Time{}, a.now(), m))
	}
	if err != nil {
		return err
	}
	return a.output(o.out, buf.Bytes())
}

// cmdSystems prints the systems on record, or the history of one of them.
func (a *app) cmdSystems(args []string) error {
	host := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		host, args = args[0], args[1:]
	}
	o := &options{}
	fs := a.flags("systems", "[host] [flags]",
		"List the systems Hejnal has seen, or print the history of one: when it first\nanswered, the versions it showed, the items found on it and when they were\nfixed, and when it went away.")
	o.stateFlags(fs)
	o.langFlag(fs)
	fs.StringVar(&o.out, "o", "", "write to this file instead of standard output")
	format := fs.String("format", "md", "output format: md for Markdown, or json")
	if host == "" {
		// Allow flags before the host.
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return err
			}
			return errUsage
		}
		if fs.NArg() > 0 {
			host, args = fs.Arg(0), fs.Args()[1:]
		} else {
			args = nil
		}
	}
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	if *format != "md" && *format != "json" {
		return fmt.Errorf("-format must be md or json")
	}
	store := state.Store{Dir: o.stateDir}
	records, err := store.LoadSystems()
	if err != nil {
		return err
	}
	history, err := store.History()
	if err != nil {
		return err
	}
	// The history is as of the latest run, when there is one.
	m := report.Meta{GeneratedAt: a.now(), Lang: o.lang}
	switch snap, err := store.LoadFindings(); {
	case err == nil:
		m = engine.Meta(snap, o.lang)
	case !errors.Is(err, state.ErrNoFindings):
		return err
	}
	var buf bytes.Buffer
	if host == "" {
		systems := report.Systems(records, history, o.lang)
		if *format == "json" {
			err = writeIndented(&buf, struct {
				Systems []report.System `json:"systems"`
			}{append([]report.System{}, systems...)})
		} else {
			err = report.SystemList(&buf, systems, m)
		}
	} else {
		sys, ok := report.SystemHistory(host, records, history, o.lang)
		if !ok {
			return fmt.Errorf("no system %q on record: `hejnal systems` lists the ones Hejnal has seen", report.CleanHost(host))
		}
		if *format == "json" {
			err = writeIndented(&buf, sys)
		} else {
			err = report.SystemReport(&buf, sys, m)
		}
	}
	if err != nil {
		return err
	}
	return a.output(o.out, buf.Bytes())
}

func writeIndented(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// output writes to standard output, or to a file readable only by its owner.
func (a *app) output(path string, data []byte) error {
	if path == "" {
		_, err := a.stdout.Write(data)
		return err
	}
	if err := writeFile(path, data); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Wrote %s.\n", path)
	return nil
}

func writeFile(path string, data []byte) error { return state.WriteFile(path, data) }

func (a *app) cmdRules(args []string) error {
	fs := a.flags("rules", "", "List the products Hejnal recognises.")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	eng, err := fingerprint.Default()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPRODUCT\tCATEGORY\tSEEN IN\tADMIN")
	rules := eng.Rules()
	greetings := 0
	for _, r := range rules {
		admin := ""
		if r.Admin {
			admin = "yes"
		}
		var seen []string
		if len(r.Headers)+len(r.Cookies)+len(r.Body) > 0 || r.Path != "" || r.Title != "" || r.Generator != "" {
			seen = append(seen, "web page")
		}
		if len(r.Banners) > 0 {
			seen = append(seen, "greeting")
			greetings++
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Name, r.Category, strings.Join(seen, ", "), admin)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "\n%d products. Rules live in fingerprint/rules.json.\n", len(rules))
	if greetings > 0 {
		fmt.Fprintln(a.stdout, "Greetings are read from mail, file-transfer and other non-web services on the ports in your scope.")
	}
	return nil
}
