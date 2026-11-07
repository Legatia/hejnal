package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Legatia/hejnal/engine"
	"github.com/Legatia/hejnal/fingerprint"
	"github.com/Legatia/hejnal/report"
	"github.com/Legatia/hejnal/state"
)

func (a *app) cmdReport(args []string) error {
	kind := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		kind, args = args[0], args[1:]
	}
	o := &options{}
	fs := a.flags("report", "fixlist|nis2|monthly [flags]",
		"Print a report from the saved runs:\n  fixlist  what to fix, most urgent first\n  nis2     a draft NIS2 early warning, for use if a system was compromised\n  monthly  exposure, new and fixed items and time to fix for one month")
	o.stateFlags(fs)
	o.langFlag(fs)
	fs.StringVar(&o.out, "o", "", "write to this file instead of standard output")
	month := fs.String("month", "", "month for the monthly report, as YYYY-MM (default: this month)")
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
	case "fixlist", "nis2", "monthly":
	case "":
		fs.Usage()
		return errUsage
	default:
		return fmt.Errorf("unknown report %q: use fixlist, nis2 or monthly", kind)
	}
	store := state.Store{Dir: o.stateDir}
	snap, err := store.LoadFindings()
	if err != nil {
		return err
	}
	m := engine.Meta(snap, o.lang)
	var buf bytes.Buffer
	switch kind {
	case "fixlist":
		err = report.FixList(&buf, snap.Findings, m)
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
	}
	if err != nil {
		return err
	}
	return a.output(o.out, buf.Bytes())
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
