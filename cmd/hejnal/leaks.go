package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/Legatia/hejnal/leaks"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
	"github.com/Legatia/hejnal/version"
)

const leaksUsage = `Usage:
  hejnal leaks scan [-history] [-save] [-fail-on high] <directory>...
  hejnal leaks breaches [-scope scope.json] [-accounts]

  scan      find secrets in source code, and in its Git history with -history
  breaches  find accounts on the scope's domains in known data breaches
            (needs a Have I Been Pwned API key in HEJNAL_HIBP_API_KEY)
`

func (a *app) cmdLeaks(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 {
		fmt.Fprint(a.stderr, leaksUsage)
		return exitError, errUsage
	}
	switch args[0] {
	case "scan":
		return a.cmdLeaksScan(ctx, args[1:])
	case "breaches":
		return exitOK, a.cmdLeaksBreaches(ctx, args[1:])
	case "-h", "-help", "--help", "help":
		fmt.Fprint(a.stdout, leaksUsage)
		return exitOK, nil
	}
	fmt.Fprintf(a.stderr, "hejnal leaks: unknown command %q\n\n%s", args[0], leaksUsage)
	return exitError, errUsage
}

func (a *app) cmdLeaksScan(ctx context.Context, args []string) (int, error) {
	o := &options{}
	fs := a.flags("leaks scan", "[flags] <directory>...",
		"Find secrets such as API keys, tokens and private keys in source code.\nSecrets are shown partly hidden and never stored in full. Mark a line that\nholds a harmless example with \"hejnal:allow\".")
	history := fs.Bool("history", false, "also scan every commit in the Git history")
	save := fs.Bool("save", false, "keep the result in the state directory, so the next run's fix list and notifications include it")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	fs.StringVar(&o.failOn, "fail-on", "high", "exit with status 2 when a secret reaches this severity: critical, high, medium or none")
	o.stateFlags(fs)
	dirs, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError, err
	}
	if len(dirs) == 0 {
		fmt.Fprintf(a.stderr, "hejnal leaks scan: name at least one directory to scan\n")
		fs.Usage()
		return exitError, errUsage
	}
	failOn, err := match.ParseSeverity(o.failOn)
	if err != nil {
		return exitError, err
	}

	store := state.Store{Dir: o.stateDir}
	var skipped []string
	opts := leaks.Options{Skipped: func(path string, size int64) { skipped = append(skipped, path) }}
	if *save {
		// A key kept with the results makes fingerprints stable across scans
		// without letting anyone check guesses of a secret against them.
		key, err := store.LeakKey()
		if err != nil {
			return exitError, err
		}
		opts.FingerprintKey = key
	}
	var found []leaks.Leak
	var roots []string
	for _, dir := range dirs {
		root, err := filepath.Abs(dir)
		if err != nil {
			return exitError, err
		}
		if st, err := os.Stat(root); err != nil {
			return exitError, err
		} else if !st.IsDir() {
			return exitError, fmt.Errorf("%s is not a directory", dir)
		}
		ls, err := leaks.ScanDir(ctx, root, opts)
		if err != nil {
			return exitError, err
		}
		if *history {
			hist, err := leaks.ScanGitHistory(ctx, root, opts)
			if err != nil {
				return exitError, err
			}
			ls = leaks.Merge(ls, hist)
		}
		// Name files after the directory, so results from several
		// repositories stay apart.
		label := rootLabel(root)
		for i := range ls {
			ls[i].File = label + "/" + ls[i].File
		}
		found = append(found, ls...)
		roots = append(roots, root)
		if *save {
			if st, err := filepath.Abs(o.stateDir); err == nil && strings.HasPrefix(st+string(filepath.Separator), root+string(filepath.Separator)) {
				fmt.Fprintf(a.stderr, "Note: the state directory %s is inside %s; keep it out of version control, for example with .gitignore.\n", o.stateDir, dir)
			}
		}
	}
	if len(skipped) > 0 {
		fmt.Fprintf(a.stderr, "%d files larger than %d MiB were not scanned, such as %s.\n", len(skipped), leaks.DefaultMaxFileSize>>20, skipped[0])
	}

	if *asJSON {
		if found == nil {
			found = []leaks.Leak{}
		}
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(found); err != nil {
			return exitError, err
		}
	} else if err := a.printLeaks(found); err != nil {
		return exitError, err
	}

	if *save {
		scan := &state.LeakScan{ScannedAt: a.now().UTC(), Roots: roots, History: *history, Leaks: found}
		if err := store.SaveLeakScan(scan); err != nil {
			return exitError, err
		}
		fmt.Fprintf(a.stderr, "Saved to %s; the next run includes it.\n", filepath.Join(o.stateDir, state.LeaksFile))
	}
	for _, l := range found {
		if failOn != "" && match.Severity(l.Severity).Rank() >= failOn.Rank() {
			return exitFindings, nil
		}
	}
	return exitOK, nil
}

// parseInterleaved parses flags that may come before or after the
// positional arguments, and returns the positional ones.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, errUsage
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func rootLabel(root string) string {
	label := filepath.Base(root)
	if label == "." || label == string(filepath.Separator) || label == "" {
		return filepath.ToSlash(root)
	}
	return label
}

func (a *app) printLeaks(ls []leaks.Leak) error {
	if len(ls) == 0 {
		fmt.Fprintln(a.stdout, "No secrets found.")
		return nil
	}
	sorted := slices.Clone(ls)
	slices.SortStableFunc(sorted, func(x, y leaks.Leak) int {
		return match.Severity(y.Severity).Rank() - match.Severity(x.Severity).Rank()
	})
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tSECRET\tWHERE\tVALUE")
	counts := map[string]int{}
	for _, l := range sorted {
		where := fmt.Sprintf("%s:%d", l.File, l.Line)
		if l.Commit != "" {
			where += " (commit " + shortHash(l.Commit) + ")"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", l.Severity, l.Description, where, l.Redacted)
		counts[l.Severity]++
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "\n%d secrets found (critical %d · high %d · medium %d). Revoke each one and issue a new one: removing it from the code is not enough.\n",
		len(ls), counts["critical"], counts["high"], counts["medium"])
	return nil
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func (a *app) cmdLeaksBreaches(ctx context.Context, args []string) error {
	o := &options{}
	fs := a.flags("leaks breaches", "[-scope scope.json] [flags]",
		"Find accounts on the scope's domains in known data breaches, using Have I\nBeen Pwned. Needs an HIBP API key with domain search in HEJNAL_HIBP_API_KEY,\nand each domain verified in your HIBP dashboard. Hejnal keeps only how many\naccounts each breach exposed; -accounts prints which, without storing them.")
	fs.StringVar(&o.scope, "scope", "scope.json", "scope file whose domains to check")
	accounts := fs.Bool("accounts", false, "also print the affected accounts (personal data; not stored)")
	o.stateFlags(fs)
	if err := a.parse(fs, args); err != nil {
		return err
	}
	key := os.Getenv("HEJNAL_HIBP_API_KEY")
	if key == "" {
		return errors.New("set HEJNAL_HIBP_API_KEY to your Have I Been Pwned API key; see https://haveibeenpwned.com/API/Key")
	}
	s, err := a.loadScope(o.scope)
	if err != nil {
		return err
	}
	if len(s.Domains) == 0 {
		return fmt.Errorf("%s lists no domains to check", o.scope)
	}
	h := leaks.HIBP{APIKey: key, Client: a.client, UserAgent: version.UserAgent()}
	if a.hibpURL != "" {
		h.BaseURL = a.hibpURL
	}
	details := map[string]leaks.Breach{}
	check := &state.BreachCheck{CheckedAt: a.now().UTC()}
	for _, domain := range s.Domains {
		accts, err := h.BreachedDomain(ctx, domain)
		if err != nil {
			return fmt.Errorf("%s: %w", domain, err)
		}
		for _, names := range accts {
			for _, name := range names {
				if _, ok := details[name]; ok {
					continue
				}
				b, err := h.Breach(ctx, name)
				if err != nil {
					return fmt.Errorf("breach %s: %w", name, err)
				}
				details[name] = b
			}
		}
		sum := leaks.Summarise(domain, accts, details)
		a.printBreaches(sum, accts, *accounts)
		check.Domains = append(check.Domains, sum.WithoutAliases())
	}
	fmt.Fprintln(a.stdout, "\nBreach data: Have I Been Pwned (https://haveibeenpwned.com/), CC BY 4.0.")
	store := state.Store{Dir: o.stateDir}
	if err := store.SaveBreachCheck(check); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Saved to %s; the next run includes it.\n", filepath.Join(o.stateDir, state.BreachesFile))
	return nil
}

// printBreaches prints a domain's breaches and, when asked, the accounts in
// each. accts maps each account's local part to the breaches it is in.
func (a *app) printBreaches(sum leaks.DomainSummary, accts map[string][]string, withAccounts bool) {
	if len(sum.Breaches) == 0 {
		fmt.Fprintf(a.stdout, "%s: no accounts in known breaches.\n", sum.Domain)
		return
	}
	fmt.Fprintf(a.stdout, "%s: %d accounts in %d breaches.\n", sum.Domain, sum.Accounts, len(sum.Breaches))
	byBreach := map[string][]string{}
	for alias, names := range accts {
		for _, name := range names {
			byBreach[name] = append(byBreach[name], alias+"@"+sum.Domain)
		}
	}
	for _, b := range sum.Breaches {
		line := fmt.Sprintf("  %s (%s): %d accounts", b.Title, b.BreachDate, b.Accounts)
		if b.Passwords {
			line += ", passwords exposed"
		}
		fmt.Fprintln(a.stdout, line)
		if withAccounts {
			who := byBreach[b.Name]
			slices.Sort(who)
			fmt.Fprintf(a.stdout, "    %s\n", strings.Join(who, ", "))
		}
	}
}
