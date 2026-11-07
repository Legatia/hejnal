package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/report"
	"github.com/Legatia/hejnal/state"
)

// acceptDays is how long an acceptance holds unless -until says otherwise.
// No acceptance holds for more than a year.
const acceptDays = 90

// itemIDRE matches an item ID as people type it: the 8 hexadecimal digits the
// fix list shows, or more of the item's hash to tell apart two items that
// share an ID.
var itemIDRE = regexp.MustCompile(`^[0-9a-f]{8,64}$`)

func (a *app) cmdAccept(args []string) error {
	o := &options{}
	fs := a.flags("accept", `-item <id> -reason "..." [-until YYYY-MM-DD] [-by name] | -list | -remove <id>`,
		"Record that you checked an item on the fix list and it needs no action for\n"+
			"now, for example because the version running has the fix. Its findings stay\n"+
			"out of alerts and the exit status, and the fix list shows the item under\n"+
			"\"Accepted\". Anything new in the item still shows, and so does the whole item\n"+
			"once the acceptance expires.")
	item := fs.String("item", "", "ID of the item to accept, as the fix list shows it")
	reason := fs.String("reason", "", "why the item needs no action now (required with -item)")
	until := fs.String("until", "", "last day the acceptance holds, as YYYY-MM-DD (default: in 90 days; at most a year)")
	by := fs.String("by", "", "who checked the item")
	list := fs.Bool("list", false, "list the accepted items, and which acceptances have expired")
	remove := fs.String("remove", "", "ID of an item whose acceptance to remove")
	o.stateFlags(fs)
	if err := a.parse(fs, args); err != nil {
		return err
	}
	modes := 0
	for _, on := range []bool{*item != "", *list, *remove != ""} {
		if on {
			modes++
		}
	}
	switch {
	case modes == 0:
		fmt.Fprintln(a.stderr, "hejnal accept: use -item, -list or -remove")
		fs.Usage()
		return errUsage
	case modes > 1:
		return errors.New("use only one of -item, -list and -remove")
	}
	if *item == "" {
		extra := false
		fs.Visit(func(f *flag.Flag) { extra = extra || f.Name == "reason" || f.Name == "until" || f.Name == "by" })
		if extra {
			return errors.New("-reason, -until and -by go only with -item")
		}
	}
	store := state.Store{Dir: o.stateDir}
	switch {
	case *list:
		return a.listAccepted(store)
	case *remove != "":
		return a.removeAccepted(store, *remove)
	}
	return a.acceptItem(store, *item, *reason, *until, *by)
}

// acceptItem accepts the open findings of an item from the latest run,
// replacing any earlier acceptance of the item.
func (a *app) acceptItem(store state.Store, id, reason, until, by string) error {
	now := a.now().UTC()
	reason, by = match.CleanNote(reason), match.CleanNote(by)
	switch {
	case reason == "":
		return errors.New(`-reason is required: say why the item needs no action now, for example -reason "Version 6.8.3 has the fix"`)
	case utf8.RuneCountInString(reason) > match.MaxReason:
		return fmt.Errorf("-reason is longer than %d characters", match.MaxReason)
	case utf8.RuneCountInString(by) > match.MaxBy:
		return fmt.Errorf("-by is longer than %d characters", match.MaxBy)
	}
	last, err := acceptUntil(until, now)
	if err != nil {
		return err
	}
	snap, err := store.LoadFindings()
	if err != nil {
		return err
	}
	g, err := findItem(match.Groups(snap.Findings), id, snap.GeneratedAt)
	if err != nil {
		return err
	}
	title := match.CleanNote(report.ItemTitle(g, "en"))
	// The acceptance covers every finding the item has now, including any
	// accepted before.
	active := match.Active(g.Findings)
	if len(active) == 0 {
		return fmt.Errorf("item %s, %s, has nothing open to accept: the version check rules out all its flaws, so alerts already leave it out", g.ID(), title)
	}
	acc := match.Acceptance{Item: g.ID(), Key: g.Key, Title: title, Reason: reason, By: by, AcceptedAt: now, Until: last}
	for _, f := range active {
		acc.Findings = append(acc.Findings, f.Key)
	}
	saved, err := store.LoadAccepted()
	if err != nil {
		return err
	}
	before := len(saved)
	saved = slices.DeleteFunc(saved, func(x match.Acceptance) bool { return x.Key == g.Key })
	verb := "Accepted"
	if len(saved) < before {
		verb = "Updated the acceptance of"
	}
	saved = append(saved, acc)
	slices.SortFunc(saved, func(x, y match.Acceptance) int { return strings.Compare(x.Item, y.Item) })
	if err := store.SaveAccepted(saved); err != nil {
		return err
	}
	findings := "findings"
	if len(active) == 1 {
		findings = "finding"
	}
	fmt.Fprintf(a.stdout, "%s %s, %s, until %s (%d %s).\n", verb, acc.Item, title, last, len(active), findings)
	fmt.Fprintf(a.stdout, "Alerts and the exit status leave these findings out. New findings in the item still show, and the whole item shows again after %s.\n", last)
	return nil
}

// acceptUntil reads -until, the last day an acceptance holds: from today to
// a year from today, and acceptDays from today when it is not given.
func acceptUntil(v string, now time.Time) (string, error) {
	const day = "2006-01-02"
	today, limit := now.UTC().Format(day), now.UTC().AddDate(1, 0, 0).Format(day)
	if v = strings.TrimSpace(v); v == "" {
		return now.UTC().AddDate(0, 0, acceptDays).Format(day), nil
	}
	t, err := time.Parse(day, v)
	if err != nil {
		return "", fmt.Errorf("-until must be a date such as %s", now.UTC().AddDate(0, 0, acceptDays).Format(day))
	}
	switch until := t.Format(day); {
	case until < today:
		return "", fmt.Errorf("-until %s is in the past", until)
	case until > limit:
		return "", fmt.Errorf("-until %s is more than a year away: accept the item for at most a year, until %s, and check it again then", until, limit)
	default:
		return until, nil
	}
}

// findItem finds the item with the given ID among the latest run's items.
func findItem(gs []match.Group, id string, at time.Time) (match.Group, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	if !itemIDRE.MatchString(id) {
		return match.Group{}, fmt.Errorf("%s is not an item ID: use the 8 characters the fix list shows after an item's title, such as 3f9a1c0d", strconv.Quote(id))
	}
	var keys []string
	var found match.Group
	for _, g := range gs {
		if strings.HasPrefix(match.ItemHash(g.Key), id) {
			keys = append(keys, g.Key)
			found = g
		}
	}
	switch len(keys) {
	case 0:
		return match.Group{}, fmt.Errorf("there is no item %s in the findings of %s; check the ID in the latest fix list", id, at.UTC().Format("2006-01-02 15:04 UTC"))
	case 1:
		return found, nil
	}
	return match.Group{}, ambiguousItem(id, keys)
}

// ambiguousItem explains that id fits several items, and gives longer IDs
// that tell them apart.
func ambiguousItem(id string, keys []string) error {
	var longer []string
	for _, k := range keys {
		longer = append(longer, match.ItemHash(k)[:16])
	}
	return fmt.Errorf("the ID %s fits %d items; use a longer one: %s", id, len(keys), strings.Join(longer, " or "))
}

// listAccepted prints the accepted items, the ones that end first first.
func (a *app) listAccepted(store state.Store) error {
	saved, err := store.LoadAccepted()
	if err != nil {
		return err
	}
	if len(saved) == 0 {
		fmt.Fprintln(a.stdout, `No accepted items. Once you have checked an item on the fix list, accept it with: hejnal accept -item <id> -reason "..."`)
		return nil
	}
	slices.SortStableFunc(saved, func(x, y match.Acceptance) int {
		return cmp.Or(strings.Compare(x.Until, y.Until), strings.Compare(x.Item, y.Item))
	})
	now := a.now()
	expired := 0
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ITEM\tUNTIL\tBY\tWHAT\tREASON")
	for _, x := range saved {
		until := x.Until
		if x.Expired(now) {
			until += " (expired)"
			expired++
		}
		by := match.CleanNote(x.By)
		if by == "" {
			by = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", x.Item, until, by, match.CleanNote(x.Title), match.CleanNote(x.Reason))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "\nAccepted items: %d, expired: %d.", len(saved), expired)
	if expired > 0 {
		fmt.Fprint(a.stdout, " An expired acceptance covers nothing, so its item is open again: check it, then accept it again or remove the acceptance with -remove.")
	}
	fmt.Fprintln(a.stdout)
	return nil
}

// removeAccepted removes the acceptance of an item.
func (a *app) removeAccepted(store state.Store, id string) error {
	id = strings.ToLower(strings.TrimSpace(id))
	if !itemIDRE.MatchString(id) {
		return fmt.Errorf("%s is not an item ID: use the 8 characters `hejnal accept -list` shows", strconv.Quote(id))
	}
	saved, err := store.LoadAccepted()
	if err != nil {
		return err
	}
	var keys []string
	for _, x := range saved {
		if strings.HasPrefix(match.ItemHash(x.Key), id) && !slices.Contains(keys, x.Key) {
			keys = append(keys, x.Key)
		}
	}
	switch len(keys) {
	case 0:
		return fmt.Errorf("item %s is not accepted; `hejnal accept -list` shows the accepted items", id)
	case 1:
	default:
		return ambiguousItem(id, keys)
	}
	var gone match.Acceptance
	saved = slices.DeleteFunc(saved, func(x match.Acceptance) bool {
		if x.Key != keys[0] {
			return false
		}
		gone = x
		return true
	})
	if err := store.SaveAccepted(saved); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Removed the acceptance of %s, %s. Its findings are open again.\n", gone.Item, match.CleanNote(gone.Title))
	return nil
}
