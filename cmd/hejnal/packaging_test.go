package main

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// TestSystemdUnitRuns runs the command line from packaging/hejnal.service,
// with its paths moved into the test directory, so a renamed flag cannot
// silently break the daily timer that the Linux packages install.
func TestSystemdUnitRuns(t *testing.T) {
	f, err := os.Open("../../packaging/hejnal.service")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var exec []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "ExecStart="); ok {
			exec = strings.Fields(rest)
		}
	}
	if len(exec) < 2 || exec[0] != "/usr/bin/hejnal" || exec[1] != "run" {
		t.Fatalf("ExecStart = %q, want /usr/bin/hejnal run ...", exec)
	}
	h := newHarness(t)
	var args []string
	for _, a := range exec[1:] {
		switch a {
		case "/etc/hejnal/scope.json":
			a = h.scope
		case "/var/lib/hejnal":
			a = h.state
		case "$HEJNAL_ARGS":
			continue // empty unless the settings file sets it
		}
		args = append(args, a)
	}
	// The flags the harness adds keep the test offline.
	args = append(args, h.runArgs()[5:]...)
	if code, _, errOut := h.run(args...); code != exitOK {
		t.Fatalf("hejnal %s: code %d\n%s", strings.Join(args, " "), code, errOut)
	}
	if _, err := os.Stat(h.state + "/fixlist.md"); err != nil {
		t.Errorf("no fix list in the state directory: %v", err)
	}
}
