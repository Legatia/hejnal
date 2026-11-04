package state

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Legatia/hejnal/leaks"
)

func TestLeakScanAndBreachCheck(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if scan, err := s.LoadLeakScan(); scan != nil || err != nil {
		t.Fatalf("before saving: %v, %v", scan, err)
	}
	if check, err := s.LoadBreachCheck(); check != nil || err != nil {
		t.Fatalf("before saving: %v, %v", check, err)
	}
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	scan := &LeakScan{ScannedAt: at, Roots: []string{"/src/web"}, History: true,
		Leaks: []leaks.Leak{{RuleID: "github-pat", File: "web/app.py", Line: 3, Redacted: "ghp_ab… (40 chars)", Fingerprint: "00112233aabbccdd"}}}
	if err := s.SaveLeakScan(scan); err != nil {
		t.Fatal(err)
	}
	check := &BreachCheck{CheckedAt: at, Domains: []leaks.DomainSummary{{Domain: "example.com", Accounts: 2}}}
	if err := s.SaveBreachCheck(check); err != nil {
		t.Fatal(err)
	}
	gotScan, err := s.LoadLeakScan()
	if err != nil || gotScan == nil || len(gotScan.Leaks) != 1 || !gotScan.History || !gotScan.ScannedAt.Equal(at) {
		t.Errorf("leak scan = %+v, %v", gotScan, err)
	}
	gotCheck, err := s.LoadBreachCheck()
	if err != nil || gotCheck == nil || gotCheck.Domains[0].Domain != "example.com" {
		t.Errorf("breach check = %+v, %v", gotCheck, err)
	}
	if runtime.GOOS != "windows" {
		for _, name := range []string{LeaksFile, BreachesFile} {
			st, err := os.Stat(filepath.Join(s.Dir, name))
			if err != nil || st.Mode().Perm() != 0o600 {
				t.Errorf("%s: %v, mode %v", name, err, st.Mode())
			}
		}
	}
}
