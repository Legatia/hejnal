package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

func dep(project, name, version, file string) match.Finding {
	return match.Finding{
		Key: "dependency|" + project + "|npm|" + name + "|" + version + "|GHSA-test", Kind: match.KindDependency,
		Host: project, Ecosystem: "npm", Technology: name, Version: version, File: file, Line: 12,
		Score: 70, Severity: match.High, Confidence: match.ConfidenceObserved,
	}
}

func idOf(t *testing.T, f match.Finding) string {
	t.Helper()
	return match.Groups([]match.Finding{f})[0].ID()
}

func TestRecheckCode(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"package-lock.json", "main.tf", "config.py"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	req := CodeRequest{Project: "shop", Dirs: []string{dir}}
	all := []string{PartDeps, PartSecrets, PartIaC}

	lodash := dep("shop", "lodash", "4.17.20", "package-lock.json")
	lodashNext := dep("shop", "lodash", "4.17.20-patch", "package-lock.json")
	lodashOld := dep("shop", "lodash", "3.10.1", "package-lock.json")
	other := dep("billing", "lodash", "4.17.20", "package-lock.json")
	inImage := dep("shop", "openssl", "3.0.9", "shop.tar:var/lib/dpkg/status")
	inSub := dep("shop", "minimist", "1.2.0", "web/package-lock.json")
	deleted := dep("shop", "left-pad", "1.0.0", "old/package-lock.json")
	bucket := match.Finding{
		Key: "misconfig|shop|main.tf|public-bucket|aws_s3_bucket.assets|3", Kind: match.KindMisconfig,
		Host: "shop", File: "main.tf", Line: 3, TechID: "public-bucket", Technology: "aws_s3_bucket.assets",
		Score: 60, Severity: match.High, Confidence: match.ConfidenceObserved,
	}
	bucketMoved := bucket
	bucketMoved.File, bucketMoved.Key = "storage.tf", "misconfig|shop|storage.tf|public-bucket|aws_s3_bucket.assets|3"
	gone := bucket
	gone.File, gone.Technology, gone.Key = "legacy.tf", "aws_s3_bucket.legacy", "misconfig|shop|legacy.tf|public-bucket|aws_s3_bucket.legacy|1"
	secret := match.Finding{
		Key: "secret|abcd|config.py", Kind: match.KindSecret, Host: "shop", File: "config.py", Line: 4,
		Fingerprint: "abcd", Score: 80, Severity: match.High, Confidence: match.ConfidenceObserved,
	}
	inHistory := secret
	inHistory.Fingerprint, inHistory.Key, inHistory.Commit = "ef01", "secret|ef01|config.py", "1a2b3c4"
	kev := match.Finding{
		Key: "kev|app.example.com|443|wordpress|CVE-2024-0001", Kind: match.KindKEV, Host: "app.example.com", Port: 443,
		TechID: "wordpress", Score: 90, Severity: match.Critical, Confidence: match.ConfidenceObserved,
	}
	ruledOut := lodash
	ruledOut.Confidence = match.ConfidenceRuledOut
	known := []match.Finding{lodash, lodashOld, other, inImage, inSub, deleted, bucket, gone, secret, inHistory, kev}

	for _, tc := range []struct {
		name   string
		item   match.Finding
		scan   state.CodeScan
		req    CodeRequest
		known  []match.Finding
		keyed  bool
		status string
		why    string
	}{
		{name: "still found", item: lodash, scan: state.CodeScan{Parts: all, Findings: []match.Finding{lodash}}, status: ItemFound},
		{name: "found without any record", item: lodash, scan: state.CodeScan{Parts: all, Findings: []match.Finding{lodash}}, known: []match.Finding{}, status: ItemFound},
		{name: "upgraded", item: lodash, scan: state.CodeScan{Parts: all, Findings: []match.Finding{lodashOld}}, status: ItemGone},
		{name: "ruled out counts as gone", item: lodash, scan: state.CodeScan{Parts: all, Findings: []match.Finding{ruledOut}}, status: ItemGone},
		{name: "upgraded to a version with an advisory", item: lodash, scan: state.CodeScan{Parts: all, Findings: []match.Finding{lodashNext, lodashOld}}, status: ItemMoved},
		{name: "no record", item: lodash, scan: state.CodeScan{Parts: all}, known: []match.Finding{}, status: ItemNotFound},
		{name: "no record and a part left out", item: lodash, scan: state.CodeScan{Parts: []string{PartSecrets, PartIaC}}, known: []match.Finding{}, status: ItemUnknown, why: "left out a part"},
		{name: "no record and an unreadable file", item: lodash, scan: state.CodeScan{Parts: all, Notes: []string{"could not read yarn.lock: bad"}}, known: []match.Finding{}, status: ItemUnknown, why: "could not read yarn.lock"},
		{name: "dependencies left out", item: lodash, scan: state.CodeScan{Parts: []string{PartSecrets, PartIaC}}, status: ItemUnknown, why: "did not check dependencies"},
		{name: "unreadable lockfile", item: lodash, scan: state.CodeScan{Parts: all, Notes: []string{"could not read package-lock.json: bad"}}, status: ItemUnknown, why: "could not read package-lock.json"},
		{name: "another project", item: other, scan: state.CodeScan{Parts: all}, status: ItemUnknown, why: `project "billing"`},
		{name: "image not checked", item: inImage, scan: state.CodeScan{Parts: all}, status: ItemUnknown, why: "container image"},
		{name: "another image checked", item: inImage, scan: state.CodeScan{Parts: []string{PartImages}, Images: []string{"other.tar"}}, status: ItemUnknown, why: "container image"},
		{name: "image checked", item: inImage, scan: state.CodeScan{Parts: []string{PartImages}, Images: []string{"shop.tar"}}, status: ItemGone},
		{name: "lockfile not in the directory", item: inSub, scan: state.CodeScan{Parts: all}, status: ItemUnknown, why: "web/package-lock.json, where the item was found, is not in what was scanned"},
		{name: "lockfile excluded", item: deleted, scan: state.CodeScan{Parts: all}, req: CodeRequest{Project: "shop", Dirs: []string{dir}, Exclude: []string{"old"}}, status: ItemUnknown, why: "excluded old/package-lock.json"},
		{name: "setting changed", item: bucket, scan: state.CodeScan{Parts: all}, status: ItemGone},
		{name: "resource moved to another file", item: bucket, scan: state.CodeScan{Parts: all, Findings: []match.Finding{bucketMoved}}, status: ItemMoved},
		{name: "file deleted, others of the project there", item: gone, scan: state.CodeScan{Parts: all}, status: ItemGone},
		{name: "file deleted, nothing else on record", item: gone, scan: state.CodeScan{Parts: all}, known: []match.Finding{gone}, status: ItemUnknown, why: "legacy.tf, where the item was found, is not in what was scanned"},
		{name: "infrastructure left out", item: bucket, scan: state.CodeScan{Parts: []string{PartDeps, PartSecrets}}, status: ItemUnknown, why: "infrastructure code"},
		{name: "secret removed", item: secret, scan: state.CodeScan{Parts: all}, keyed: true, status: ItemGone},
		{name: "secret without the key", item: secret, scan: state.CodeScan{Parts: all}, status: ItemUnknown, why: "key in the state directory"},
		{name: "secrets left out", item: secret, scan: state.CodeScan{Parts: []string{PartDeps, PartIaC}}, keyed: true, status: ItemUnknown, why: "did not look for secrets"},
		{name: "secret in history, history not read", item: inHistory, scan: state.CodeScan{Parts: all}, keyed: true, status: ItemUnknown, why: "Git history"},
		{name: "secret in history, history read", item: inHistory, scan: state.CodeScan{Parts: all}, req: CodeRequest{Project: "shop", Dirs: []string{dir}, History: true}, keyed: true, status: ItemGone},
		{name: "an item on a system", item: kev, scan: state.CodeScan{Parts: all}, status: ItemUnknown, why: "app.example.com:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scan := tc.scan
			scan.Project = "shop"
			r, k := tc.req, tc.known
			if r.Dirs == nil {
				r = req
			}
			if k == nil {
				k = known
			}
			id := idOf(t, tc.item)
			got := RecheckCode(id, &scan, r, k, tc.keyed)
			if got.Status != tc.status || !strings.Contains(got.Why, tc.why) {
				t.Fatalf("status = %q (%s), want %q (… %s …)", got.Status, got.Why, tc.status, tc.why)
			}
			if got.ID != id {
				t.Errorf("ID = %q, want %q", got.ID, id)
			}
			if (got.Why != "") != (got.Status == ItemUnknown) {
				t.Errorf("status %q with reason %q", got.Status, got.Why)
			}
			if (got.Now != nil) != (got.Status == ItemMoved) {
				t.Errorf("status %q with successor %v", got.Status, got.Now)
			}
			if (got.Group == nil) != (got.Status == ItemNotFound || (got.Status == ItemUnknown && len(k) == 0)) {
				t.Errorf("status %q with item %v", got.Status, got.Group)
			}
		})
	}
}

// A package at two versions is two items: fixing one does not turn it
// into the other.
func TestRecheckCodeKeepsSeparateItemsApart(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, b := dep("shop", "lodash", "4.17.20", "package-lock.json"), dep("shop", "lodash", "3.10.1", "package-lock.json")
	scan := &state.CodeScan{Project: "shop", Parts: []string{PartDeps, PartSecrets, PartIaC}, Findings: []match.Finding{b}}
	got := RecheckCode(idOf(t, a), scan, CodeRequest{Project: "shop", Dirs: []string{dir}}, []match.Finding{a, b}, false)
	if got.Status != ItemGone {
		t.Fatalf("status = %q (%s), want %q", got.Status, got.Why, ItemGone)
	}
}

func TestRecheckCodeSeveralDirectories(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"web", "api"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "web", "package-lock.json"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	req := CodeRequest{Project: "shop", Dirs: []string{filepath.Join(root, "web"), filepath.Join(root, "api")}}
	scan := &state.CodeScan{Project: "shop", Parts: []string{PartDeps, PartSecrets, PartIaC}}
	inWeb, inAPI := dep("shop", "lodash", "4.17.20", "web/package-lock.json"), dep("shop", "minimist", "1.2.0", "api/package-lock.json")
	known := []match.Finding{inWeb, inAPI}
	if got := RecheckCode(idOf(t, inWeb), scan, req, known, false); got.Status != ItemGone {
		t.Errorf("web: status = %q (%s), want %q", got.Status, got.Why, ItemGone)
	}
	if got := RecheckCode(idOf(t, inAPI), scan, req, known, false); got.Status != ItemUnknown {
		t.Errorf("api: status = %q, want %q", got.Status, ItemUnknown)
	}
	// A file name from a saved result cannot point outside the directory.
	out := dep("shop", "lodash", "1.0.0", "web/../../etc/passwd")
	if req.has(out.File) {
		t.Error("a path that leaves the scanned directory counts as in it")
	}
}

func TestRecheckLive(t *testing.T) {
	kev := match.Finding{
		Key: "kev|app.example.com|443|wordpress|CVE-2024-0001", Kind: match.KindKEV, Host: "app.example.com", Port: 443,
		TechID: "wordpress", Score: 90, Severity: match.Critical, Confidence: match.ConfidenceObserved,
	}
	cert := match.Finding{
		Key: "tls-expiring|app.example.com|443", Kind: match.KindTLSExpiring, Host: "app.example.com", Port: 443,
		Score: 50, Severity: match.Medium, Confidence: match.ConfidenceObserved,
	}
	file := match.Finding{
		Key: "exposed-file|app.example.com|443|git", Kind: match.KindExposedFile, Host: "app.example.com", Port: 443,
		Score: 80, Severity: match.High, Confidence: match.ConfidenceObserved,
	}
	elsewhere := kev
	elsewhere.Host, elsewhere.Key = "old.example.com", "kev|old.example.com|443|wordpress|CVE-2024-0001"
	onPort := kev
	onPort.Port, onPort.Key = 8443, "kev|app.example.com|8443|wordpress|CVE-2024-0001"
	mail := match.Finding{
		Key: "email|example.com|dmarc", Kind: match.KindEmail, Host: "example.com",
		Score: 40, Severity: match.Medium, Confidence: match.ConfidenceObserved,
	}
	lodash := dep("shop", "lodash", "4.17.20", "package-lock.json")
	ruledOut := kev
	ruledOut.Confidence = match.ConfidenceRuledOut
	known := []match.Finding{kev, cert, file, elsewhere, onPort, mail, lodash}
	targets := []LiveTarget{{Shown: "https://app.example.com", Host: "app.example.com", Port: 443}}

	for _, tc := range []struct {
		name     string
		item     match.Finding
		found    []match.Finding
		known    []match.Finding
		noChecks bool
		status   string
		why      string
	}{
		{name: "still found", item: kev, found: []match.Finding{kev}, status: ItemFound},
		{name: "found without any record", item: kev, found: []match.Finding{kev}, known: []match.Finding{}, status: ItemFound},
		{name: "fixed", item: kev, found: []match.Finding{cert}, status: ItemGone},
		{name: "version ruled out", item: kev, found: []match.Finding{ruledOut}, status: ItemGone},
		{name: "no record", item: kev, known: []match.Finding{}, status: ItemNotFound},
		{name: "another host", item: elsewhere, status: ItemUnknown, why: "old.example.com:443, which this check did not look at"},
		{name: "another port", item: onPort, status: ItemUnknown, why: "app.example.com:8443"},
		{name: "mail records", item: mail, status: ItemUnknown, why: "the next run does"},
		{name: "an item in code", item: lodash, status: ItemUnknown, why: "a code scan checks it"},
		{name: "exposed file without the fixed paths", item: file, noChecks: true, status: ItemUnknown, why: "left out the fixed paths"},
		{name: "exploited flaw without the version checks", item: kev, noChecks: true, status: ItemUnknown, why: "left out the fixed paths"},
		{name: "certificate without the fixed paths", item: cert, noChecks: true, status: ItemGone},
		{name: "exposed file with the fixed paths", item: file, status: ItemGone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := tc.known
			if k == nil {
				k = known
			}
			got := RecheckLive(idOf(t, tc.item), tc.found, k, targets, !tc.noChecks)
			if got.Status != tc.status || !strings.Contains(got.Why, tc.why) {
				t.Fatalf("status = %q (%s), want %q (… %s …)", got.Status, got.Why, tc.status, tc.why)
			}
			if (got.Why != "") != (got.Status == ItemUnknown) {
				t.Errorf("status %q with reason %q", got.Status, got.Why)
			}
		})
	}
}

func TestValidItemID(t *testing.T) {
	for id, want := range map[string]bool{
		"30c07628": true, "00000000": true, "": false, "30c0762": false, "30c076288": false,
		"30C07628": false, "30c0762g": false, "../../ab": false,
	} {
		if got := ValidItemID(id); got != want {
			t.Errorf("ValidItemID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestKnownReadsRunsAndCodeScans(t *testing.T) {
	store := state.Store{Dir: t.TempDir()}
	if fs, err := Known(store); err != nil || len(fs) != 0 {
		t.Fatalf("empty state: %v, %v", fs, err)
	}
	scan := &state.CodeScan{Project: "shop", Findings: []match.Finding{dep("shop", "lodash", "4.17.20", "package-lock.json")}}
	if err := store.SaveCodeScan(scan); err != nil {
		t.Fatal(err)
	}
	fs, err := Known(store)
	if err != nil || len(fs) != 1 {
		t.Fatalf("after a saved code scan: %v, %v", fs, err)
	}
}
