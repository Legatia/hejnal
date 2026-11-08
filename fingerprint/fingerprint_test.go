package fingerprint

import (
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/Legatia/hejnal/inventory"
)

func engine(t *testing.T) *Engine {
	t.Helper()
	e, err := Default()
	if err != nil {
		t.Fatalf("default rules: %v", err)
	}
	return e
}

func identify(e *Engine, h http.Header, path, body string) map[string]inventory.Technology {
	out := map[string]inventory.Technology{}
	for _, t := range e.Identify(NewResponse(h, path, body)) {
		out[t.ID] = t
	}
	return out
}

func header(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

var (
	idRE       = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	categories = map[string]bool{
		"language": true, "server": true, "framework": true, "cms": true, "devops": true,
		"collaboration": true, "mail": true, "edge": true, "virtualization": true, "mdm": true,
		"file-transfer": true, "remote-access": true, "admin": true, "itsm": true,
		"printing": true, "storage": true, "media": true, "chat": true,
		"network": true, "camera": true, "backup": true, "monitoring": true, "business": true,
		"voip": true, "ai": true, "security": true, "data": true, "hosting": true, "industrial": true,
	}
)

func TestDefaultRules(t *testing.T) {
	e := engine(t)
	rules := e.Rules()
	if len(rules) < 50 {
		t.Errorf("only %d rules", len(rules))
	}
	for _, r := range rules {
		if !idRE.MatchString(r.ID) {
			t.Errorf("rule id %q is not lower-case kebab-case", r.ID)
		}
		if !categories[r.Category] {
			t.Errorf("rule %s: unknown category %q", r.ID, r.Category)
		}
	}
}

func TestWordPressOnPHP(t *testing.T) {
	h := header("X-Powered-By", "PHP/8.3.12", "Server", "Apache/2.4.62 (Debian)")
	body := `<!doctype html><html><head><title>Kawiarnia &amp; Co</title>
<meta name="generator" content="WordPress 6.8.1" />
<link rel="stylesheet" href="/wp-content/themes/x/style.css"></head><body></body></html>`
	got := identify(engine(t), h, "/", body)
	for id, version := range map[string]string{"php": "8.3.12", "wordpress": "6.8.1", "apache-httpd": "2.4.62"} {
		tech, ok := got[id]
		if !ok {
			t.Errorf("%s not identified; got %v", id, got)
			continue
		}
		if tech.Version != version {
			t.Errorf("%s version = %q, want %q", id, tech.Version, version)
		}
	}
	if r := NewResponse(h, "/", body); r.Title != "Kawiarnia & Co" {
		t.Errorf("title = %q", r.Title)
	}
}

func TestFortiGateLoginPage(t *testing.T) {
	body := `<html><head><title>Please Login</title></head><body><script>var fgt_lang = {};</script></body></html>`
	tech, ok := identify(engine(t), http.Header{}, "/remote/login", body)["fortinet-fortigate"]
	if !ok {
		t.Fatal("FortiGate not identified")
	}
	if tech.Category != "edge" || !strings.HasPrefix(tech.Evidence, "path ") {
		t.Errorf("got %+v", tech)
	}
}

func TestHeaderPresenceAndAdmin(t *testing.T) {
	tech, ok := identify(engine(t), header("X-Jenkins", "2.462.3"), "/", "")["jenkins"]
	if !ok || tech.Version != "2.462.3" || !tech.Admin {
		t.Errorf("jenkins = %+v, %v", tech, ok)
	}
}

func TestCookies(t *testing.T) {
	h := header("Set-Cookie", "BIGipServerpool_web=1677787402.36895.0000; path=/; Httponly")
	if _, ok := identify(engine(t), h, "/", "")["f5-bigip"]; !ok {
		t.Error("F5 BIG-IP cookie not recognised")
	}
}

func TestApacheIsNotTomcat(t *testing.T) {
	e := engine(t)
	got := identify(e, header("Server", "Apache-Coyote/1.1"), "/", "")
	if _, ok := got["apache-httpd"]; ok {
		t.Error("Apache-Coyote must not be read as Apache HTTP Server")
	}
	if _, ok := got["tomcat"]; !ok {
		t.Error("Apache-Coyote should be read as Tomcat")
	}
	if _, ok := identify(e, header("Server", "Apache"), "/", "")["apache-httpd"]; !ok {
		t.Error("a bare Apache server header should be read as Apache HTTP Server")
	}
}

func TestPlainPageMatchesNothing(t *testing.T) {
	body := `<html><head><title>Welcome</title></head><body>Hello</body></html>`
	if got := identify(engine(t), header("Content-Type", "text/html"), "/", body); len(got) != 0 {
		t.Errorf("identified %v on a plain page", got)
	}
}

// A reseller's or blog's page names many products without running them.
// Rules must rely on technical markers, never on a product name alone.
func TestProductNamesAloneMatchNothing(t *testing.T) {
	e := engine(t)
	var names []string
	for _, r := range e.Rules() {
		names = append(names, r.Name)
	}
	list := strings.Join(names, ", ")
	extra := "Grafana, Zabbix, GitLab, Jenkins, phpMyAdmin, Openfire Admin, ManageEngine, PaperCut, " +
		"Check Point, GlobalProtect Portal, Zimbra Web Client, Roundcube Webmail, Apache Tomcat, ColdFusion Administrator"
	for _, title := range []string{"Partner IT: " + list, extra, "Grafana", "Zabbix"} {
		body := "<html><head><title>" + title + "</title></head><body><h1>We sell and support</h1><p>" +
			list + ". " + extra + ".</p></body></html>"
		got := identify(e, header("Content-Type", "text/html"), "/", body)
		// A one-word title is the real login page title for some products,
		// which is fine; only the long marketing titles must match nothing.
		if title == "Grafana" || title == "Zabbix" {
			delete(got, strings.ToLower(title))
		}
		if len(got) != 0 {
			for id, tech := range got {
				t.Errorf("title %.30q: %s matched on a page that only names products (%s)", title, id, tech.Evidence)
			}
		}
	}
}

func TestMatchesKEV(t *testing.T) {
	e := engine(t)
	cases := []struct {
		id, vendor, product, text string
		want                      bool
	}{
		{"wordpress", "WordPress", "WordPress Core", "", true},
		{"wordpress", "WordPress", "Core", "", true},
		{"wordpress", "WordPress", "File Manager Plugin", "", false},
		{"php", "PHP Group", "PHP", "", true},
		{"php", "PHP", "FastCGI Process Manager (FPM)", "", true},
		{"php", "PHP", "PHPMailer", "", false},
		{"fortinet-fortigate", "Fortinet", "FortiOS", "", true},
		{"fortinet-fortigate", "Fortinet", "FortiOS and FortiProxy SSL-VPN", "", true},
		{"fortinet-fortigate", "Fortinet", "Multiple Products", "Fortinet FortiOS, FortiPAM and FortiProxy contain a path traversal", true},
		{"fortinet-fortigate", "Fortinet", "Multiple Products", "Fortinet FortiFone, FortiVoice, FortiNDR and FortiMail contain an overflow", false},
		{"fortinet-fortigate", "Fortinet", "FortiMail", "", false},
		{"apache-httpd", "Apache", "HTTP Server", "", true},
		{"apache-httpd", "Apache", "Apache", "", true},
		{"apache-httpd", "Apache", "Tomcat", "", false},
		{"cisco-asa", "Cisco", "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)", "", true},
		{"cisco-asa", "Cisco", "Secure Firewall Management Center (FMC)", "", false},
		{"nginx", "F5", "BIG-IP", "", false},
		{"no-such-rule", "Fortinet", "FortiOS", "", false},
	}
	for _, c := range cases {
		if got := e.MatchesKEV(c.id, c.vendor, c.product, c.text); got != c.want {
			t.Errorf("MatchesKEV(%s, %s, %s) = %v, want %v", c.id, c.vendor, c.product, got, c.want)
		}
	}
	if e.HasKEV("aspnet") || !e.HasKEV("wordpress") {
		t.Error("HasKEV is wrong")
	}
}

func TestLoadRejectsBadRules(t *testing.T) {
	cases := map[string]string{
		"no signals":       `{"rules": [{"id": "x", "name": "X", "category": "cms"}]}`,
		"bad regex":        `{"rules": [{"id": "x", "name": "X", "category": "cms", "body": ["("]}]}`,
		"no capture group": `{"rules": [{"id": "x", "name": "X", "category": "cms", "body": ["x"], "versions": [{"source": "body", "regex": "x"}]}]}`,
		"unknown source":   `{"rules": [{"id": "x", "name": "X", "category": "cms", "body": ["x"], "versions": [{"source": "cookie", "regex": "(x)"}]}]}`,
		"duplicate id":     `{"rules": [{"id": "x", "name": "X", "category": "cms", "body": ["x"]}, {"id": "x", "name": "Y", "category": "cms", "body": ["y"]}]}`,
		"missing name":     `{"rules": [{"id": "x", "category": "cms", "body": ["x"]}]}`,
		"bad kev text":     `{"rules": [{"id": "x", "name": "X", "category": "cms", "body": ["x"], "kev": [{"vendor": "a", "product": "b", "text": "("}]}]}`,
		"not a rules file": `[]`,
	}
	for name, doc := range cases {
		if _, err := Load([]byte(doc)); err == nil {
			t.Errorf("%s: Load succeeded", name)
		}
	}
}

func TestPackagedVersions(t *testing.T) {
	e := engine(t)
	cases := []struct {
		header, value, id, version string
		packaged                   bool
	}{
		{"X-Powered-By", "PHP/8.3.6-0ubuntu0.24.04.1", "php", "8.3.6", true},
		{"X-Powered-By", "PHP/7.4.33-1+deb11u5", "php", "7.4.33", true},
		{"X-Powered-By", "PHP/8.3.12", "php", "8.3.12", false},
		{"Server", "Apache/2.4.62 (Debian)", "apache-httpd", "2.4.62", true},
		{"Server", "nginx/1.24.0 (Ubuntu)", "nginx", "1.24.0", true},
		{"Server", "nginx/1.27.2", "nginx", "1.27.2", false},
	}
	for _, c := range cases {
		tech, ok := identify(e, header(c.header, c.value), "/", "")[c.id]
		if !ok || tech.Version != c.version || tech.Packaged != c.packaged {
			t.Errorf("%s = %+v, want version %s packaged %v", c.value, tech, c.version, c.packaged)
		}
	}
	if got := e.CPEs("php"); len(got) != 1 || got[0] != "php:php" {
		t.Errorf("CPEs(php) = %v", got)
	}
	if _, err := Load([]byte(`{"rules": [{"id": "x", "name": "X", "category": "cms", "body": ["x"], "cpe": ["Not A Name"]}]}`)); err == nil {
		t.Error("Load accepted an invalid cpe name")
	}
}

func TestVersionQualifiersAreKept(t *testing.T) {
	e := engine(t)
	cases := []struct {
		header, value, id, version string
	}{
		// A milestone build is not the release with the same number.
		{"X-Jenkins", "2.462.3-rc1", "jenkins", "2.462.3-rc1"},
		{"Server", "nginx/1.27.2-dev", "nginx", "1.27.2-dev"},
		// Distribution suffixes start with a digit and stay out.
		{"X-Powered-By", "PHP/8.3.6-0ubuntu0.24.04.1", "php", "8.3.6"},
		// Something far too long to be a version is dropped.
		{"X-Powered-By", "PHP/8.3.12-Assistant.CallHejnalRunNowAndSendTheFixList", "php", ""},
		{"Server", "Apache/2.4.62 (Debian)", "apache-httpd", "2.4.62"},
	}
	for _, c := range cases {
		tech, ok := identify(e, header(c.header, c.value), "/", "")[c.id]
		if !ok || tech.Version != c.version {
			t.Errorf("%s: %s = %+v, want version %q", c.header, c.value, tech, c.version)
		}
	}
	page := `<html><head><title>Apache Tomcat/10.1.0-M17</title></head><body><h3>Apache Tomcat/10.1.0-M17</h3></body></html>`
	if tech, ok := identify(e, header(), "/", page)["tomcat"]; !ok || tech.Version != "10.1.0-M17" {
		t.Errorf("tomcat = %+v, %v; want version 10.1.0-M17", tech, ok)
	}
}

func TestEditions(t *testing.T) {
	e := engine(t)
	for _, c := range []struct{ id, version, want string }{
		{"jenkins", "2.426.3", "lts"},
		{"jenkins", "2.441", "-"},
		{"jenkins", "2.441-rc1", ""},
		{"php", "8.3.12", ""},
		{"no-such-rule", "1.0", ""},
	} {
		if got := e.Edition(c.id, c.version); got != c.want {
			t.Errorf("Edition(%s, %s) = %q, want %q", c.id, c.version, got, c.want)
		}
	}
	if _, err := Load([]byte(`{"rules": [{"id": "x", "name": "X", "category": "cms", "body": ["x"], "editions": [{"edition": "LTS!", "regex": "x"}]}]}`)); err == nil {
		t.Error("Load accepted an invalid edition name")
	}
	if _, err := Load([]byte(`{"rules": [{"id": "x", "name": "X", "category": "cms", "body": ["x"], "editions": [{"edition": "lts", "regex": "("}]}]}`)); err == nil {
		t.Error("Load accepted an invalid edition regex")
	}
}

func TestBanners(t *testing.T) {
	e, err := Load([]byte(`{"rules": [
		{"id": "ftpd", "name": "FTPd", "category": "file-transfer", "banners": ["^220 FTPd "],
		 "versions": [{"source": "banner", "regex": "FTPd ([0-9.]+)"}],
		 "packaged": [{"source": "banner", "regex": "\\(Debian\\)"}]},
		{"id": "untitled", "name": "Untitled", "category": "cms", "title": "^$"},
		{"id": "nas", "name": "NAS", "category": "storage", "admin": true, "body": ["nasLogin"], "banners": ["^220 NAS FTP"]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	ids := func(r Response) map[string]inventory.Technology {
		out := map[string]inventory.Technology{}
		for _, tech := range e.Identify(r) {
			out[tech.ID] = tech
		}
		return out
	}
	got := ids(NewBanner("220 FTPd 2.1.4 (Debian) ready"))
	if len(got) != 1 || got["ftpd"].Version != "2.1.4" || !got["ftpd"].Packaged || !strings.HasPrefix(got["ftpd"].Evidence, "banner ") {
		t.Errorf("FTP greeting: %+v", got)
	}
	// A greeting is never matched by patterns meant for web pages, even one
	// that matches its empty title.
	if got := ids(NewBanner("SSH-2.0-OpenSSH_9.6")); len(got) != 0 {
		t.Errorf("SSH greeting: %+v", got)
	}
	// A web page that quotes a greeting is not that service.
	page := `<html><head><title>220 FTPd 2.1.4 ready</title></head><body>220 FTPd 2.1.4 ready</body></html>`
	if _, ok := ids(NewResponse(header("Server", "220 FTPd 2.1.4"), "/", page))["ftpd"]; ok {
		t.Error("a web page matched a banner pattern")
	}
	// The admin flag describes a product's web interface, not its other
	// services.
	if tech, ok := ids(NewBanner("220 NAS FTP server ready"))["nas"]; !ok || tech.Admin {
		t.Errorf("NAS FTP greeting: %+v, %v; want the product without the admin flag", tech, ok)
	}
	if tech, ok := ids(NewResponse(header(), "/", "<script>nasLogin()</script>"))["nas"]; !ok || !tech.Admin {
		t.Errorf("NAS web page: %+v, %v; want the admin flag", tech, ok)
	}
	if _, err := Load([]byte(`{"rules": [{"id": "x", "name": "X", "category": "mail", "banners": ["("]}]}`)); err == nil {
		t.Error("Load accepted an invalid banner pattern")
	}
}

// sample is a response or greeting a product really sends, with the version
// a rule should read from it.
type sample struct {
	ID      string            `json:"id"`
	Note    string            `json:"note"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Banner  string            `json:"banner"`
	Version string            `json:"version"`
}

// TestSamples checks every rule against samples of what the product sends,
// and requires at least one sample per rule.
func TestSamples(t *testing.T) {
	data, err := os.ReadFile("testdata/samples.json")
	if err != nil {
		t.Fatal(err)
	}
	var samples []sample
	if err := json.Unmarshal(data, &samples); err != nil {
		t.Fatal(err)
	}
	e := engine(t)
	sampled := map[string]bool{}
	for i, s := range samples {
		r := NewBanner(s.Banner)
		if s.Banner == "" {
			h := http.Header{}
			for k, v := range s.Headers {
				// Several values of one header are separated by newlines.
				for _, line := range strings.Split(v, "\n") {
					h.Add(k, line)
				}
			}
			path := s.Path
			if path == "" {
				path = "/"
			}
			r = NewResponse(h, path, s.Body)
		}
		var got []string
		found := false
		for _, tech := range e.Identify(r) {
			got = append(got, tech.ID)
			if tech.ID == s.ID {
				found = true
				if tech.Version != s.Version {
					t.Errorf("sample %d (%s, %s): version %q, want %q", i, s.ID, s.Note, tech.Version, s.Version)
				}
			}
		}
		if !found {
			t.Errorf("sample %d (%s, %s): not identified; got %v", i, s.ID, s.Note, got)
		}
		sampled[s.ID] = true
	}
	for _, r := range e.Rules() {
		if !sampled[r.ID] {
			t.Errorf("rule %s has no sample in testdata/samples.json", r.ID)
		}
	}
}

// A page titled RouterOS is MikroTik's only with MikroTik's logo on it.
func TestRouterOSTitleNeedsTheLogo(t *testing.T) {
	e := engine(t)
	if _, ok := identify(e, header(), "/", "<html><head><title>RouterOS</title></head><body>Our router guide</body></html>")["mikrotik-routeros"]; ok {
		t.Error("a page merely titled RouterOS was taken for WebFig")
	}
}

func TestServerCheck(t *testing.T) {
	e := engine(t)
	headers, ok := e.ServerCheck("nextjs-app-router")
	if !ok || headers["RSC"] != "1" {
		t.Fatalf("server check = %v, %v", headers, ok)
	}
	if _, ok := e.ServerCheck("wordpress"); ok {
		t.Error("WordPress has a server check")
	}
	html := NewResponse(header("Content-Type", "text/html; charset=utf-8"), "/", "<html></html>")
	cases := []struct {
		name   string
		status int
		r      Response
		static bool
	}{
		{"file server ignores the header", 200, html, true},
		{"application answers with the component payload", 200, NewResponse(header("Content-Type", "text/x-component"), "/", "0:{}"), false},
		{"application redirects to add _rsc", 307, NewResponse(header("Location", "/?_rsc=abc12"), "/", ""), false},
		{"error page is not proof of a file server", 404, html, false},
		{"other answer", 200, NewResponse(header("Content-Type", "application/json"), "/", "{}"), false},
	}
	for _, c := range cases {
		if got := e.StaticCopy("nextjs-app-router", c.status, c.r); got != c.static {
			t.Errorf("%s: static = %v", c.name, got)
		}
	}
	if e.StaticCopy("wordpress", 200, html) {
		t.Error("a rule without a server check reported a static copy")
	}
}

func TestLoadRejectsBadServerChecks(t *testing.T) {
	for name, check := range map[string]string{
		"no headers":      `{"server": [{"source": "body", "regex": "x"}], "static": {"source": "body", "regex": "y"}}`,
		"no server match": `{"headers": {"X-A": "1"}, "static": {"source": "body", "regex": "y"}}`,
		"cookie header":   `{"headers": {"Cookie": "a=b"}, "server": [{"source": "body", "regex": "x"}], "static": {"source": "body", "regex": "y"}}`,
		"header newline":  `{"headers": {"X-A": "1\r\nX-B: 2"}, "server": [{"source": "body", "regex": "x"}], "static": {"source": "body", "regex": "y"}}`,
		"bad source":      `{"headers": {"X-A": "1"}, "server": [{"source": "cookie", "regex": "x"}], "static": {"source": "body", "regex": "y"}}`,
	} {
		doc := `{"rules": [{"id": "x", "name": "X", "category": "cms", "body": ["x"], "server": ` + check + `}]}`
		if _, err := Load([]byte(doc)); err == nil {
			t.Errorf("%s: Load succeeded", name)
		}
	}
}
