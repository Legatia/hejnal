package fingerprint

import (
	"net/http"
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
