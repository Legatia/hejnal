package iac

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// adminPorts are ports where a login, an admin API or a database answers:
// open to everyone, they are what attackers scan for.
var adminPorts = []struct {
	port int
	name string
}{
	{22, "SSH"}, {23, "Telnet"}, {3389, "Remote Desktop"}, {5900, "VNC"},
	{2375, "Docker API"}, {2376, "Docker API"}, {6443, "Kubernetes API"}, {10250, "kubelet"}, {2379, "etcd"},
	{3306, "MySQL"}, {5432, "PostgreSQL"}, {1433, "SQL Server"}, {1521, "Oracle"}, {27017, "MongoDB"},
	{6379, "Redis"}, {9200, "Elasticsearch"}, {11211, "Memcached"}, {5984, "CouchDB"}, {9042, "Cassandra"},
}

// world reports whether a source address range is the whole internet.
func world(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0.0.0.0/0", "::/0", "*", "internet", "any", "0.0.0.0":
		return true
	}
	return false
}

// openPorts describes the admin ports a rule opens between from and to, or
// "" if none. all is set for "every port". A rule from 0 to 0 means every
// port only when it covers every protocol, which the caller passes as all.
func openPorts(from, to int, all bool) string {
	if all || from <= 0 && to >= 65535 {
		return "every port"
	}
	var hit []string
	for _, p := range adminPorts {
		if p.port >= from && p.port <= to {
			hit = append(hit, fmt.Sprintf("%s (%d)", p.name, p.port))
		}
	}
	switch {
	case len(hit) == 0:
		return ""
	case len(hit) > 3:
		return fmt.Sprintf("%s and %d more admin ports", strings.Join(hit[:3], ", "), len(hit)-3)
	}
	return strings.Join(hit, ", ")
}

func allProtocols(p any) bool {
	s := strings.ToLower(strings.TrimSpace(fmt.Sprint(p)))
	return s == "-1" || s == "all" || s == "*"
}

// icmp reports whether a rule is for ICMP, whose "ports" are message types
// and codes, not ports.
func icmp(p any) bool {
	switch strings.ToLower(strings.TrimSpace(fmt.Sprint(p))) {
	case "icmp", "icmpv6", "1", "58":
		return true
	}
	return false
}

// hostPath cleans a host path for the hostMounts lookup, so "/var/run/" and
// "/var/run" match alike and "/" stays "/".
func hostPath(p string) string {
	if t := strings.TrimRight(p, "/"); t != "" || p == "" {
		return t
	}
	return "/"
}

// ingress checks one AWS-style ingress rule.
func (c *checker) ingress(resource string, line int, from, to, proto any, cidrs ...any) {
	var open []string
	for _, cs := range cidrs {
		for _, v := range list(cs) {
			if s := str(v); world(s) && !slices.Contains(open, s) {
				open = append(open, s)
			}
		}
	}
	if len(open) == 0 || icmp(proto) {
		return
	}
	f, okf := number(from)
	t, okt := number(to)
	all := allProtocols(proto)
	if !all && (!okf || !okt) {
		return
	}
	if ports := openPorts(f, t, all); ports != "" {
		c.add(RuleOpenAdminPort, resource, line, ports+" open to "+strings.Join(open, " and "))
	}
}

// portRanges reads ports written as "22", "1000-2000" or "*".
func portRanges(v any) (ranges [][2]int, all bool) {
	for _, p := range list(v) {
		s := strings.TrimSpace(fmt.Sprint(p))
		if p == nil {
			continue
		}
		if f, ok := p.(float64); ok {
			s = strconv.Itoa(int(f))
		}
		if s == "*" {
			return nil, true
		}
		a, b, ok := strings.Cut(s, "-")
		lo, ok1 := number(a)
		hi := lo
		ok2 := true
		if ok {
			hi, ok2 = number(b)
		}
		if ok1 && ok2 {
			ranges = append(ranges, [2]int{lo, hi})
		}
	}
	return ranges, false
}

func (c *checker) portList(resource string, line int, ports any, sources []string) {
	ranges, all := portRanges(ports)
	if ports == nil {
		all = true
	}
	desc := ""
	if all {
		desc = "every port"
	} else {
		var parts []string
		for _, r := range ranges {
			if d := openPorts(r[0], r[1], false); d != "" {
				parts = append(parts, d)
			}
		}
		desc = strings.Join(parts, ", ")
	}
	if desc != "" {
		c.add(RuleOpenAdminPort, resource, line, desc+" open to "+strings.Join(sources, " and "))
	}
}

func worldSources(vs ...any) []string {
	var out []string
	for _, v := range vs {
		for _, x := range list(v) {
			if s := str(x); world(s) && !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

var publicACLs = map[string]bool{"public-read": true, "public-read-write": true, "authenticated-read": true,
	"publicread": true, "publicreadwrite": true, "authenticatedread": true}

// policy checks an IAM-style policy document, given as JSON text or a map:
// statements that allow every action on every resource, and, for bucket
// policies, statements that let anyone in without a condition.
func (c *checker) policy(resource string, line int, doc any, bucket bool) {
	if s, ok := doc.(string); ok {
		var m any
		if json.Unmarshal([]byte(s), &m) != nil {
			return
		}
		doc = m
	}
	for _, st := range list(get(doc, "Statement")) {
		effect := str(get(st, "Effect"))
		if effect != "" && effect != "Allow" {
			continue
		}
		if bucket {
			if p := get(st, "Principal"); (str(p) == "*" || hasStar(get(p, "AWS"))) && get(st, "Condition") == nil {
				c.add(RulePublicBucket, resource, line, "the bucket policy lets anyone ("+`"Principal": "*"`+") "+actionsOf(get(st, "Action")))
			}
		}
		if hasStar(get(st, "Action")) && hasStar(get(st, "Resource")) {
			c.add(RuleWildcardPolicy, resource, line, `allows every action ("*") on every resource ("*")`)
		}
	}
}

func hasStar(v any) bool {
	return slices.ContainsFunc(list(v), func(x any) bool { return str(x) == "*" })
}

func actionsOf(v any) string {
	var acts []string
	for _, a := range list(v) {
		if s := str(a); s != "" {
			acts = append(acts, s)
		}
	}
	if len(acts) == 0 {
		return "in"
	}
	if len(acts) > 3 {
		acts = append(acts[:3], "…")
	}
	return strings.Join(acts, ", ")
}

// terraform checks one resource or data source, from a .tf file or a
// plan's planned values.
func (c *checker) terraform(typ, addr string, line int, body map[string]any) {
	at := func(v any) int { return lineOf(v, line) }
	switch typ {
	case "aws_security_group":
		for _, r := range list(body["ingress"]) {
			c.ingress(addr, at(r), get(r, "from_port"), get(r, "to_port"), get(r, "protocol"), get(r, "cidr_blocks"), get(r, "ipv6_cidr_blocks"))
		}
	case "aws_security_group_rule":
		if str(body["type"]) == "ingress" {
			c.ingress(addr, line, body["from_port"], body["to_port"], body["protocol"], body["cidr_blocks"], body["ipv6_cidr_blocks"])
		}
	case "aws_vpc_security_group_ingress_rule":
		from, to := body["from_port"], body["to_port"]
		c.ingress(addr, line, from, to, body["ip_protocol"], body["cidr_ipv4"], body["cidr_ipv6"])
	case "google_compute_firewall":
		if d := str(body["direction"]); d != "" && !strings.EqualFold(d, "INGRESS") {
			return
		}
		src := worldSources(body["source_ranges"])
		if len(src) == 0 {
			return
		}
		for _, a := range list(body["allow"]) {
			if allProtocols(get(a, "protocol")) {
				c.add(RuleOpenAdminPort, addr, at(a), "every port open to "+strings.Join(src, " and "))
				continue
			}
			c.portList(addr, at(a), get(a, "ports"), src)
		}
	case "azurerm_network_security_rule":
		c.azureRule(addr, line, body)
	case "azurerm_network_security_group":
		for _, r := range list(body["security_rule"]) {
			if m, ok := r.(map[string]any); ok {
				c.azureRule(addr, at(r), m)
			}
		}
	case "aws_s3_bucket", "aws_s3_bucket_acl":
		if acl := str(body["acl"]); publicACLs[strings.ToLower(acl)] {
			c.add(RulePublicBucket, addr, line, `acl = "`+acl+`" lets anyone read the bucket`)
		}
	case "aws_s3_bucket_policy":
		c.policy(addr, line, body["policy"], true)
	case "google_storage_bucket_iam_member", "google_storage_bucket_iam_binding":
		for _, m := range append(list(body["member"]), list(body["members"])...) {
			if s := str(m); s == "allUsers" || s == "allAuthenticatedUsers" {
				c.add(RulePublicBucket, addr, line, s+" may "+orRole(str(body["role"])))
			}
		}
	case "google_storage_bucket_acl":
		if a := str(body["predefined_acl"]); strings.HasPrefix(strings.ToLower(a), "public") {
			c.add(RulePublicBucket, addr, line, `predefined_acl = "`+a+`" lets anyone read the bucket`)
		}
	case "azurerm_storage_container":
		if t := str(body["container_access_type"]); t == "blob" || t == "container" {
			c.add(RulePublicBucket, addr, line, `container_access_type = "`+t+`" lets anyone read its files`)
		}
	case "aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster", "aws_dms_replication_instance":
		if isTrue(body["publicly_accessible"]) {
			c.add(RulePublicDatabase, addr, line, "publicly_accessible = true gives it an address on the internet")
		}
	case "google_sql_database_instance":
		for _, s := range list(body["settings"]) {
			for _, ip := range list(get(s, "ip_configuration")) {
				for _, n := range list(get(ip, "authorized_networks")) {
					if world(str(get(n, "value"))) {
						c.add(RulePublicDatabase, addr, at(n), "authorized_networks lets in "+str(get(n, "value")))
					}
				}
			}
		}
	case "azurerm_postgresql_firewall_rule", "azurerm_mysql_firewall_rule", "azurerm_mssql_firewall_rule", "azurerm_sql_firewall_rule",
		"azurerm_postgresql_flexible_server_firewall_rule", "azurerm_mysql_flexible_server_firewall_rule", "azurerm_mariadb_firewall_rule":
		if str(body["start_ip_address"]) == "0.0.0.0" && str(body["end_ip_address"]) == "255.255.255.255" {
			c.add(RulePublicDatabase, addr, line, "the firewall rule lets in every address, 0.0.0.0 to 255.255.255.255")
		}
	case "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy":
		c.policy(addr, line, body["policy"], false)
	case "aws_iam_policy_document":
		for _, st := range list(body["statement"]) {
			if e := str(get(st, "effect")); e != "" && e != "Allow" {
				continue
			}
			if hasStar(get(st, "actions")) && hasStar(get(st, "resources")) {
				c.add(RuleWildcardPolicy, addr, at(st), `allows every action ("*") on every resource ("*")`)
			}
		}
	}
}

func orRole(r string) string {
	if r == "" {
		return "use the bucket"
	}
	return "use it as " + r
}

func (c *checker) azureRule(addr string, line int, r map[string]any) {
	if !strings.EqualFold(str(r["direction"]), "Inbound") || !strings.EqualFold(str(r["access"]), "Allow") {
		return
	}
	src := worldSources(r["source_address_prefix"], r["source_address_prefixes"])
	if len(src) == 0 {
		return
	}
	ports := r["destination_port_range"]
	if ports == nil {
		ports = r["destination_port_ranges"]
	}
	if ports == nil {
		return
	}
	c.portList(addr, line, ports, src)
}

// plan checks the planned values of `terraform show -json`.
func (c *checker) plan(m map[string]any) {
	var walk func(mod any, depth int)
	walk = func(mod any, depth int) {
		if depth > 16 {
			return
		}
		for _, r := range list(get(mod, "resources")) {
			body, _ := get(r, "values").(map[string]any)
			if body != nil {
				c.terraform(str(get(r, "type")), str(get(r, "address")), 0, body)
			}
		}
		for _, child := range list(get(mod, "child_modules")) {
			walk(child, depth+1)
		}
	}
	walk(get(m, "planned_values", "root_module"), 0)
}

// cloudFormation checks a template's resources.
func (c *checker) cloudFormation(m map[string]any) {
	rs, _ := m["Resources"].(map[string]any)
	for id, r := range rs {
		if id == LineKey {
			continue
		}
		props := get(r, "Properties")
		line := lineOf(r, 0)
		at := func(v any) int { return lineOf(v, line) }
		switch str(get(r, "Type")) {
		case "AWS::EC2::SecurityGroup":
			for _, in := range list(get(props, "SecurityGroupIngress")) {
				c.ingress(id, at(in), get(in, "FromPort"), get(in, "ToPort"), get(in, "IpProtocol"), get(in, "CidrIp"), get(in, "CidrIpv6"))
			}
		case "AWS::EC2::SecurityGroupIngress":
			c.ingress(id, line, get(props, "FromPort"), get(props, "ToPort"), get(props, "IpProtocol"), get(props, "CidrIp"), get(props, "CidrIpv6"))
		case "AWS::S3::Bucket":
			if acl := str(get(props, "AccessControl")); publicACLs[strings.ToLower(acl)] {
				c.add(RulePublicBucket, id, line, "AccessControl: "+acl+" lets anyone read the bucket")
			}
		case "AWS::S3::BucketPolicy":
			c.policy(id, line, get(props, "PolicyDocument"), true)
		case "AWS::RDS::DBInstance", "AWS::Redshift::Cluster":
			if isTrue(get(props, "PubliclyAccessible")) {
				c.add(RulePublicDatabase, id, line, "PubliclyAccessible: true gives it an address on the internet")
			}
		case "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy":
			c.policy(id, line, get(props, "PolicyDocument"), false)
		case "AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group":
			for _, p := range list(get(props, "Policies")) {
				c.policy(id, at(p), get(p, "PolicyDocument"), false)
			}
		}
	}
}

// hostMounts are host paths whose mount hands a container its host.
var hostMounts = map[string]string{
	"/": "the host's whole file system", "/var/run/docker.sock": "the Docker socket", "/run/docker.sock": "the Docker socket",
	"/run/containerd/containerd.sock": "the containerd socket", "/var/run/crio/crio.sock": "the CRI-O socket",
	"/proc": "the host's /proc", "/etc": "the host's /etc", "/root": "the host's /root", "/var/lib/kubelet": "the kubelet's files",
}

// kubernetes checks the pod spec of a workload.
func (c *checker) kubernetes(m map[string]any) {
	kind, name := str(m["kind"]), str(get(m, "metadata", "name"))
	var spec any
	switch kind {
	case "Pod":
		spec = m["spec"]
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController":
		spec = get(m, "spec", "template", "spec")
	case "CronJob":
		spec = get(m, "spec", "jobTemplate", "spec", "template", "spec")
	default:
		return
	}
	if spec == nil {
		return
	}
	resource := kind + "/" + name
	line := lineOf(spec, lineOf(m, 0))
	for _, k := range []string{"containers", "initContainers", "ephemeralContainers"} {
		for _, ct := range list(get(spec, k)) {
			if isTrue(get(ct, "securityContext", "privileged")) {
				c.add(RulePrivileged, resource, lineOf(ct, line), "container "+str(get(ct, "name"))+" runs privileged, with full access to the host")
			}
		}
	}
	for _, v := range list(get(spec, "volumes")) {
		p := hostPath(str(get(v, "hostPath", "path")))
		if what, ok := hostMounts[p]; ok {
			c.add(RulePrivileged, resource, lineOf(v, line), "volume "+str(get(v, "name"))+" mounts "+what+" ("+p+")")
		}
	}
	var ns []string
	for _, k := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		if isTrue(get(spec, k)) {
			ns = append(ns, k)
		}
	}
	if len(ns) > 0 {
		c.add(RuleHostNamespace, resource, line, strings.Join(ns, ", ")+" share the host's "+nsWhat(ns))
	}
}

func nsWhat(ns []string) string {
	var w []string
	for _, n := range ns {
		w = append(w, map[string]string{"hostNetwork": "network", "hostPID": "processes", "hostIPC": "shared memory"}[n])
	}
	return strings.Join(w, ", ")
}

// compose checks a Compose file's services.
func (c *checker) compose(m map[string]any) {
	svcs, _ := m["services"].(map[string]any)
	for name, s := range svcs {
		if name == LineKey {
			continue
		}
		line := lineOf(s, 0)
		resource := "service " + name
		if isTrue(get(s, "privileged")) {
			c.add(RulePrivileged, resource, line, "privileged: true gives it full access to the host")
		}
		for _, v := range list(get(s, "volumes")) {
			src := str(get(v, "source"))
			if s, ok := v.(string); ok {
				src, _, _ = strings.Cut(s, ":")
			}
			src = hostPath(src)
			if what, ok := hostMounts[src]; ok {
				c.add(RulePrivileged, resource, line, "mounts "+what+" ("+src+")")
			}
		}
		var ns []string
		if str(get(s, "network_mode")) == "host" {
			ns = append(ns, "hostNetwork")
		}
		if str(get(s, "pid")) == "host" {
			ns = append(ns, "hostPID")
		}
		if len(ns) > 0 {
			c.add(RuleHostNamespace, resource, line, "shares the host's "+nsWhat(ns))
		}
	}
}
