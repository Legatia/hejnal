// Package iac finds settings in infrastructure code that open a way in:
// admin and database ports open to the whole internet, public storage
// buckets and databases, policies that allow everything, and containers
// that control their host.
//
// It reads Terraform (.tf files and `terraform show -json` plans),
// CloudFormation templates, Kubernetes manifests and Compose files, with
// its own small readers: no Terraform, no cloud access, nothing run. Only
// literal values count; a value the code computes (a variable, a function,
// a !Ref) never makes a finding, so the list stays short and every item is
// something the file says outright.
package iac

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Rules, from most to least urgent.
const (
	RuleOpenAdminPort  = "open-admin-port"
	RulePublicBucket   = "public-bucket"
	RulePublicDatabase = "public-database"
	RulePrivileged     = "privileged-container"
	RuleWildcardPolicy = "wildcard-policy"
	RuleHostNamespace  = "host-namespace"
)

// Scores rate each rule as Hejnal rates other findings.
var Scores = map[string]int{
	RuleOpenAdminPort:  75,
	RulePublicBucket:   70,
	RulePublicDatabase: 70,
	RulePrivileged:     65,
	RuleWildcardPolicy: 55,
	RuleHostNamespace:  50,
}

// Issue is one setting that opens a way in.
type Issue struct {
	Rule string `json:"rule"`
	// Resource names what the setting is on, such as
	// "aws_security_group.web" or "Deployment/api".
	Resource string `json:"resource"`
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	// Detail says exactly what was found, such as "port 22 open to
	// 0.0.0.0/0".
	Detail string `json:"detail"`
}

// MaxFileSize is the largest file read: 8 MiB.
const MaxFileSize = 8 << 20

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".terraform": true, ".venv": true, "venv": true}

// ScanDir checks every infrastructure file under root.
func ScanDir(ctx context.Context, root string) ([]Issue, error) {
	var out []Issue
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if p != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !candidate(d.Name()) {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
		f.Close()
		if err != nil || len(data) > MaxFileSize {
			return nil
		}
		out = append(out, Check(filepath.ToSlash(rel), data)...)
		return nil
	})
	return out, err
}

func candidate(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".tf", ".yaml", ".yml", ".json", ".template":
		return true
	}
	return false
}

// Check reads one file and returns the issues in it; name decides the
// format and is what each Issue's File says.
func Check(name string, data []byte) []Issue {
	c := &checker{file: name}
	ext := strings.ToLower(path.Ext(name))
	switch ext {
	case ".tf":
		for _, b := range parseHCL(string(data)) {
			if (b.Type == "resource" || b.Type == "data") && len(b.Labels) == 2 {
				addr := b.Labels[0] + "." + b.Labels[1]
				if b.Type == "data" {
					addr = "data." + addr
				}
				c.terraform(b.Labels[0], addr, b.Line, b.Body)
			}
		}
	case ".json", ".template":
		var doc map[string]any
		if json.Unmarshal(data, &doc) != nil {
			if ext == ".template" {
				for _, d := range parseYAML(data) {
					c.document(d)
				}
			}
			return c.issues
		}
		c.document(doc)
	default:
		// Helm templates are not YAML until rendered.
		if strings.Contains(string(data), "{{") {
			return nil
		}
		for _, d := range parseYAML(data) {
			c.document(d)
		}
	}
	return c.issues
}

// document checks one parsed JSON or YAML document of whatever kind.
func (c *checker) document(d any) {
	m, ok := d.(map[string]any)
	if !ok {
		return
	}
	switch {
	case m["planned_values"] != nil || m["format_version"] != nil && m["resource_changes"] != nil:
		c.plan(m)
	case m["Resources"] != nil && (m["AWSTemplateFormatVersion"] != nil || hasAWSType(m["Resources"])):
		c.cloudFormation(m)
	case str(m["apiVersion"]) != "" && str(m["kind"]) != "":
		c.kubernetes(m)
	case m["services"] != nil:
		c.compose(m)
	}
}

func hasAWSType(v any) bool {
	rs, _ := v.(map[string]any)
	for _, r := range rs {
		if rm, ok := r.(map[string]any); ok && strings.HasPrefix(str(rm["Type"]), "AWS::") {
			return true
		}
	}
	return false
}

type checker struct {
	file   string
	issues []Issue
}

func (c *checker) add(rule, resource string, line int, detail string) {
	c.issues = append(c.issues, Issue{Rule: rule, Resource: resource, File: c.file, Line: line, Detail: detail})
}

// Helpers on the generic values the readers return.

func str(v any) string {
	s, _ := v.(string)
	return s
}

func isTrue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	}
	return false
}

// list returns v as a list: a single value becomes a list of one.
func list(v any) []any {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		return x
	}
	return []any{v}
}

func get(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func lineOf(v any, fallback int) int {
	if m, ok := v.(map[string]any); ok {
		switch n := m[LineKey].(type) {
		case int:
			return n
		case float64:
			return int(n)
		}
	}
	return fallback
}

func number(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case string:
		n := 0
		if x == "" {
			return 0, false
		}
		for _, r := range x {
			if r < '0' || r > '9' {
				return 0, false
			}
			n = n*10 + int(r-'0')
			if n > 1<<20 {
				return 0, false
			}
		}
		return n, true
	}
	return 0, false
}
