package iac

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestScanDir(t *testing.T) {
	issues, err := ScanDir(context.Background(), "testdata/infra")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, i := range issues {
		got = append(got, fmt.Sprintf("%s:%d %s %s: %s", i.File, i.Line, i.Rule, i.Resource, i.Detail))
	}
	sort.Strings(got)
	want := []string{
		`cfn/stack.yaml:8 open-admin-port WebSG: MySQL (3306) open to 0.0.0.0/0`,
		`cfn/stack.yaml:16 wildcard-policy Admin: allows every action ("*") on every resource ("*")`,
		`compose.yaml:3 privileged-container service ci: mounts the Docker socket (/var/run/docker.sock)`,
		`compose.yaml:7 host-namespace service web: shares the host's network`,
		`k8s/agent.yaml:10 privileged-container DaemonSet/agent: container agent runs privileged, with full access to the host`,
		`k8s/agent.yaml:15 privileged-container DaemonSet/agent: volume sock mounts the Docker socket (/var/run/docker.sock)`,
		`k8s/agent.yaml:8 host-namespace DaemonSet/agent: hostPID share the host's processes`,
		`tf/main.tf:2 open-admin-port aws_security_group.bastion: SSH (22) open to 0.0.0.0/0`,
		`tf/main.tf:31 open-admin-port aws_vpc_security_group_ingress_rule.all: every port open to ::/0`,
		`tf/main.tf:37 public-bucket aws_s3_bucket_acl.assets: acl = "public-read" lets anyone read the bucket`,
		`tf/main.tf:42 public-database aws_db_instance.main: publicly_accessible = true gives it an address on the internet`,
		`tf/main.tf:52 wildcard-policy data.aws_iam_policy_document.ci: allows every action ("*") on every resource ("*")`,
		`tf/main.tf:62 public-bucket aws_s3_bucket_policy.site: the bucket policy lets anyone ("Principal": "*") s3:GetObject`,
		`tf/main.tf:71 open-admin-port google_compute_firewall.rdp: Remote Desktop (3389) open to 0.0.0.0/0`,
		`tf/main.tf:78 open-admin-port azurerm_network_security_group.nsg: Redis (6379) open to *`,
		`tf/main.tf:87 public-bucket google_storage_bucket_iam_member.pub: allUsers may use it as roles/storage.objectViewer`,
		`tf/plan.json:0 public-database module.db.aws_db_instance.this: publicly_accessible = true gives it an address on the internet`,
	}
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\n\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestOpenPorts(t *testing.T) {
	if got := openPorts(1, 65535, false); got != "every port" && !strings.Contains(got, "more admin ports") {
		t.Errorf("wide range = %q", got)
	}
	if got := openPorts(8080, 8090, false); got != "" {
		t.Errorf("no admin port: %q", got)
	}
	if got := openPorts(5400, 5500, false); got != "PostgreSQL (5432)" {
		t.Errorf("range = %q", got)
	}
}
