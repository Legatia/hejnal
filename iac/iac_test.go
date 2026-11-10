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

func TestAnchorsAndTagsOnTheirOwnLine(t *testing.T) {
	// A Compose file whose shared settings come first, as an anchor.
	compose := `x-common: &common
  restart: always
  logging:
    driver: json-file

services:
  web:
    <<: *common
    image: nginx
    privileged: true
`
	if got := rulesOf(Check("compose.yaml", []byte(compose))); got != "privileged-container" {
		t.Errorf("compose after an anchor: %q", got)
	}
	// A CloudFormation tag whose arguments follow as a list.
	cfn := `Resources:
  Web:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: !If
        - IsProd
        - prod
        - dev
      SecurityGroupIngress:
        - CidrIp: 0.0.0.0/0
          FromPort: 22
          ToPort: 22
`
	if got := rulesOf(Check("stack.yaml", []byte(cfn))); got != "open-admin-port" {
		t.Errorf("template after a tag: %q", got)
	}
	// A list item that is only an anchor keeps its block.
	docs := parseYAML([]byte("items:\n  - &one\n    name: a\n  - name: b\n"))
	items, _ := docs[0].(map[string]any)["items"].([]any)
	if len(items) != 2 || get(items[0], "name") != "a" || get(items[1], "name") != "b" {
		t.Errorf("anchored list item: %v", items)
	}
}

func rulesOf(issues []Issue) string {
	var r []string
	for _, i := range issues {
		r = append(r, i.Rule)
	}
	sort.Strings(r)
	return strings.Join(r, ",")
}

func TestICMPAndPortZero(t *testing.T) {
	tf := `resource "aws_security_group" "ping" {
  ingress {
    protocol    = "icmp"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    protocol    = "tcp"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "everything" {
  ingress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`
	issues := Check("main.tf", []byte(tf))
	if len(issues) != 1 || issues[0].Resource != "aws_security_group.everything" || !strings.HasPrefix(issues[0].Detail, "every port") {
		t.Errorf("ICMP and port 0 are not every port: %+v", issues)
	}
}

func TestHostRootMount(t *testing.T) {
	compose := `services:
  long:
    image: alpine
    volumes:
      - type: bind
        source: /
        target: /host
  short:
    image: alpine
    volumes:
      - /:/host:ro
  data:
    image: alpine
    volumes:
      - ./data:/data
`
	var got []string
	for _, i := range Check("compose.yaml", []byte(compose)) {
		got = append(got, i.Resource+": "+i.Detail)
	}
	sort.Strings(got)
	want := "service long: mounts the host's whole file system (/)\nservice short: mounts the host's whole file system (/)"
	if strings.Join(got, "\n") != want {
		t.Errorf("host root mounts:\n%s", strings.Join(got, "\n"))
	}
	k8s := `apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  containers:
  - name: c
    image: alpine
  volumes:
  - name: root
    hostPath:
      path: /
`
	if got := rulesOf(Check("pod.yaml", []byte(k8s))); got != "privileged-container" {
		t.Errorf("kubernetes host root: %q", got)
	}
}
