package iac

import (
	"reflect"
	"testing"
)

func TestYAML(t *testing.T) {
	docs := parseYAML([]byte(`# comment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: "web" # trailing
  labels: {app: web, tier: "front"}
spec:
  template:
    spec:
      hostNetwork: true
      containers:
      - name: app
        image: nginx:1.25
        ports: [80, 443]
        securityContext:
          privileged: true
        args:
          - --x
          - "y: z"
      - name: side
        command: |
          echo hi
          echo there
      volumes:
        - name: sock
          hostPath:
            path: /var/run/docker.sock
---
Resources:
  Web:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: !Ref Name
      SecurityGroupIngress:
        - CidrIp: 0.0.0.0/0
          FromPort: 22
          ToPort: 22
`))
	if len(docs) != 2 {
		t.Fatalf("%d documents", len(docs))
	}
	d := docs[0].(map[string]any)
	if d["kind"] != "Deployment" || d[LineKey] != 2 {
		t.Errorf("doc = %v", d)
	}
	meta := d["metadata"].(map[string]any)
	if meta["name"] != "web" || !reflect.DeepEqual(meta["labels"], map[string]any{"app": "web", "tier": "front"}) {
		t.Errorf("metadata = %v", meta)
	}
	pod := d["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	cs := pod["containers"].([]any)
	c0 := cs[0].(map[string]any)
	if pod["hostNetwork"] != true || c0["securityContext"].(map[string]any)["privileged"] != true || c0[LineKey] != 12 {
		t.Errorf("container = %v", c0)
	}
	if !reflect.DeepEqual(c0["ports"], []any{80.0, 443.0}) || !reflect.DeepEqual(c0["args"], []any{"--x", "y: z"}) {
		t.Errorf("ports/args = %v %v", c0["ports"], c0["args"])
	}
	if cs[1].(map[string]any)["command"] != "echo hi\necho there" {
		t.Errorf("block scalar = %q", cs[1].(map[string]any)["command"])
	}
	vol := pod["volumes"].([]any)[0].(map[string]any)
	if vol["hostPath"].(map[string]any)["path"] != "/var/run/docker.sock" {
		t.Errorf("volume = %v", vol)
	}
	sg := docs[1].(map[string]any)["Resources"].(map[string]any)["Web"].(map[string]any)["Properties"].(map[string]any)
	if _, ok := sg["GroupName"].(Unknown); !ok {
		t.Errorf("!Ref = %#v", sg["GroupName"])
	}
	in := sg["SecurityGroupIngress"].([]any)[0].(map[string]any)
	if in["CidrIp"] != "0.0.0.0/0" || in["FromPort"] != 22.0 {
		t.Errorf("ingress = %v", in)
	}
}

func FuzzYAML(f *testing.F) {
	f.Add("a: [1, {b: [c, d]}, 'e']\n- x\n  - y: |\n   z\n")
	f.Add("k: {a: {b: {c: [[[]]]}}}")
	f.Fuzz(func(t *testing.T, s string) { parseYAML([]byte(s)) })
}
