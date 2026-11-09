package iac

import (
	"reflect"
	"testing"
)

func TestHCL(t *testing.T) {
	src := `# A security group
resource "aws_security_group" "web" {
  name        = "web-${var.env}"
  description = "Web" // comment
  /* block
     comment */
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0", var.office]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }
  tags = merge(local.tags, { Name = "web" })
  count = var.enabled ? 1 : 0
}

resource "aws_iam_policy" "admin" {
  policy = <<EOF
{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
EOF
}

data "aws_iam_policy_document" "x" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_db_instance" "db" {
  publicly_accessible = true
  settings = { a = 1, b = "two" }
}
`
	bs := parseHCL(src)
	if len(bs) != 4 {
		t.Fatalf("%d blocks: %+v", len(bs), bs)
	}
	sg := bs[0]
	if sg.Type != "resource" || !reflect.DeepEqual(sg.Labels, []string{"aws_security_group", "web"}) || sg.Line != 2 {
		t.Errorf("block = %+v", sg)
	}
	if _, ok := sg.Body["name"].(Unknown); !ok || sg.Body["description"] != "Web" {
		t.Errorf("attrs = %#v %#v", sg.Body["name"], sg.Body["description"])
	}
	ing := sg.Body["ingress"].([]any)
	first := ing[0].(map[string]any)
	if len(ing) != 2 || first["from_port"] != 22.0 || first[LineKey] != 7 {
		t.Errorf("ingress = %#v", ing)
	}
	cidrs := first["cidr_blocks"].([]any)
	if cidrs[0] != "0.0.0.0/0" {
		t.Errorf("cidrs = %#v", cidrs)
	}
	if _, ok := cidrs[1].(Unknown); !ok {
		t.Errorf("var in list = %#v", cidrs[1])
	}
	if ing[1].(map[string]any)["cidr_blocks"].([]any)[0] != "0.0.0.0/0" {
		t.Error("multi-line list")
	}
	for _, k := range []string{"tags", "count"} {
		if _, ok := sg.Body[k].(Unknown); !ok {
			t.Errorf("%s = %#v", k, sg.Body[k])
		}
	}
	if bs[1].Body["policy"] != `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}` {
		t.Errorf("heredoc = %#v", bs[1].Body["policy"])
	}
	st := bs[2].Body["statement"].([]any)[0].(map[string]any)
	if !reflect.DeepEqual(st["actions"], []any{"*"}) {
		t.Errorf("statement = %#v", st)
	}
	if bs[3].Body["publicly_accessible"] != true || bs[3].Body["settings"].(map[string]any)["b"] != "two" || bs[3].Line != 38 {
		t.Errorf("db = %+v", bs[3])
	}
}

func FuzzHCL(f *testing.F) {
	f.Add("resource \"a\" \"b\" {\n x = [1, {y = \"${z}\"}]\n c { d = <<E\nq\nE\n }\n}\n")
	f.Add("a = [for x in y : x]\nb = {for k, v in m : k => v}")
	f.Fuzz(func(t *testing.T, s string) { parseHCL(s) })
}
