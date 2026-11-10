package version

import "testing"

func TestResolve(t *testing.T) {
	cases := []struct {
		name, stamped, module, want string
	}{
		{"release build keeps its version", "0.5.0", "v0.5.0", "0.5.0"},
		{"release build ignores a different module version", "0.5.0", "(devel)", "0.5.0"},
		{"go install of a tag", dev, "v0.5.0", "0.5.0"},
		{"build from a checkout", dev, "v0.5.1-0.20261110093000-4d285fb801a5+dirty", "0.5.1-0.20261110093000-4d285fb801a5+dirty"},
		{"go run or test without a version", dev, "(devel)", dev},
		{"no module version at all", dev, "", dev},
	}
	for _, c := range cases {
		if got := resolve(c.stamped, c.module); got != c.want {
			t.Errorf("%s: resolve(%q, %q) = %q, want %q", c.name, c.stamped, c.module, got, c.want)
		}
	}
}
