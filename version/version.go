// Package version holds the build version of Hejnal.
package version

import (
	"runtime/debug"
	"strings"
)

// dev is the version of a build that says nothing about where it came from.
const dev = "0.1.0-dev"

// Version is set at build time by the release build with
// -ldflags "-X github.com/Legatia/hejnal/version.Version=0.1.0".
// Other builds take it from the module version Go records in the binary:
// the tag for "go install ...@v0.5.0", or a pseudo-version for a build
// from a Git checkout.
var Version = dev

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		Version = resolve(Version, info.Main.Version)
	}
}

// resolve keeps a version set by the release build and otherwise uses the
// module version, without its leading "v" so both kinds of build print alike.
func resolve(stamped, module string) string {
	if stamped != dev || module == "" || module == "(devel)" {
		return stamped
	}
	return strings.TrimPrefix(module, "v")
}

// UserAgent identifies Hejnal in every HTTP request it makes, so the owners of
// scanned systems can recognise the traffic in their logs.
func UserAgent() string {
	return "hejnal/" + Version + " (+https://github.com/Legatia/hejnal)"
}
