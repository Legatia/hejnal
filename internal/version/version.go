// Package version holds the build version of Hejnal.
package version

// Version is overridden at build time with
// -ldflags "-X github.com/Legatia/hejnal/internal/version.Version=v0.1.0".
var Version = "0.1.0-dev"

// UserAgent identifies Hejnal in every HTTP request it makes, so the owners of
// scanned systems can recognise the traffic in their logs.
func UserAgent() string {
	return "hejnal/" + Version + " (+https://github.com/Legatia/hejnal)"
}
