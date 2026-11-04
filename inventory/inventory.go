// Package inventory defines the asset inventory Hejnal builds for an
// organisation: hosts, the services they expose and the software behind them.
package inventory

import "time"

// Technology is a product identified on a service.
type Technology struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Category string `json:"category"`
	Admin    bool   `json:"admin,omitempty"`
	// Packaged is set for Linux distribution builds, which get security
	// fixes without a new upstream version number.
	Packaged bool   `json:"packaged,omitempty"`
	Evidence string `json:"evidence"`
}

// TLSInfo describes the certificate a service presented.
type TLSInfo struct {
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"notAfter"`
	DNSNames []string  `json:"dnsNames,omitempty"`
}

// Service is an open port on a host.
type Service struct {
	Port         int          `json:"port"`
	Scheme       string       `json:"scheme"`
	URL          string       `json:"url,omitempty"`
	FinalURL     string       `json:"finalUrl,omitempty"`
	Status       int          `json:"status,omitempty"`
	Title        string       `json:"title,omitempty"`
	Server       string       `json:"server,omitempty"`
	Banner       string       `json:"banner,omitempty"`
	TLS          *TLSInfo     `json:"tls,omitempty"`
	Technologies []Technology `json:"technologies,omitempty"`
	// Exposures are files found readable by the opt-in checks.
	Exposures []Exposure `json:"exposures,omitempty"`
}

// Exposure is a file that should not be public, found by an opt-in check.
// Evidence describes it without its contents.
type Exposure struct {
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Evidence string `json:"evidence"`
}

// Asset is one host and what it exposes.
type Asset struct {
	Host     string    `json:"host"`
	Source   string    `json:"source"`
	IPs      []string  `json:"ips,omitempty"`
	Services []Service `json:"services,omitempty"`
	Errors   []string  `json:"errors,omitempty"`
}

// Inventory is the result of one discovery run.
type Inventory struct {
	Organization string    `json:"organization"`
	GeneratedAt  time.Time `json:"generatedAt"`
	Assets       []Asset   `json:"assets"`
}

// Counts summarises an inventory.
func (inv *Inventory) Counts() (assets, services, technologies int) {
	for _, a := range inv.Assets {
		assets++
		for _, s := range a.Services {
			services++
			technologies += len(s.Technologies)
		}
	}
	return
}
