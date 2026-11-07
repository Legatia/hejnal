package euvd

import (
	"slices"
	"strings"

	"github.com/Legatia/hejnal/kev"
)

// Stats says what Merge added to a catalog.
type Stats struct {
	// IDs is how many of the catalog's flaws got an EUVD ID.
	IDs int
	// ENISAOnly is how many flaws only ENISA lists were added.
	ENISAOnly int
	// Earlier is how many of CISA's flaws ENISA listed first.
	Earlier int
}

// Merge adds ENISA's list to CISA's catalog: the EUVD ID and the date ENISA
// listed a flaw before CISA to CISA's entries, and a new entry for each flaw
// that only ENISA lists. records holds EUVD records by EUVD ID, for the
// description and advisory links of those flaws; a missing record leaves
// them out. Merging the same list twice changes nothing.
//
// CISA's catalog decides which flaws CISA lists: an entry the dump marks as
// CISA's but CISA's current catalog lacks was probably withdrawn, so it is
// not added.
func Merge(cat *kev.Catalog, entries []Entry, records map[string]*Record) Stats {
	var st Stats
	byCVE := make(map[string]int, len(cat.Vulnerabilities))
	for i, v := range cat.Vulnerabilities {
		byCVE[v.CVEID] = i
	}
	for _, e := range entries {
		if i, ok := byCVE[e.CVEID]; ok {
			v := &cat.Vulnerabilities[i]
			if v.ENISAOnly {
				continue
			}
			if v.EUVDID == "" {
				st.IDs++
			}
			v.EUVDID = e.EUVDID
			v.ENISA = e.ENISA()
			// The dump's date is the earliest of the two lists.
			if v.ENISA && v.DateAdded != "" && e.DateAdded < v.DateAdded {
				if v.ENISAEarlier == "" {
					st.Earlier++
				}
				v.ENISAEarlier = e.DateAdded
			}
			continue
		}
		if !e.ENISA() || e.VendorProject == "" || e.Product == "" {
			continue
		}
		v := kev.Vulnerability{
			CVEID:             e.CVEID,
			VendorProject:     vendorName(e.VendorProject),
			Product:           productName(e.Product),
			VulnerabilityName: flawName(e),
			DateAdded:         e.DateAdded,
			EUVDID:            e.EUVDID,
			ENISA:             true,
			ENISAOnly:         true,
		}
		if rec := records[e.EUVDID]; rec != nil {
			v.ShortDescription = rec.Description
			v.Notes = strings.Join(rec.References, "; ")
		}
		byCVE[v.CVEID] = len(cat.Vulnerabilities)
		cat.Vulnerabilities = append(cat.Vulnerabilities, v)
		st.ENISAOnly++
		st.IDs++
	}
	return st
}

// ENISAOnly returns the entries only ENISA lists that are not in the catalog:
// the ones Merge adds, and whose records are worth fetching.
func ENISAOnly(cat *kev.Catalog, entries []Entry) []Entry {
	have := make(map[string]bool, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		if !v.ENISAOnly {
			have[v.CVEID] = true
		}
	}
	var out []Entry
	for _, e := range entries {
		if e.ENISA() && !have[e.CVEID] && e.VendorProject != "" && e.Product != "" {
			out = append(out, e)
		}
	}
	return out
}

// genericProducts are product names that say nothing about the product.
// They become CISA's "Multiple Products", which fingerprint rules only match
// together with a description that names their product.
var genericProducts = []string{"various", "multiple", "multiple products", "all", "all products", "n/a", "-"}

func productName(p string) string {
	if slices.Contains(genericProducts, strings.ToLower(p)) {
		return "Multiple Products"
	}
	return p
}

// vendorAliases maps vendor names ENISA spells differently from CISA, which
// the fingerprint rules follow.
var vendorAliases = map[string]string{
	"checkpoint":         "Check Point",
	"oracle corporation": "Oracle",
}

func vendorName(v string) string {
	if a, ok := vendorAliases[strings.ToLower(v)]; ok {
		return a
	}
	return v
}

// flawName names a flaw only ENISA lists, which rarely has a name of its own.
func flawName(e Entry) string {
	product := productName(e.Product)
	name := product
	if product == "Multiple Products" {
		name = e.VendorProject + " products"
	} else if !strings.HasPrefix(strings.ToLower(product), strings.ToLower(e.VendorProject)) {
		name = e.VendorProject + " " + product
	}
	name += " vulnerability"
	if e.VulnerabilityName != "" {
		name += " (" + e.VulnerabilityName + ")"
	}
	return name
}
