// Package epss fetches FIRST's Exploit Prediction Scoring System (EPSS)
// scores: the estimated probability that a flaw is exploited in the next 30 days.
package epss

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// DefaultAPI is FIRST's public EPSS API.
const DefaultAPI = "https://api.first.org/data/v1/epss"

// batchSize keeps each request URL short; the API accepts comma-separated CVEs.
const batchSize = 100

// Score is the EPSS estimate for one CVE.
type Score struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

// flexFloat accepts both JSON numbers and numeric strings, because the API
// returns scores as strings. Scores are probabilities, so values outside 0–1
// are clamped and non-numbers are rejected.
type flexFloat float64

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return err
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return fmt.Errorf("invalid score %q", s)
	}
	*f = flexFloat(min(1, max(0, v)))
	return nil
}

// The API's CVE IDs and dates appear in reports, so they must look right.
var (
	cveRE  = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	dateRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

type apiResponse struct {
	Status string `json:"status"`
	Data   []struct {
		CVE        string    `json:"cve"`
		EPSS       flexFloat `json:"epss"`
		Percentile flexFloat `json:"percentile"`
		Date       string    `json:"date"`
	} `json:"data"`
}

// ParseResponse decodes one API response.
func ParseResponse(r io.Reader) (map[string]Score, error) {
	var resp apiResponse
	if err := json.NewDecoder(io.LimitReader(r, 8<<20)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("epss: decode: %w", err)
	}
	if resp.Status != "" && !strings.EqualFold(resp.Status, "OK") {
		return nil, fmt.Errorf("epss: api status %q", resp.Status)
	}
	out := make(map[string]Score, len(resp.Data))
	for _, d := range resp.Data {
		cve := strings.ToUpper(strings.TrimSpace(d.CVE))
		if !cveRE.MatchString(cve) {
			continue
		}
		date := strings.TrimSpace(d.Date)
		if !dateRE.MatchString(date) {
			date = ""
		}
		out[cve] = Score{CVE: cve, EPSS: float64(d.EPSS), Percentile: float64(d.Percentile), Date: date}
	}
	return out, nil
}

// Fetch looks up scores for the given CVEs in batches.
func Fetch(ctx context.Context, client *http.Client, base, userAgent string, cves []string) (map[string]Score, error) {
	list := slices.Clone(cves)
	slices.Sort(list)
	list = slices.Compact(list)
	out := make(map[string]Score, len(list))
	for start := 0; start < len(list); start += batchSize {
		end := min(start+batchSize, len(list))
		u, err := url.Parse(base)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("cve", strings.Join(list[start:end], ","))
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("epss: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("epss: %s", resp.Status)
		}
		scores, err := ParseResponse(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		for k, v := range scores {
			out[k] = v
		}
	}
	return out, nil
}

// LoadCache reads previously fetched scores. A missing file is not an error.
func LoadCache(path string) (map[string]Score, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Score{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]Score{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("epss: cache: %w", err)
	}
	return out, nil
}

// SaveCache writes scores atomically.
func SaveCache(path string, scores map[string]Score) error {
	data, err := json.MarshalIndent(scores, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".epss-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
