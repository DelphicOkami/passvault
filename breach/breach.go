// Package breach checks passwords against the Have I Been Pwned
// "Pwned Passwords" range API using k-anonymity: only the first five
// hex characters of the SHA-1 hash of each password are ever sent over
// the wire, and the response contains every suffix sharing that
// prefix. The full hash (and the password) never leaves the client.
//
// API reference: https://haveibeenpwned.com/API/v3#PwnedPasswords
//
// The package is intentionally narrow: pass in a set of passwords,
// get back a count per password. Whether to actually call this is the
// caller's decision (gated on settings.Security.BreachCheckEnabled).
package breach

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Endpoint is the HIBP range API. Overridable in tests.
var Endpoint = "https://api.pwnedpasswords.com/range/"

// userAgent identifies the app to HIBP. The HIBP terms ask for a
// "meaningful" UA string that isn't a generic library default.
const userAgent = "ncpassui"

// maxConcurrent caps in-flight HTTP requests. HIBP doesn't publish a
// hard limit on the range endpoint, but keeping concurrency modest is
// good citizenship and avoids hammering the free service.
const maxConcurrent = 5

// Client runs HIBP range lookups. The zero value works (uses the
// default HTTP client with a 15s timeout); supply HTTP for tests or
// to plug in a custom transport.
type Client struct {
	HTTP *http.Client
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return defaultHTTP
}

var defaultHTTP = &http.Client{Timeout: 15 * time.Second}

// Check returns a map of password → breach count for every password
// that appears in HIBP. Passwords not found in the dataset are simply
// omitted from the result (the caller can treat "missing" as "safe").
//
// Duplicate passwords in the input are de-duplicated before hashing,
// and ranges hit by multiple passwords are fetched once — so a vault
// of 500 entries with heavy reuse may only need a handful of HTTP
// round-trips. Returning a map keyed on the cleartext password is
// safe because callers already hold those plaintexts in memory.
func (c *Client) Check(ctx context.Context, passwords []string) (map[string]int, error) {
	// 1) Hash each unique password, bucket by 5-char prefix.
	type entry struct {
		password string
		suffix   string // upper-hex, 35 chars
	}
	byPrefix := map[string][]entry{}
	seen := map[string]struct{}{}
	for _, pw := range passwords {
		if pw == "" {
			continue
		}
		if _, dup := seen[pw]; dup {
			continue
		}
		seen[pw] = struct{}{}
		sum := sha1.Sum([]byte(pw))
		hash := strings.ToUpper(hex.EncodeToString(sum[:]))
		prefix, suffix := hash[:5], hash[5:]
		byPrefix[prefix] = append(byPrefix[prefix], entry{password: pw, suffix: suffix})
	}
	if len(byPrefix) == 0 {
		return map[string]int{}, nil
	}

	// 2) Fan out fetches with bounded concurrency.
	type rangeResult struct {
		prefix string
		hits   map[string]int // suffix → count
		err    error
	}
	prefixes := make([]string, 0, len(byPrefix))
	for p := range byPrefix {
		prefixes = append(prefixes, p)
	}

	results := make([]rangeResult, len(prefixes))
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for i, p := range prefixes {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, prefix string) {
			defer wg.Done()
			defer func() { <-sem }()
			hits, err := c.fetchRange(ctx, prefix)
			results[i] = rangeResult{prefix: prefix, hits: hits, err: err}
		}(i, p)
	}
	wg.Wait()

	// 3) Stitch hits back onto the originating passwords. The first
	//    fetch error wins — we don't want to silently report "0
	//    breaches" when the request actually failed.
	out := map[string]int{}
	var firstErr error
	for _, r := range results {
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		for _, e := range byPrefix[r.prefix] {
			if n, ok := r.hits[e.suffix]; ok && n > 0 {
				out[e.password] = n
			}
		}
	}
	if firstErr != nil {
		return out, firstErr
	}
	return out, nil
}

// fetchRange GETs https://api.pwnedpasswords.com/range/<prefix> and
// parses the "SUFFIX:COUNT" body. The Add-Padding header asks HIBP to
// pad the response with junk lines (count=0) so the response size
// doesn't leak how popular the queried prefix is.
func (c *Client) fetchRange(ctx context.Context, prefix string) (map[string]int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, Endpoint+prefix, nil)
	if err != nil {
		return nil, fmt.Errorf("breach: build request: %w", err)
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/plain")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("breach: range %s: %w", prefix, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("breach: range %s returned %s: %s",
			prefix, resp.Status, strings.TrimSpace(string(body)))
	}

	hits := map[string]int{}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Each line is "SUFFIX:COUNT". Padding lines have count=0 and
		// we drop them at the call-site, but parse them here so the
		// scan stays simple.
		colon := strings.IndexByte(line, ':')
		if colon <= 0 || colon == len(line)-1 {
			continue
		}
		suffix := strings.ToUpper(line[:colon])
		n, err := strconv.Atoi(line[colon+1:])
		if err != nil {
			continue
		}
		if n > 0 {
			hits[suffix] = n
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("breach: read range %s: %w", prefix, err)
	}
	return hits, nil
}

// ErrDisabled is what the GUI binding returns when the user hasn't
// opted in. Exported so the frontend can distinguish "feature off"
// from "network failed".
var ErrDisabled = errors.New("breach checks are disabled in settings")
