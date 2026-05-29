// Vault-level audit checks: duplicate, reused, weak, and stale
// credentials. Pure functions over the in-memory snapshot — no I/O, no
// server round-trips — so the GUI can run them at any time without
// re-fetching the vault.

package audit

import (
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"
)

// AuditReport collects the four categories the GUI surfaces in the
// Audit view. Each list contains password IDs (or groups of IDs) that
// can be resolved against Vault.Passwords for display.
type AuditReport struct {
	// Duplicates groups entries that share the same (normalized URL
	// host + username). Each inner slice has 2+ IDs.
	Duplicates [][]string `json:"duplicates"`
	// Reused groups entries that share the same non-empty password.
	// Each inner slice has 2+ IDs. The shared password itself is not
	// included — the UI looks it up by ID.
	Reused [][]string `json:"reused"`
	// Weak flags entries whose password fails one or more cheap
	// heuristics. Each hit names the worst-offending reason.
	Weak []WeakHit `json:"weak"`
	// Stale lists entries that haven't been Updated within the
	// staleness window passed to Audit. Empty when threshold is 0.
	Stale []string `json:"stale"`
}

// WeakHit pairs a password ID with a short, user-facing reason. Reason
// is intentionally a single category — if an entry hits multiple
// (e.g. short AND digits-only) we report the more specific one.
type WeakHit struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// AuditOptions configures the audit run. Zero-value fields fall back to
// the defaults documented on each field.
type AuditOptions struct {
	// StaleAfter is the duration past which an unchanged entry counts
	// as stale. Zero disables the stale check entirely (the GUI uses
	// this when the user dials the threshold to 0 in settings).
	StaleAfter time.Duration
	// Now overrides time.Now for tests. Zero means time.Now().
	Now time.Time
}

// Audit runs all four checks against v and returns the combined
// report. Trashed entries are skipped — the user has already flagged
// them for removal, so re-surfacing them in the audit is noise.
func (v Vault) Audit(opts AuditOptions) AuditReport {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	live := make([]Password, 0, len(v.Passwords))
	for _, p := range v.Passwords {
		if !p.Trashed {
			live = append(live, p)
		}
	}

	return AuditReport{
		Duplicates: findDuplicates(live),
		Reused:     findReused(live),
		Weak:       findWeak(live),
		Stale:      findStale(live, opts.StaleAfter, now),
	}
}

// findDuplicates groups entries that share the same (URL host, username)
// pair. Empty hosts and empty usernames are skipped — they would lump
// every uncategorised entry together, which isn't useful.
func findDuplicates(ps []Password) [][]string {
	groups := map[string][]string{}
	for _, p := range ps {
		host := urlHost(p.URL)
		user := strings.ToLower(strings.TrimSpace(p.Username))
		if host == "" || user == "" {
			continue
		}
		key := host + "\x00" + user
		groups[key] = append(groups[key], p.ID)
	}
	return collectGroups(groups)
}

// findReused groups entries that share the same non-empty password.
// We deliberately don't hash here — the vault is already in memory
// in cleartext, and the IDs we emit are only consumed by the GUI in
// the same process.
func findReused(ps []Password) [][]string {
	groups := map[string][]string{}
	for _, p := range ps {
		if p.Password == "" {
			continue
		}
		groups[p.Password] = append(groups[p.Password], p.ID)
	}
	return collectGroups(groups)
}

func collectGroups(m map[string][]string) [][]string {
	out := make([][]string, 0, len(m))
	for _, ids := range m {
		if len(ids) < 2 {
			continue
		}
		sort.Strings(ids)
		out = append(out, ids)
	}
	// Stable, deterministic order: largest groups first, then by first
	// ID so test snapshots stay reproducible.
	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i][0] < out[j][0]
	})
	return out
}

// weakMinLength is the floor below which we flag a password as "too
// short" regardless of complexity. NIST 800-63B floor is 8 — we match
// that rather than nag about a few characters more.
const weakMinLength = 8

// findWeak applies cheap heuristics to surface obviously-weak
// passwords. Order matters: the first matching reason wins so the UI
// shows one tight label per entry.
func findWeak(ps []Password) []WeakHit {
	hits := make([]WeakHit, 0)
	for _, p := range ps {
		if p.Password == "" {
			continue
		}
		if reason := weakReason(p.Password); reason != "" {
			hits = append(hits, WeakHit{ID: p.ID, Reason: reason})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].ID < hits[j].ID })
	return hits
}

func weakReason(pw string) string {
	if isCommonPassword(pw) {
		return "common password"
	}
	runes := []rune(pw)
	if len(runes) < weakMinLength {
		return "too short"
	}
	var hasLower, hasUpper, hasDigit, hasOther bool
	for _, r := range runes {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasOther = true
		}
	}
	classes := 0
	for _, b := range []bool{hasLower, hasUpper, hasDigit, hasOther} {
		if b {
			classes++
		}
	}
	switch {
	case hasDigit && !hasLower && !hasUpper && !hasOther:
		return "digits only"
	case (hasLower || hasUpper) && !hasDigit && !hasOther:
		return "letters only"
	case classes == 1:
		// Hit when the password is all-symbols or all-other — still
		// low-entropy enough to call out.
		return "single character class"
	case len(runes) < 12 && classes < 3:
		return "low complexity"
	}
	return ""
}

// commonPasswords is a tiny denylist of the worst-of-the-worst —
// enough to flag the obvious mistakes without pulling in a large
// wordlist. A full top-N list belongs behind an opt-in setting because
// it would balloon the binary and trigger false positives on
// legitimately-strong passphrases that share a prefix.
var commonPasswords = map[string]struct{}{
	"password":   {},
	"password1":  {},
	"password!":  {},
	"123456":     {},
	"12345678":   {},
	"123456789":  {},
	"qwerty":     {},
	"qwerty123":  {},
	"abc123":     {},
	"letmein":    {},
	"welcome":    {},
	"admin":      {},
	"iloveyou":   {},
	"monkey":     {},
	"dragon":     {},
	"000000":     {},
	"111111":     {},
	"changeme":   {},
}

func isCommonPassword(pw string) bool {
	_, ok := commonPasswords[strings.ToLower(pw)]
	return ok
}

// findStale returns entries whose Updated timestamp is older than
// `after`. Entries with no Updated value (older API versions, or fresh
// imports that never round-tripped) are treated as recent — flagging
// them would produce a flood of false positives on first run.
func findStale(ps []Password, after time.Duration, now time.Time) []string {
	if after <= 0 {
		return nil
	}
	cutoff := now.Add(-after).Unix()
	out := make([]string, 0)
	for _, p := range ps {
		if p.Updated == 0 {
			continue
		}
		if p.Updated < cutoff {
			out = append(out, p.ID)
		}
	}
	sort.Strings(out)
	return out
}

// urlHost extracts a comparable host from a URL, tolerating the
// no-scheme inputs common in user-entered URLs ("github.com",
// "github.com/foo"). Empty input → empty host.
func urlHost(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	return strings.TrimPrefix(host, "www.")
}
