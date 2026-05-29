package search

import (
	"sort"
	"strings"
	"unicode"
)

// SearchHit pairs a password ID with the match score so the caller can
// preserve ranking. Higher scores are better matches.
type SearchHit struct {
	ID    string `json:"id"`
	Score int    `json:"score"`
}

// Search returns IDs of password entries that fuzzily match query,
// ordered best-first. An empty query returns nil (caller should fall
// back to the folder-filtered listing).
//
// Scoring favours, in order: contiguous substring in the label, hit
// against the URL host, hit against the username, then subsequence
// match anywhere in label+username+url. This is intentionally simple —
// good enough for ~10k entries and avoids pulling in a fuzzy lib.
func (v Vault) Search(query string) []SearchHit {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	hits := make([]SearchHit, 0, 32)
	for _, p := range v.Passwords {
		if p.Trashed {
			continue
		}
		score := matchScore(q, p)
		if score > 0 {
			hits = append(hits, SearchHit{ID: p.ID, Score: score})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
	return hits
}

// matchScore returns a positive score when query matches p, or 0 if
// not. Score weights are arbitrary but stable across calls — the only
// thing that matters is that better matches outrank worse ones.
func matchScore(query string, p Password) int {
	label := strings.ToLower(p.Label)
	user := strings.ToLower(p.Username)
	urlField := strings.ToLower(p.URL)
	score := 0

	switch {
	case label == query:
		score += 1000
	case strings.HasPrefix(label, query):
		score += 500
	case strings.Contains(label, query):
		score += 250
	}
	if strings.Contains(user, query) {
		score += 100
	}
	if strings.Contains(urlField, query) {
		score += 80
	}

	// Subsequence fallback so e.g. "ghb" matches "GitHub". Only credit
	// if we haven't already scored above — otherwise we double-count.
	if score == 0 && isSubsequence(query, label+" "+user+" "+urlField) {
		score = 25
	}
	return score
}

// isSubsequence reports whether every rune in needle appears in
// haystack in order (case-insensitive — caller lowercases first).
func isSubsequence(needle, haystack string) bool {
	if needle == "" {
		return true
	}
	hi := 0
	hr := []rune(haystack)
	for _, n := range needle {
		if unicode.IsSpace(n) {
			continue
		}
		matched := false
		for hi < len(hr) {
			if hr[hi] == n {
				hi++
				matched = true
				break
			}
			hi++
		}
		if !matched {
			return false
		}
	}
	return true
}
