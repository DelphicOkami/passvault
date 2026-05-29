package search

import "testing"

func TestSearchRanksLabelOverUsername(t *testing.T) {
	v := Vault{Passwords: []Password{
		{ID: "a", Label: "github.com", Username: "alice"},
		{ID: "b", Label: "Gmail", Username: "github-bot"},
		{ID: "c", Label: "GitHub", Username: "alice"},
	}}
	hits := v.Search("github")
	if len(hits) < 2 {
		t.Fatalf("expected at least 2 hits, got %v", hits)
	}
	// "GitHub" is an exact label match (case-insensitive) and must rank
	// above "github.com" (prefix) and "Gmail" (username substring only).
	if hits[0].ID != "c" {
		t.Fatalf("want exact label match c first, got %v", hits)
	}
}

func TestSearchSkipsTrashed(t *testing.T) {
	v := Vault{Passwords: []Password{
		{ID: "a", Label: "Bank", Trashed: true},
		{ID: "b", Label: "Bank"},
	}}
	hits := v.Search("bank")
	if len(hits) != 1 || hits[0].ID != "b" {
		t.Fatalf("want only non-trashed b, got %v", hits)
	}
}

func TestSearchSubsequenceFallback(t *testing.T) {
	v := Vault{Passwords: []Password{
		{ID: "a", Label: "GitHub"},
		{ID: "b", Label: "Bitbucket"},
	}}
	hits := v.Search("ghb")
	if len(hits) != 1 || hits[0].ID != "a" {
		t.Fatalf("want subsequence match a, got %v", hits)
	}
}
