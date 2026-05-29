package audit

import (
	"testing"
	"time"
)

func TestAuditDuplicatesByHostAndUsername(t *testing.T) {
	v := Vault{Passwords: []Password{
		{ID: "a", URL: "https://github.com/foo", Username: "alice", Password: "x1!Aaaaa"},
		{ID: "b", URL: "github.com/bar", Username: "Alice", Password: "x2!Bbbbb"},
		{ID: "c", URL: "https://gitlab.com", Username: "alice", Password: "x3!Ccccc"},
		{ID: "d", URL: "https://github.com", Username: "bob", Password: "x4!Ddddd"},
	}}
	r := v.Audit(AuditOptions{})
	if len(r.Duplicates) != 1 {
		t.Fatalf("want 1 duplicate group, got %v", r.Duplicates)
	}
	got := r.Duplicates[0]
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("want [a b], got %v", got)
	}
}

func TestAuditReusedPasswords(t *testing.T) {
	v := Vault{Passwords: []Password{
		{ID: "a", Password: "Hunter2!shared"},
		{ID: "b", Password: "Hunter2!shared"},
		{ID: "c", Password: "different-Long-One!"},
		{ID: "d", Password: ""},
		{ID: "e", Password: ""},
	}}
	r := v.Audit(AuditOptions{})
	if len(r.Reused) != 1 || len(r.Reused[0]) != 2 {
		t.Fatalf("want one group of 2 reused, got %v", r.Reused)
	}
}

func TestAuditWeakReasons(t *testing.T) {
	cases := []struct {
		id, pw, reason string
	}{
		{"short", "abc12", "too short"},
		{"digits", "1234567890", "digits only"},
		{"letters", "abcdefghij", "letters only"},
		{"common", "Password", "common password"},
		{"lowcomplex", "abcd12ef", "low complexity"},
	}
	pws := make([]Password, 0, len(cases))
	for _, c := range cases {
		pws = append(pws, Password{ID: c.id, Password: c.pw})
	}
	r := Vault{Passwords: pws}.Audit(AuditOptions{})

	reasonByID := map[string]string{}
	for _, h := range r.Weak {
		reasonByID[h.ID] = h.Reason
	}
	for _, c := range cases {
		if reasonByID[c.id] != c.reason {
			t.Errorf("id=%s want %q, got %q", c.id, c.reason, reasonByID[c.id])
		}
	}
}

func TestAuditWeakSkipsStrong(t *testing.T) {
	v := Vault{Passwords: []Password{
		{ID: "ok", Password: "Tr0ub4dor&3-correcthorse"},
	}}
	r := v.Audit(AuditOptions{})
	if len(r.Weak) != 0 {
		t.Fatalf("expected no weak hits, got %v", r.Weak)
	}
}

func TestAuditStaleWithCutoff(t *testing.T) {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	v := Vault{Passwords: []Password{
		{ID: "old", Updated: now.Add(-400 * 24 * time.Hour).Unix()},
		{ID: "fresh", Updated: now.Add(-30 * 24 * time.Hour).Unix()},
		{ID: "no-ts", Updated: 0},
	}}
	r := v.Audit(AuditOptions{StaleAfter: 365 * 24 * time.Hour, Now: now})
	if len(r.Stale) != 1 || r.Stale[0] != "old" {
		t.Fatalf("want [old], got %v", r.Stale)
	}
}

func TestAuditStaleDisabledWhenZero(t *testing.T) {
	v := Vault{Passwords: []Password{
		{ID: "old", Updated: 1},
	}}
	r := v.Audit(AuditOptions{})
	if len(r.Stale) != 0 {
		t.Fatalf("expected no stale entries with zero threshold, got %v", r.Stale)
	}
}

func TestAuditSkipsTrashed(t *testing.T) {
	v := Vault{Passwords: []Password{
		{ID: "a", Password: "shared", Trashed: true},
		{ID: "b", Password: "shared"},
	}}
	r := v.Audit(AuditOptions{})
	if len(r.Reused) != 0 {
		t.Fatalf("trashed entries must not contribute to reused groups: %v", r.Reused)
	}
}
