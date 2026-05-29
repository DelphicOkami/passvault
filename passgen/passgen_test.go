package passgen

import (
	"strings"
	"testing"
	"unicode"
)

func TestRandomLengthAndPool(t *testing.T) {
	pw, err := Random(RandomOpts{
		Length: 20, Upper: true, Lower: true, Digits: true, Symbols: true,
	})
	if err != nil {
		t.Fatalf("random: %v", err)
	}
	if len(pw) != 20 {
		t.Fatalf("want length 20, got %d", len(pw))
	}
	for _, r := range pw {
		if !strings.ContainsRune(upperChars+lowerChars+digitChars+symbolChars, r) {
			t.Fatalf("unexpected rune %q in output %q", r, pw)
		}
	}
}

func TestRandomRejectsNoClasses(t *testing.T) {
	if _, err := Random(RandomOpts{Length: 12}); err == nil {
		t.Fatalf("expected error when no classes enabled")
	}
}

func TestRandomRejectsNonPositiveLength(t *testing.T) {
	if _, err := Random(RandomOpts{Length: 0, Lower: true}); err == nil {
		t.Fatalf("expected error for length 0")
	}
}

func TestRandomExcludeAmbiguous(t *testing.T) {
	for range 50 {
		pw, err := Random(RandomOpts{
			Length: 32, Upper: true, Lower: true, Digits: true,
			ExcludeAmbiguous: true,
		})
		if err != nil {
			t.Fatalf("random: %v", err)
		}
		if strings.ContainsAny(pw, ambiguousChars) {
			t.Fatalf("ambiguous rune in %q", pw)
		}
	}
}

func TestPIN(t *testing.T) {
	pw, err := PIN(6)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	if len(pw) != 6 {
		t.Fatalf("want length 6, got %d", len(pw))
	}
	for _, r := range pw {
		if !unicode.IsDigit(r) {
			t.Fatalf("non-digit %q in pin %q", r, pw)
		}
	}
}

func TestXKCDDefault(t *testing.T) {
	pw, err := XKCD(XKCDOpts{Words: 4, Number: true, Suffix: "!"})
	if err != nil {
		t.Fatalf("xkcd: %v", err)
	}
	if !strings.HasSuffix(pw, "!") {
		t.Fatalf("want trailing !, got %q", pw)
	}
	// First rune of each word should be uppercase.
	if !unicode.IsUpper([]rune(pw)[0]) {
		t.Fatalf("want capitalised first word, got %q", pw)
	}
}

func TestXKCDDiceware(t *testing.T) {
	pw, err := XKCD(XKCDOpts{Words: 5, Separator: "-"})
	if err != nil {
		t.Fatalf("xkcd: %v", err)
	}
	if strings.Count(pw, "-") != 4 {
		t.Fatalf("want 4 dashes in diceware output, got %q", pw)
	}
}

func TestXKCDRejectsZeroWords(t *testing.T) {
	if _, err := XKCD(XKCDOpts{Words: 0}); err == nil {
		t.Fatalf("expected error for 0 words")
	}
}

func TestRandIndexUniformish(t *testing.T) {
	// Smoke test: 10 buckets, 10k draws, expect every bucket non-empty.
	counts := make([]int, 10)
	for range 10000 {
		n, err := randIndex(10)
		if err != nil {
			t.Fatalf("randIndex: %v", err)
		}
		counts[n]++
	}
	for i, c := range counts {
		if c == 0 {
			t.Fatalf("bucket %d empty after 10k draws", i)
		}
	}
}
