// Package passgen generates passwords for the ncpassui generator
// popover. Four styles are exposed:
//
//   - Random:   a uniformly-sampled string over a configurable set of
//                character classes.
//   - XKCD:     concatenated capitalised dictionary words, optionally
//                followed by a 1–100 number and a trailing suffix.
//                Mirrors a popular shell script style.
//   - Diceware: same wordlist + algorithm as XKCD, defaults tuned for
//                separator-joined passphrases.
//   - PIN:      decimal digits only.
//
// All randomness comes from crypto/rand; rejection sampling is used to
// avoid the modulo bias the naive `% n` approach has on pool sizes that
// don't divide the underlying byte/uint32 range.
package passgen

import (
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"errors"
	"strings"
	"unicode"
)

//go:embed wordlist.txt
var wordlistRaw string

var wordlist = func() []string {
	lines := strings.Split(strings.TrimSpace(wordlistRaw), "\n")
	out := make([]string, 0, len(lines))
	for _, w := range lines {
		w = strings.TrimSpace(w)
		if w != "" {
			out = append(out, w)
		}
	}
	return out
}()

const (
	upperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerChars  = "abcdefghijklmnopqrstuvwxyz"
	digitChars  = "0123456789"
	symbolChars = "!@#$%^&*()-_=+[]{};:,.<>/?"
	// ambiguousChars is the visually-confusable set we drop when the
	// "exclude ambiguous" toggle is on. Kept conservative — adding
	// B8/S5/Z2 starts costing real entropy without much real-world
	// benefit, since those rarely get misread when transcribed.
	ambiguousChars = "Il1O0"
)

// RandomOpts mirrors the toggles in the popover. An all-false option
// set is refused: silently producing an empty string would surprise
// callers who expect "no toggles == defaults."
type RandomOpts struct {
	Length           int
	Upper            bool
	Lower            bool
	Digits           bool
	Symbols          bool
	ExcludeAmbiguous bool
}

func Random(opts RandomOpts) (string, error) {
	if opts.Length <= 0 {
		return "", errors.New("length must be positive")
	}
	var pool strings.Builder
	if opts.Upper {
		pool.WriteString(upperChars)
	}
	if opts.Lower {
		pool.WriteString(lowerChars)
	}
	if opts.Digits {
		pool.WriteString(digitChars)
	}
	if opts.Symbols {
		pool.WriteString(symbolChars)
	}
	chars := pool.String()
	if opts.ExcludeAmbiguous {
		chars = stripChars(chars, ambiguousChars)
	}
	if len(chars) == 0 {
		return "", errors.New("at least one character class required")
	}
	out := make([]byte, opts.Length)
	for i := range opts.Length {
		n, err := randIndex(len(chars))
		if err != nil {
			return "", err
		}
		out[i] = chars[n]
	}
	return string(out), nil
}

// stripChars removes every byte in drop from s, preserving order.
// Used for the "exclude ambiguous" toggle so the rejection-sampling
// pool sees the reduced set, not a post-filter that would skew weight.
func stripChars(s, drop string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		if !strings.ContainsRune(drop, rune(s[i])) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// PIN returns `length` decimal digits — same uniform crypto/rand path
// as Random, just with a fixed 10-char pool.
func PIN(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("length must be positive")
	}
	out := make([]byte, length)
	for i := range length {
		n, err := randIndex(10)
		if err != nil {
			return "", err
		}
		out[i] = digitChars[n]
	}
	return string(out), nil
}

// XKCDOpts controls the words-style generator. With Separator="" and
// the default suffix this matches a common shell-script style; with
// Separator="-" and no number/suffix it produces classic Diceware.
type XKCDOpts struct {
	Words     int
	Separator string
	Number    bool   // append a random 1-100
	Suffix    string // appended verbatim after everything else
}

func XKCD(opts XKCDOpts) (string, error) {
	if opts.Words <= 0 {
		return "", errors.New("words must be positive")
	}
	if len(wordlist) == 0 {
		return "", errors.New("wordlist empty")
	}
	parts := make([]string, 0, opts.Words)
	for range opts.Words {
		idx, err := randIndex(len(wordlist))
		if err != nil {
			return "", err
		}
		parts = append(parts, capitalise(wordlist[idx]))
	}
	out := strings.Join(parts, opts.Separator)
	if opts.Number {
		// Inclusive on both ends, matching the original shell script.
		n, err := randIndex(100)
		if err != nil {
			return "", err
		}
		out += itoa(n + 1)
	}
	out += opts.Suffix
	return out, nil
}

func capitalise(w string) string {
	if w == "" {
		return w
	}
	runes := []rune(w)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

// itoa avoids pulling strconv in for a single 1-100 integer.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// randIndex returns a uniform int in [0, n) using crypto/rand and
// rejection sampling on a uint32 — `% n` alone would bias the low
// indices whenever n does not divide 2^32.
func randIndex(n int) (int, error) {
	if n <= 0 {
		return 0, errors.New("randIndex: n must be positive")
	}
	// Reject values that would land in the short tail past the last
	// full n-aligned block in [0, 2^32). uint64 keeps 2^32 itself
	// representable without overflow tricks.
	bigN := uint64(n)
	limit := (uint64(1) << 32) - ((uint64(1) << 32) % bigN)
	var buf [4]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, err
		}
		v := uint64(binary.BigEndian.Uint32(buf[:]))
		if v < limit {
			return int(v % bigN), nil
		}
	}
}
