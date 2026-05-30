package tree

import (
	"fmt"
	"sort"
	"strings"
)

// Validate runs the same structural and field checks the firmware's
// validateUpdate does, so bad input is rejected client-side before a
// wasted CDC round-trip. The device re-validates on commit regardless —
// this is for friendly errors, not trust.
func (t Tree) Validate() error {
	return validateChildren(map[string]*Node(t))
}

func validateChildren(m map[string]*Node) error {
	for name, node := range m {
		if err := validateKey(name); err != nil {
			return err
		}
		if node == nil {
			return fmt.Errorf("bad node: %s", name)
		}
		isDir := node.Children != nil
		isCred := node.Cred != nil
		if isDir && isCred {
			return fmt.Errorf("node is both dir and cred: %s", name)
		}
		if !isDir && !isCred {
			return fmt.Errorf("node is neither dir nor cred: %s", name)
		}
		if isDir {
			if err := validateChildren(node.Children); err != nil {
				return err
			}
			continue
		}
		if err := validateCred(name, node.Cred); err != nil {
			return err
		}
	}
	return nil
}

// validateKey mirrors isValidNodeKey: ASCII-printable, non-empty, and no
// '/' or literal space (both reserved — '/' is the path separator, '_'
// is the canonical display-space separator).
func validateKey(s string) error {
	if s == "" {
		return fmt.Errorf("empty node name")
	}
	if !asciiPrintable(s) {
		return fmt.Errorf("non-ASCII character in name: %q", s)
	}
	if strings.ContainsAny(s, "/ ") {
		return fmt.Errorf("name may not contain '/' or space (use '_'): %q", s)
	}
	return nil
}

func validateCred(name string, c *Cred) error {
	if !asciiPrintable(c.Password) {
		return fmt.Errorf("non-ASCII character in password: %s", name)
	}
	if c.Username != nil && !asciiPrintable(*c.Username) {
		return fmt.Errorf("non-ASCII character in username: %s", name)
	}
	if c.URL != nil && !asciiPrintable(*c.URL) {
		return fmt.Errorf("non-ASCII character in url: %s", name)
	}
	for _, tr := range []*string{c.UsernameTrailer, c.PasswordTrailer, c.TotpTrailer} {
		if !validTrailer(tr) {
			return fmt.Errorf("bad trailer (want \"tab\" or \"enter\"): %s", name)
		}
	}
	if c.TotpSecret != nil {
		if _, ok := decodeBase32(*c.TotpSecret); !ok {
			return fmt.Errorf("invalid TOTP secret (not base32): %s", name)
		}
	}
	if c.TotpDigits != nil {
		if d := *c.TotpDigits; d != 6 && d != 7 && d != 8 {
			return fmt.Errorf("bad TOTP digits (want 6, 7, or 8): %s", name)
		}
	}
	if c.TotpPeriod != nil {
		if p := *c.TotpPeriod; p < 1 || p > 600 {
			return fmt.Errorf("bad TOTP period (want 1-600): %s", name)
		}
	}
	if c.TotpAlgo != nil {
		switch *c.TotpAlgo {
		case "SHA1", "SHA256", "SHA512":
		default:
			return fmt.Errorf("bad TOTP algo (want SHA1/SHA256/SHA512): %s", name)
		}
	}
	return nil
}

func asciiPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}

func validTrailer(s *string) bool {
	if s == nil {
		return true
	}
	return *s == "tab" || *s == "enter"
}

// decodeBase32 mirrors crypto::decodeBase32 — RFC 4648 alphabet, with
// spaces/tabs/newlines/dashes ignored, '=' terminating, and the device's
// 64-byte output cap. Returns false on any invalid character, on
// overflow, or on empty output (the firmware requires produced > 0).
func decodeBase32(in string) (int, bool) {
	const outCap = 64
	var buffer uint32
	bits := 0
	produced := 0
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '-':
			continue
		case c == '=':
			i = len(in)
			continue
		}
		v := b32val(c)
		if v < 0 {
			return 0, false
		}
		buffer = (buffer << 5) | uint32(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			if produced >= outCap {
				return 0, false
			}
			produced++
		}
	}
	return produced, produced > 0
}

func b32val(c byte) int {
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= 'a' && c <= 'z':
		return int(c - 'a')
	case c >= '2' && c <= '7':
		return 26 + int(c-'2')
	}
	return -1
}

// ValidateName checks a node key against the firmware's isValidNodeKey
// rules. Exposed so the GUI's per-field on-blur validators share the
// same error vocabulary the tree-wide Validate uses.
func ValidateName(s string) error { return validateKey(s) }

// ValidateTOTPSecret reports whether s decodes as base32 under the
// firmware's tolerant rules (whitespace/dashes ignored, '=' terminates,
// 64-byte output cap, non-empty produced).
func ValidateTOTPSecret(s string) error {
	if _, ok := decodeBase32(s); !ok {
		return fmt.Errorf("invalid TOTP secret (not base32)")
	}
	return nil
}

// ValidateTOTPDigits mirrors the cred-level digit check.
func ValidateTOTPDigits(d int) error {
	if d != 6 && d != 7 && d != 8 {
		return fmt.Errorf("bad TOTP digits (want 6, 7, or 8)")
	}
	return nil
}

// ValidateTOTPPeriod mirrors the cred-level period check.
func ValidateTOTPPeriod(p int) error {
	if p < 1 || p > 600 {
		return fmt.Errorf("bad TOTP period (want 1-600)")
	}
	return nil
}

// ValidateTOTPAlgo mirrors the cred-level algorithm check.
func ValidateTOTPAlgo(a string) error {
	switch a {
	case "SHA1", "SHA256", "SHA512":
		return nil
	}
	return fmt.Errorf("bad TOTP algo (want SHA1/SHA256/SHA512)")
}

// ValidatePrintable enforces the ASCII-printable rule that the firmware
// applies to password / username strings. field names the surfacing
// context (e.g. "password") so the error reads naturally.
func ValidatePrintable(field, s string) error {
	if !asciiPrintable(s) {
		return fmt.Errorf("non-ASCII character in %s", field)
	}
	return nil
}

// DisplayName renders a stored key for display: '_' becomes a space, the
// same rule the device applies when drawing a name on the OLED.
func DisplayName(key string) string {
	return strings.ReplaceAll(key, "_", " ")
}

// sortFold sorts keys case-insensitively in place — the device's display
// order, where dirs and creds are mixed.
func sortFold(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		return strings.ToLower(keys[i]) < strings.ToLower(keys[j])
	})
}
