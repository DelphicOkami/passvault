// Package totp mirrors the Passbox firmware's RFC 4226 / 6238 TOTP
// generator so the shared Wails frontend can render live codes from a
// secret without a backend round-trip. Output matches the firmware's
// crypto::totp bit-for-bit; the unit tests pin that against the standard
// RFC 6238 test vectors.
//
// The package also exposes [Parse] and [Now] envelope wrappers that the
// passvault.App interface implementations can forward to one-line —
// keeping JS-visible shapes consistent across both consumers.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
	"time"
)

// Generate returns the TOTP code for the given secret at time t.
// secret is base32 (RFC 4648 alphabet; whitespace, dashes, and lowercase
// tolerated; '=' padding optional). algo ∈ {"SHA1","SHA256","SHA512"}.
// digits ∈ {6,7,8}. period ≥ 1 seconds.
func Generate(secret, algo string, digits, period int, t time.Time) (string, error) {
	key, err := DecodeBase32(secret)
	if err != nil {
		return "", err
	}
	if len(key) == 0 {
		return "", fmt.Errorf("empty TOTP secret")
	}
	if digits < 6 || digits > 8 {
		return "", fmt.Errorf("bad TOTP digits (want 6, 7, or 8)")
	}
	if period < 1 {
		return "", fmt.Errorf("bad TOTP period (want >= 1)")
	}
	h, err := newHash(algo)
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix()) / uint64(period)
	code := hotp(h, key, counter, digits)
	return fmt.Sprintf("%0*d", digits, code), nil
}

func hotp(h func() hash.Hash, key []byte, counter uint64, digits int) uint32 {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(h, key)
	m.Write(msg[:])
	mac := m.Sum(nil)
	off := mac[len(mac)-1] & 0x0F
	bin := (uint32(mac[off]&0x7F) << 24) |
		(uint32(mac[off+1]) << 16) |
		(uint32(mac[off+2]) << 8) |
		uint32(mac[off+3])
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return bin % mod
}

func newHash(algo string) (func() hash.Hash, error) {
	switch strings.ToUpper(algo) {
	case "", "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	}
	return nil, fmt.Errorf("bad TOTP algo (want SHA1/SHA256/SHA512)")
}

// DecodeBase32 mirrors the firmware's crypto::decodeBase32: RFC 4648
// alphabet, whitespace and dashes ignored, '=' terminates, lowercase
// tolerated. Returns an error on any invalid character.
func DecodeBase32(in string) ([]byte, error) {
	var out []byte
	var buf uint32
	bits := 0
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch c {
		case ' ', '\t', '\r', '\n', '-':
			continue
		case '=':
			return out, nil
		}
		v := b32val(c)
		if v < 0 {
			return nil, fmt.Errorf("invalid base32 character %q", c)
		}
		buf = (buf << 5) | uint32(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte((buf>>bits)&0xFF))
		}
	}
	return out, nil
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

// TOTPCode is the envelope [Now] returns and the App.TOTPNow interface
// method forwards to JS. RemainingMs lets the UI drive a countdown ring
// without re-reading the host clock; PeriodMs is the full period so the
// ring can size its arc.
type TOTPCode struct {
	Code        string `json:"code"`
	RemainingMs int    `json:"remainingMs"`
	PeriodMs    int    `json:"periodMs"`
	Error       string `json:"error"`
}

// Now renders the current TOTP code using the host wall clock. Defaults
// match the firmware schema: algo "" → SHA1, digits 0 → 6, period 0 →
// 30, so consumers can pass cred fields straight through without
// filling optional defaults.
func Now(secret, algo string, digits, period int) TOTPCode {
	if algo == "" {
		algo = "SHA1"
	}
	if digits == 0 {
		digits = 6
	}
	if period == 0 {
		period = 30
	}
	now := time.Now()
	code, err := Generate(secret, algo, digits, period, now)
	if err != nil {
		return TOTPCode{Error: err.Error()}
	}
	periodMs := int64(period) * 1000
	remaining := periodMs - (now.UnixMilli() % periodMs)
	return TOTPCode{
		Code:        code,
		RemainingMs: int(remaining),
		PeriodMs:    int(periodMs),
	}
}
