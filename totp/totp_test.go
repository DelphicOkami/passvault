package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B test vectors. The shared secret is the ASCII
// string "12345678901234567890" extended as needed for SHA-256 / SHA-512
// (32 / 64 bytes), per RFC 6238 Errata 2866.
func TestRFC6238Vectors(t *testing.T) {
	keySha1 := []byte("12345678901234567890")
	keySha256 := []byte("12345678901234567890123456789012")
	keySha512 := []byte("1234567890123456789012345678901234567890123456789012345678901234")

	secret := func(key []byte) string {
		return base32.StdEncoding.EncodeToString(key)
	}

	cases := []struct {
		t    int64
		want struct{ sha1, sha256, sha512 string }
	}{
		{59, struct{ sha1, sha256, sha512 string }{"94287082", "46119246", "90693936"}},
		{1111111109, struct{ sha1, sha256, sha512 string }{"07081804", "68084774", "25091201"}},
		{1111111111, struct{ sha1, sha256, sha512 string }{"14050471", "67062674", "99943326"}},
		{1234567890, struct{ sha1, sha256, sha512 string }{"89005924", "91819424", "93441116"}},
		{2000000000, struct{ sha1, sha256, sha512 string }{"69279037", "90698825", "38618901"}},
		{20000000000, struct{ sha1, sha256, sha512 string }{"65353130", "77737706", "47863826"}},
	}
	for _, tc := range cases {
		when := time.Unix(tc.t, 0)
		if got, err := Generate(secret(keySha1), "SHA1", 8, 30, when); err != nil || got != tc.want.sha1 {
			t.Errorf("SHA1 @%d: got %q err %v, want %q", tc.t, got, err, tc.want.sha1)
		}
		if got, err := Generate(secret(keySha256), "SHA256", 8, 30, when); err != nil || got != tc.want.sha256 {
			t.Errorf("SHA256 @%d: got %q err %v, want %q", tc.t, got, err, tc.want.sha256)
		}
		if got, err := Generate(secret(keySha512), "SHA512", 8, 30, when); err != nil || got != tc.want.sha512 {
			t.Errorf("SHA512 @%d: got %q err %v, want %q", tc.t, got, err, tc.want.sha512)
		}
	}
}

func TestGenerateDigits(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	when := time.Unix(59, 0)
	got, err := Generate(secret, "SHA1", 6, 30, when)
	if err != nil {
		t.Fatal(err)
	}
	// RFC 6238 SHA1 @59 with 8 digits = 94287082 → last 6 = "287082"
	if got != "287082" {
		t.Errorf("got %q, want %q", got, "287082")
	}
}

func TestBase32Tolerance(t *testing.T) {
	raw := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	noisy := strings.ToLower(strings.TrimRight(raw, "="))
	noisy = noisy[:4] + " " + noisy[4:8] + "-" + noisy[8:]
	when := time.Unix(59, 0)
	a, err := Generate(raw, "SHA1", 6, 30, when)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(noisy, "SHA1", 6, 30, when)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("tolerant decode disagrees: %q vs %q", a, b)
	}
}

func TestBase32Rejects(t *testing.T) {
	if _, err := Generate("!!!notbase32!!!", "SHA1", 6, 30, time.Now()); err == nil {
		t.Error("expected error on bad base32")
	}
	if _, err := Generate("", "SHA1", 6, 30, time.Now()); err == nil {
		t.Error("expected error on empty secret")
	}
}

func TestNowDefaultsAndShape(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	res := Now(secret, "", 0, 0)
	if res.Error != "" {
		t.Fatalf("unexpected error: %q", res.Error)
	}
	if len(res.Code) != 6 {
		t.Errorf("default digits should be 6, got %q", res.Code)
	}
	if res.PeriodMs != 30000 {
		t.Errorf("default period should be 30s, got %d ms", res.PeriodMs)
	}
	if res.RemainingMs <= 0 || res.RemainingMs > res.PeriodMs {
		t.Errorf("remaining %d out of range (0, %d]", res.RemainingMs, res.PeriodMs)
	}
}

func TestNowReportsErrors(t *testing.T) {
	res := Now("!!!", "SHA1", 6, 30)
	if res.Error == "" {
		t.Error("expected error on bad base32 secret")
	}
	if res.Code != "" {
		t.Errorf("expected empty code on error, got %q", res.Code)
	}
}
