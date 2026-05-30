package totp

import "testing"

func TestParseFull(t *testing.T) {
	got := Parse(
		"otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60")
	if got.Error != "" {
		t.Fatal(got.Error)
	}
	if got.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("secret: %q", got.Secret)
	}
	if got.Issuer != "Example" {
		t.Errorf("issuer: %q", got.Issuer)
	}
	if got.Account != "alice@example.com" {
		t.Errorf("account: %q", got.Account)
	}
	if got.Algorithm != "SHA256" {
		t.Errorf("algorithm: %q", got.Algorithm)
	}
	if got.Digits != 8 {
		t.Errorf("digits: %d", got.Digits)
	}
	if got.Period != 60 {
		t.Errorf("period: %d", got.Period)
	}
}

func TestParseMinimal(t *testing.T) {
	got := Parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
	if got.Error != "" {
		t.Fatal(got.Error)
	}
	if got.Account != "alice" || got.Issuer != "" {
		t.Errorf("label split wrong: %+v", got)
	}
	// Optionals zero-valued when absent from the URI — omitempty drops them.
	if got.Algorithm != "" || got.Digits != 0 || got.Period != 0 {
		t.Errorf("expected optionals zero: %+v", got)
	}
}

func TestParseRejects(t *testing.T) {
	cases := []string{
		"https://example.com",                          // wrong scheme
		"otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",     // HOTP not supported
		"otpauth://totp/x",                             // no secret
		"otpauth://totp/x?secret=",                     // empty secret
		"otpauth://totp/x?secret=!!!",                  // bad base32
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=9",
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=601",
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
	}
	for _, c := range cases {
		if Parse(c).Error == "" {
			t.Errorf("expected error for %q", c)
		}
	}
}
