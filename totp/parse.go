package totp

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// OTPAuth is the parsed contents of an `otpauth://totp/...` URI, in the
// envelope shape the App.ParseOTPAuth interface method returns. Optional
// fields are zero-valued when the URI omitted them (omitempty drops them
// from JSON), so the cred form can leave the corresponding node fields
// untouched instead of writing back explicit defaults.
type OTPAuth struct {
	Secret    string `json:"secret"`
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
	Algorithm string `json:"algorithm,omitempty"`
	Digits    int    `json:"digits,omitempty"`
	Period    int    `json:"period,omitempty"`
	Error     string `json:"error"`
}

// Parse decodes an otpauth:// URI. Only `totp` is accepted — HOTP has no
// time component the live preview can drive.
//
// Validation matches the firmware schema (digits 6/7/8, period 1-600,
// algo SHA1/SHA256/SHA512, base32 secret) so an out-of-range parameter
// from a third-party QR is rejected up front rather than failing later
// on the backend's write path.
//
// Errors are returned in the envelope's Error field, not as a separate
// return value — Parse is the wrapper consumers forward to from
// App.ParseOTPAuth, and the JS side reads `res.error`.
func Parse(raw string) OTPAuth {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return OTPAuth{Error: fmt.Sprintf("invalid otpauth URI: %v", err)}
	}
	if u.Scheme != "otpauth" {
		return OTPAuth{Error: fmt.Sprintf("not an otpauth URI (scheme %q)", u.Scheme)}
	}
	if !strings.EqualFold(u.Host, "totp") {
		return OTPAuth{Error: fmt.Sprintf("unsupported otpauth type %q (want totp)", u.Host)}
	}

	out := OTPAuth{}

	label := strings.TrimPrefix(u.Path, "/")
	if issuer, account, ok := strings.Cut(label, ":"); ok {
		out.Issuer = strings.TrimSpace(issuer)
		out.Account = strings.TrimSpace(account)
	} else {
		out.Account = label
	}

	q := u.Query()
	out.Secret = strings.TrimSpace(q.Get("secret"))
	if out.Secret == "" {
		return OTPAuth{Error: "missing secret"}
	}
	if _, err := DecodeBase32(out.Secret); err != nil {
		return OTPAuth{Error: fmt.Sprintf("invalid base32 secret: %v", err)}
	}
	if iss := q.Get("issuer"); iss != "" && out.Issuer == "" {
		out.Issuer = iss
	}
	if a := q.Get("algorithm"); a != "" {
		algo := strings.ToUpper(a)
		switch algo {
		case "SHA1", "SHA256", "SHA512":
		default:
			return OTPAuth{Error: fmt.Sprintf("bad algorithm %q", a)}
		}
		out.Algorithm = algo
	}
	if d := q.Get("digits"); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || (n != 6 && n != 7 && n != 8) {
			return OTPAuth{Error: fmt.Sprintf("bad digits %q", d)}
		}
		out.Digits = n
	}
	if p := q.Get("period"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 600 {
			return OTPAuth{Error: fmt.Sprintf("bad period %q", p)}
		}
		out.Period = n
	}
	return out
}
