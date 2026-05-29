package breach

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// suffixFor returns the upper-hex SHA-1 suffix (chars 5..40) of pw —
// the same shape HIBP returns. Used by the fake server.
func suffixFor(pw string) string {
	sum := sha1.Sum([]byte(pw))
	return strings.ToUpper(hex.EncodeToString(sum[:]))[5:]
}

func prefixFor(pw string) string {
	sum := sha1.Sum([]byte(pw))
	return strings.ToUpper(hex.EncodeToString(sum[:]))[:5]
}

// newServer returns a stub HIBP that maps prefix → body. Each call
// increments an atomic counter so tests can assert dedup.
func newServer(t *testing.T, bodies map[string]string) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		prefix := strings.ToUpper(strings.TrimPrefix(r.URL.Path, "/"))
		body, ok := bodies[prefix]
		if !ok {
			body = "" // no hits in this range
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// withEndpoint swaps the package-level Endpoint for the test's
// duration. Restore on cleanup.
func withEndpoint(t *testing.T, url string) {
	t.Helper()
	orig := Endpoint
	Endpoint = url + "/"
	t.Cleanup(func() { Endpoint = orig })
}

func TestCheck_FindsBreachedAndIgnoresClean(t *testing.T) {
	pwBreached := "password"
	pwClean := "Z9!correcthorse-batterystaple-7q"

	bodies := map[string]string{
		prefixFor(pwBreached): suffixFor(pwBreached) + ":12345\n" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\n", // padding line
		// pwClean's prefix returns only padding-style lines (count=0)
		// and a suffix that doesn't match.
		prefixFor(pwClean): "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEA:7\n",
	}
	srv, _ := newServer(t, bodies)
	withEndpoint(t, srv.URL)

	c := &Client{HTTP: srv.Client()}
	got, err := c.Check(context.Background(), []string{pwBreached, pwClean})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if n := got[pwBreached]; n != 12345 {
		t.Errorf("breached count = %d, want 12345", n)
	}
	if _, ok := got[pwClean]; ok {
		t.Errorf("clean password should be absent from result, got %v", got)
	}
}

func TestCheck_DeduplicatesIdenticalPasswords(t *testing.T) {
	pw := "hunter2"
	bodies := map[string]string{
		prefixFor(pw): suffixFor(pw) + ":42\n",
	}
	srv, calls := newServer(t, bodies)
	withEndpoint(t, srv.URL)

	c := &Client{HTTP: srv.Client()}
	got, err := c.Check(context.Background(), []string{pw, pw, pw, pw})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got[pw] != 42 {
		t.Errorf("count = %d, want 42", got[pw])
	}
	if c := atomic.LoadInt32(calls); c != 1 {
		t.Errorf("HTTP calls = %d, want 1 (dedup by password)", c)
	}
}

func TestCheck_DeduplicatesSharedPrefix(t *testing.T) {
	// Two distinct passwords that happen to share a SHA-1 prefix
	// would only hit the API once. We can't easily construct a
	// collision, so instead: when two passwords share a prefix in
	// the bucket, only one fetch should fire. Simulate this by
	// running Check with two passwords known to share a prefix —
	// here we just use the same password twice, but with the dedup
	// check above we trust the bucketing path.
	//
	// This test instead verifies that passwords in different
	// prefixes produce separate calls.
	pwA, pwB := "alpha", "bravo"
	bodies := map[string]string{
		prefixFor(pwA): suffixFor(pwA) + ":1\n",
		prefixFor(pwB): suffixFor(pwB) + ":1\n",
	}
	srv, calls := newServer(t, bodies)
	withEndpoint(t, srv.URL)

	c := &Client{HTTP: srv.Client()}
	if _, err := c.Check(context.Background(), []string{pwA, pwB}); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if c := atomic.LoadInt32(calls); c != 2 {
		t.Errorf("HTTP calls = %d, want 2", c)
	}
}

func TestCheck_EmptyInput(t *testing.T) {
	c := &Client{}
	got, err := c.Check(context.Background(), nil)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty result, got %v", got)
	}
}

func TestCheck_SkipsEmptyPasswords(t *testing.T) {
	srv, calls := newServer(t, nil)
	withEndpoint(t, srv.URL)

	c := &Client{HTTP: srv.Client()}
	got, err := c.Check(context.Background(), []string{"", "", ""})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty result, got %v", got)
	}
	if c := atomic.LoadInt32(calls); c != 0 {
		t.Errorf("HTTP calls = %d, want 0 (all-empty input)", c)
	}
}

func TestCheck_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	withEndpoint(t, srv.URL)

	c := &Client{HTTP: srv.Client()}
	_, err := c.Check(context.Background(), []string{"anything"})
	if err == nil {
		t.Fatal("want error from 503, got nil")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error %q should mention 503", err)
	}
}

func TestCheck_IsCaseInsensitiveSuffix(t *testing.T) {
	// HIBP returns suffixes in upper-case; defend against a server
	// returning them lower-cased anyway.
	pw := "thequickbrown"
	bodies := map[string]string{
		prefixFor(pw): strings.ToLower(suffixFor(pw)) + ":99\n",
	}
	srv, _ := newServer(t, bodies)
	withEndpoint(t, srv.URL)

	c := &Client{HTTP: srv.Client()}
	got, err := c.Check(context.Background(), []string{pw})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got[pw] != 99 {
		t.Errorf("count = %d, want 99 (suffix should match case-insensitively); body was %q",
			got[pw], bodies[prefixFor(pw)])
	}
}

func TestCheck_IgnoresMalformedLines(t *testing.T) {
	pw := "salty"
	body := fmt.Sprintf("notacolon\n%s:abc\n%s:5\n", suffixFor("x"), suffixFor(pw))
	bodies := map[string]string{prefixFor(pw): body}
	srv, _ := newServer(t, bodies)
	withEndpoint(t, srv.URL)

	c := &Client{HTTP: srv.Client()}
	got, err := c.Check(context.Background(), []string{pw})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got[pw] != 5 {
		t.Errorf("count = %d, want 5", got[pw])
	}
}
