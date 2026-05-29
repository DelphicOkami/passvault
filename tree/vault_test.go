package tree

import (
	"encoding/json"
	"testing"
)

const sample = `{
  "Personal": {"children": {
    "Github": {"password": "pw", "username": "me", "totpSecret": "JBSWY3DPEHPK3PXP", "usernameTrailer": "tab", "passwordTrailer": "enter"},
    "Empty": {"children": {}}
  }},
  "Work": {"children": {
    "Fanatics": {"password": "x"}
  }}
}`

func parseSample(t *testing.T) Tree {
	t.Helper()
	tree, err := Parse([]byte(sample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := tree.Validate(); err != nil {
		t.Fatalf("sample should validate: %v", err)
	}
	return tree
}

func TestRoundTrip(t *testing.T) {
	tree := parseSample(t)
	b, err := tree.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	again, err := Parse(b)
	if err != nil {
		t.Fatalf("re-Parse: %v", err)
	}
	if err := again.Validate(); err != nil {
		t.Fatalf("re-Validate: %v", err)
	}
	// Empty dir must survive the round-trip as a dir, not collapse to a cred.
	node, ok, err := again.Resolve([]string{"Personal", "Empty"})
	if err != nil || !ok {
		t.Fatalf("Personal/Empty lost: ok=%v err=%v", ok, err)
	}
	if !node.IsDir() {
		t.Fatalf("Personal/Empty should be a dir after round-trip")
	}
}

func TestEmptyDirMarshalsWithChildren(t *testing.T) {
	n := &Node{Children: map[string]*Node{}}
	b, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"children":{}}` {
		t.Fatalf("empty dir marshalled as %s", b)
	}
}

func TestParsePath(t *testing.T) {
	cases := []struct {
		in   string
		want []string
		err  bool
	}{
		{"", nil, false},
		{"/", nil, false},
		{"/Work", []string{"Work"}, false},
		{"Work/Github", []string{"Work", "Github"}, false},
		{"/Work/Github/", []string{"Work", "Github"}, false},
		{"//Work", nil, true},
		{"Work//Github", nil, true},
	}
	for _, tc := range cases {
		got, err := ParsePath(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("ParsePath(%q): want error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePath(%q): %v", tc.in, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("ParsePath(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("ParsePath(%q) = %v, want %v", tc.in, got, tc.want)
			}
		}
	}
}

func TestResolveCaseInsensitive(t *testing.T) {
	tree := parseSample(t)
	node, ok, err := tree.Resolve([]string{"personal", "github"})
	if err != nil || !ok {
		t.Fatalf("case-insensitive resolve failed: ok=%v err=%v", ok, err)
	}
	if !node.IsCred() {
		t.Fatalf("Personal/Github should be a cred")
	}
}

func TestResolveMissingLeaf(t *testing.T) {
	tree := parseSample(t)
	_, ok, err := tree.Resolve([]string{"Personal", "Nope"})
	if err != nil {
		t.Fatalf("missing leaf with existing parent should not error: %v", err)
	}
	if ok {
		t.Fatalf("missing leaf reported as found")
	}
}

func TestResolveMissingParent(t *testing.T) {
	tree := parseSample(t)
	_, _, err := tree.Resolve([]string{"Nope", "Github"})
	if err == nil {
		t.Fatalf("missing parent should error")
	}
}

func TestMkdir(t *testing.T) {
	tree := parseSample(t)
	if err := tree.Mkdir([]string{"Personal", "Banking"}, false); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, ok, _ := tree.Resolve([]string{"Personal", "Banking"}); !ok {
		t.Fatalf("Banking not created")
	}
	// Plain mkdir with a missing parent errors.
	if err := tree.Mkdir([]string{"Nope", "Deep"}, false); err == nil {
		t.Fatalf("mkdir without -p should error on missing parent")
	}
	// -p creates intermediates and is a no-op on an existing dir.
	if err := tree.Mkdir([]string{"A", "B", "C"}, true); err != nil {
		t.Fatalf("mkdir -p: %v", err)
	}
	if err := tree.Mkdir([]string{"A", "B"}, true); err != nil {
		t.Fatalf("mkdir -p on existing dir should be a no-op: %v", err)
	}
	// Existing name without -p errors.
	if err := tree.Mkdir([]string{"Work"}, false); err == nil {
		t.Fatalf("mkdir over existing should error")
	}
}

func TestRmdir(t *testing.T) {
	tree := parseSample(t)
	if err := tree.Rmdir([]string{"Personal", "Empty"}, false); err != nil {
		t.Fatalf("rmdir empty: %v", err)
	}
	// Non-empty without -r errors.
	if err := tree.Rmdir([]string{"Work"}, false); err == nil {
		t.Fatalf("rmdir non-empty should error")
	}
	// -r removes the subtree.
	if err := tree.Rmdir([]string{"Work"}, true); err != nil {
		t.Fatalf("rmdir -r: %v", err)
	}
	// Refuses a cred.
	if err := tree.Rmdir([]string{"Personal", "Github"}, true); err == nil {
		t.Fatalf("rmdir on a cred should error")
	}
	// Refuses root.
	if err := tree.Rmdir(nil, true); err == nil {
		t.Fatalf("rmdir root should error")
	}
}

func TestRm(t *testing.T) {
	tree := parseSample(t)
	if err := tree.Rm([]string{"Personal", "Github"}, false); err != nil {
		t.Fatalf("rm cred: %v", err)
	}
	// Dir without -r errors.
	if err := tree.Rm([]string{"Work"}, false); err == nil {
		t.Fatalf("rm on a dir without -r should error")
	}
	if err := tree.Rm([]string{"Work"}, true); err != nil {
		t.Fatalf("rm -r dir: %v", err)
	}
	if err := tree.Rm(nil, true); err == nil {
		t.Fatalf("rm root should error")
	}
}

func TestMvRename(t *testing.T) {
	tree := parseSample(t)
	if err := tree.Mv([]string{"Work", "Fanatics"}, []string{"Work", "Fanatics-Old"}); err != nil {
		t.Fatalf("mv rename: %v", err)
	}
	if _, ok, _ := tree.Resolve([]string{"Work", "Fanatics-Old"}); !ok {
		t.Fatalf("renamed node missing")
	}
	if _, ok, _ := tree.Resolve([]string{"Work", "Fanatics"}); ok {
		t.Fatalf("original node still present after mv")
	}
}

func TestMvIntoDir(t *testing.T) {
	tree := parseSample(t)
	// Personal/Empty is a dir; moving Work/Fanatics into it keeps the leaf name.
	if err := tree.Mv([]string{"Work", "Fanatics"}, []string{"Personal", "Empty"}); err != nil {
		t.Fatalf("mv into dir: %v", err)
	}
	if _, ok, _ := tree.Resolve([]string{"Personal", "Empty", "Fanatics"}); !ok {
		t.Fatalf("node not placed inside target dir")
	}
}

func TestMvOverwriteRefused(t *testing.T) {
	tree := parseSample(t)
	// Work/Fanatics already exists as a cred; moving onto it must refuse
	// rather than clobber (no -f in v1).
	if err := tree.Mv([]string{"Personal", "Github"}, []string{"Work", "Fanatics"}); err == nil {
		t.Fatalf("mv onto existing name should be refused")
	}
}

func TestMvCyclicRefused(t *testing.T) {
	tree := parseSample(t)
	if err := tree.Mv([]string{"Personal"}, []string{"Personal", "Sub"}); err == nil {
		t.Fatalf("moving a dir into itself should be refused")
	}
}

func TestCpDeep(t *testing.T) {
	tree := parseSample(t)
	if err := tree.Cp([]string{"Personal"}, []string{"PersonalCopy"}, true); err != nil {
		t.Fatalf("cp -r: %v", err)
	}
	// Mutating the copy must not touch the source.
	copyNode, _, _ := tree.Resolve([]string{"PersonalCopy", "Github"})
	newPw := "changed"
	copyNode.Cred.Password = newPw
	srcNode, _, _ := tree.Resolve([]string{"Personal", "Github"})
	if srcNode.Cred.Password == newPw {
		t.Fatalf("cp was shallow — source mutated with copy")
	}
}

func TestCpDirRequiresRecursive(t *testing.T) {
	tree := parseSample(t)
	if err := tree.Cp([]string{"Personal"}, []string{"PersonalCopy"}, false); err == nil {
		t.Fatalf("cp of a dir without -r should error")
	}
}

func TestSet(t *testing.T) {
	tree := parseSample(t)

	// Replace an existing cred; the splice point is the resolved leaf.
	pw := "rotated"
	if err := tree.Set([]string{"Personal", "Github"}, &Node{Cred: &Cred{Password: pw}}); err != nil {
		t.Fatalf("Set replace: %v", err)
	}
	node, ok, _ := tree.Resolve([]string{"Personal", "Github"})
	if !ok || node.Cred == nil || node.Cred.Password != pw {
		t.Fatalf("replaced cred not stored")
	}

	// Create a new cred under an existing dir.
	if err := tree.Set([]string{"Work", "New"}, &Node{Cred: &Cred{Password: "p"}}); err != nil {
		t.Fatalf("Set create: %v", err)
	}
	if _, ok, _ := tree.Resolve([]string{"Work", "New"}); !ok {
		t.Fatalf("new cred not created")
	}

	// Casing of an existing key is preserved, not forked.
	if err := tree.Set([]string{"personal", "github"}, &Node{Cred: &Cred{Password: "x"}}); err != nil {
		t.Fatalf("Set case-insensitive: %v", err)
	}
	personal, _, _ := tree.Resolve([]string{"Personal"})
	if _, dup := personal.Children["github"]; dup {
		t.Fatalf("Set forked a lower-case key alongside the stored one")
	}

	// Refuses the root and a missing parent.
	if err := tree.Set(nil, &Node{Cred: &Cred{Password: "p"}}); err == nil {
		t.Fatalf("Set on root should error")
	}
	if err := tree.Set([]string{"Nope", "Leaf"}, &Node{Cred: &Cred{Password: "p"}}); err == nil {
		t.Fatalf("Set under missing parent should error")
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]string{
		"both dir and cred": `{"X": {"children": {}, "password": "p"}}`,
		"neither":           `{"X": {}}`,
		"slash in name":     `{"a/b": {"password": "p"}}`,
		"space in name":     `{"a b": {"password": "p"}}`,
		"bad trailer":       `{"X": {"password": "p", "usernameTrailer": "space"}}`,
		"bad totp digits":   `{"X": {"password": "p", "totpDigits": 5}}`,
		"bad totp period":   `{"X": {"password": "p", "totpPeriod": 0}}`,
		"bad totp algo":     `{"X": {"password": "p", "totpAlgo": "MD5"}}`,
		"bad totp secret":   `{"X": {"password": "p", "totpSecret": "01890"}}`,
	}
	for name, src := range cases {
		tree, err := Parse([]byte(src))
		if err != nil {
			// A parse error is also an acceptable rejection.
			continue
		}
		if err := tree.Validate(); err == nil {
			t.Errorf("%s: expected Validate to reject %s", name, src)
		}
	}
}

func TestValidateAcceptsTotpVariants(t *testing.T) {
	src := `{"X": {"password": "p", "totpSecret": "JBSWY3DPEHPK3PXP", "totpDigits": 8, "totpPeriod": 60, "totpAlgo": "SHA256"}}`
	tree, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Validate(); err != nil {
		t.Fatalf("valid TOTP cred rejected: %v", err)
	}
}
