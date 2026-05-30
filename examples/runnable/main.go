// Runnable example: spins up the passvault UI against an in-memory
// dummy backend so frontend changes can be exercised without standing
// up a real consumer (Passman, Passbox).
//
// The DummyAdapter implements passvault.App with a small seeded tree
// and write-through mutations. Everything is in process — no network,
// no hardware — so `just run-test` launches a fully clickable app.
package main

import (
	"context"
	"log"
	"time"

	"github.com/DelphicOkami/passvault"
	"github.com/DelphicOkami/passvault/audit"
	"github.com/DelphicOkami/passvault/breach"
	"github.com/DelphicOkami/passvault/passgen"
	"github.com/DelphicOkami/passvault/tree"
	"github.com/DelphicOkami/passvault/ui"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

func main() {
	app := NewDummyAdapter()
	err := wails.Run(&options.App{
		Title:  "passvault runnable example",
		Width:  1100,
		Height: 720,
		AssetServer: &assetserver.Options{
			Assets: ui.Assets,
		},
		Bind: []any{app},
	})
	if err != nil {
		log.Fatal(err)
	}
}

// DummyAdapter is an in-memory passvault.App. Writes are immediate —
// SaveVault is a no-op — so it mimics a write-through backend.
type DummyAdapter struct {
	vault   passvault.Tree
	breach  *breach.Client
	enabled passvault.Capabilities
}

func NewDummyAdapter() *DummyAdapter {
	return &DummyAdapter{
		vault:  seedTree(),
		breach: &breach.Client{},
		enabled: passvault.Capabilities{
			BatchedWrites:  false,
			Audit:          true,
			BreachCheck:    false,
			DeviceSettings: false,
			AppSettings:    true,
			DeviceMgmt:     false,
			Login:          false,
		},
	}
}

func (d *DummyAdapter) Capabilities() passvault.Capabilities { return d.enabled }

func (d *DummyAdapter) LoadVault() passvault.VaultResult {
	return passvault.VaultResult{Tree: d.vault}
}

func (d *DummyAdapter) SaveVault(t passvault.Tree) passvault.SaveResult {
	d.vault = t
	return passvault.SaveResult{}
}

func (d *DummyAdapter) ApplyNewFolder(t passvault.Tree, path string) passvault.MutateResult {
	parts, err := tree.ParsePath(path)
	if err != nil {
		return mutErr(t, err)
	}
	if err := t.Mkdir(parts, false); err != nil {
		return mutErr(t, err)
	}
	d.vault = t
	return passvault.MutateResult{Tree: t}
}

func (d *DummyAdapter) ApplyNewCred(t passvault.Tree, path string) passvault.MutateResult {
	parts, err := tree.ParsePath(path)
	if err != nil {
		return mutErr(t, err)
	}
	if err := t.Set(parts, &tree.Node{Cred: &tree.Cred{}}); err != nil {
		return mutErr(t, err)
	}
	d.vault = t
	return passvault.MutateResult{Tree: t}
}

func (d *DummyAdapter) ApplyDelete(t passvault.Tree, path string) passvault.MutateResult {
	parts, err := tree.ParsePath(path)
	if err != nil {
		return mutErr(t, err)
	}
	if err := t.Rm(parts, true); err != nil {
		return mutErr(t, err)
	}
	d.vault = t
	return passvault.MutateResult{Tree: t}
}

func (d *DummyAdapter) ApplyRename(t passvault.Tree, path, newName string) passvault.MutateResult {
	parts, err := tree.ParsePath(path)
	if err != nil {
		return mutErr(t, err)
	}
	if len(parts) == 0 {
		return mutErr(t, errString("cannot rename root"))
	}
	dst := append(append([]string{}, parts[:len(parts)-1]...), newName)
	if err := t.Mv(parts, dst); err != nil {
		return mutErr(t, err)
	}
	d.vault = t
	return passvault.MutateResult{Tree: t}
}

func (d *DummyAdapter) ApplyMv(t passvault.Tree, src, dst string) passvault.MutateResult {
	srcParts, err := tree.ParsePath(src)
	if err != nil {
		return mutErr(t, err)
	}
	dstParts, err := tree.ParsePath(dst)
	if err != nil {
		return mutErr(t, err)
	}
	if err := t.Mv(srcParts, dstParts); err != nil {
		return mutErr(t, err)
	}
	d.vault = t
	return passvault.MutateResult{Tree: t}
}

func (d *DummyAdapter) ApplyCp(t passvault.Tree, src, dst string, recursive bool) passvault.MutateResult {
	srcParts, err := tree.ParsePath(src)
	if err != nil {
		return mutErr(t, err)
	}
	dstParts, err := tree.ParsePath(dst)
	if err != nil {
		return mutErr(t, err)
	}
	if err := t.Cp(srcParts, dstParts, recursive); err != nil {
		return mutErr(t, err)
	}
	d.vault = t
	return passvault.MutateResult{Tree: t}
}

func (d *DummyAdapter) GenerateRandom(opts passgen.RandomOpts) passvault.PasswordResult {
	pw, err := passgen.Random(opts)
	if err != nil {
		return passvault.PasswordResult{Error: err.Error()}
	}
	return passvault.PasswordResult{Password: pw}
}

func (d *DummyAdapter) GenerateXKCD(opts passgen.XKCDOpts) passvault.PasswordResult {
	pw, err := passgen.XKCD(opts)
	if err != nil {
		return passvault.PasswordResult{Error: err.Error()}
	}
	return passvault.PasswordResult{Password: pw}
}

func (d *DummyAdapter) AuditVault(opts audit.AuditOptions) passvault.AuditResult {
	v := treeToAuditVault(d.vault)
	return passvault.AuditResult{Report: v.Audit(opts)}
}

func (d *DummyAdapter) CheckBreach(passwords []string) (map[string]int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return d.breach.Check(ctx, passwords)
}

// treeToAuditVault flattens the tree into the (folders, passwords)
// shape the audit package expects. Synthetic IDs are stable per run so
// the frontend can resolve them against the same snapshot it just got
// from LoadVault.
func treeToAuditVault(t passvault.Tree) audit.Vault {
	v := audit.Vault{}
	var walk func(node map[string]*tree.Node, folderID, prefix string)
	walk = func(node map[string]*tree.Node, folderID, prefix string) {
		for _, name := range tree.SortedKeys(node) {
			n := node[name]
			full := prefix + "/" + name
			if n.IsDir() {
				id := "folder:" + full
				v.Folders = append(v.Folders, audit.Folder{
					ID: id, ParentID: folderID, Label: name,
				})
				walk(n.Children, id, full)
				continue
			}
			if n.Cred == nil {
				continue
			}
			p := audit.Password{
				ID:       "cred:" + full,
				FolderID: folderID,
				Label:    name,
				Password: n.Cred.Password,
			}
			if n.Cred.Username != nil {
				p.Username = *n.Cred.Username
			}
			v.Passwords = append(v.Passwords, p)
		}
	}
	walk(map[string]*tree.Node(t), "", "")
	return v
}

func mutErr(t passvault.Tree, err error) passvault.MutateResult {
	return passvault.MutateResult{Tree: t, Error: err.Error()}
}

type errString string

func (e errString) Error() string { return string(e) }

// seedTree returns a small vault that exercises folders, nested
// folders, a duplicate, a reused password, and a deliberately-weak
// entry so the Audit view has something to report.
func seedTree() passvault.Tree {
	s := func(v string) *string { return &v }
	t := passvault.Tree{
		"Work": &tree.Node{Children: map[string]*tree.Node{
			"github.com": {Cred: &tree.Cred{
				Password: "Tr0ub4dor&3xample",
				Username: s("alice"),
			}},
			"gitlab.com": {Cred: &tree.Cred{
				Password: "Tr0ub4dor&3xample",
				Username: s("alice"),
			}},
		}},
		"Personal": &tree.Node{Children: map[string]*tree.Node{
			"Email": {Children: map[string]*tree.Node{
				"fastmail.com": {Cred: &tree.Cred{
					Password: "correct horse battery staple",
					Username: s("alice@example.com"),
				}},
			}},
			"old-router": {Cred: &tree.Cred{
				Password: "admin",
				Username: s("admin"),
			}},
		}},
	}
	if err := t.Validate(); err != nil {
		log.Fatalf("seed tree invalid: %v", err)
	}
	return t
}
