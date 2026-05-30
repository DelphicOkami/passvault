// Runnable example: spins up the passvault UI against an in-memory
// dummy backend so frontend changes can be exercised without standing
// up a real consumer (Passbox, ncpassui).
//
// DummyAdapter implements passvault.App against:
//   - a seeded in-memory tree (folders, nested folders, a duplicate
//     password, a reused password, a deliberately-weak entry, a TOTP
//     entry — so the Audit view has something to report);
//   - an in-memory mocked authentication flow (any non-empty server URL
//     is accepted; WaitForLogin sleeps briefly then succeeds) so the
//     generic login chrome can be exercised without dragging Nextcloud
//     or Flow v2 into the example;
//   - a hardcoded fake HIBP responder so CheckBreach reports breaches
//     for known-weak passwords (admin / password / 123456) without
//     hitting the real API.
//
// Capabilities-wise this is the canonical "neither Passbox nor
// Nextcloud, just the interface" demo: Login + Audit + BreachCheck +
// AppSettings on, DeviceMgmt + DeviceSettings off.
package main

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/DelphicOkami/passvault"
	"github.com/DelphicOkami/passvault/audit"
	"github.com/DelphicOkami/passvault/config"
	"github.com/DelphicOkami/passvault/passgen"
	"github.com/DelphicOkami/passvault/search"
	"github.com/DelphicOkami/passvault/totp"
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

// DummyAdapter is an in-memory passvault.App. Apply* mutations are
// write-through (BatchedWrites=false), so WriteVault is a no-op
// re-confirmation.
type DummyAdapter struct {
	mu          sync.Mutex
	vault       passvault.Tree
	settings    config.Settings
	loggedIn    bool
	loginServer string
	caps        passvault.Capabilities
}

func NewDummyAdapter() *DummyAdapter {
	return &DummyAdapter{
		vault:    seedTree(),
		settings: config.Defaults(),
		caps: passvault.Capabilities{
			BatchedWrites:  false,
			Audit:          true,
			BreachCheck:    true,
			AppSettings:    true,
			Login:          true,
			DeviceMgmt:     false,
			DeviceSettings: false,
		},
	}
}

// --- Lifecycle ---------------------------------------------------------

func (d *DummyAdapter) Capabilities() passvault.Capabilities { return d.caps }

func (d *DummyAdapter) ConfirmClose() bool { return true }

// --- Vault -------------------------------------------------------------

func (d *DummyAdapter) ReadVault() passvault.VaultResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.loggedIn {
		return passvault.VaultResult{Locked: true}
	}
	return passvault.VaultResult{Tree: d.vault}
}

func (d *DummyAdapter) WriteVault(t passvault.Tree) passvault.SaveResult {
	d.mu.Lock()
	defer d.mu.Unlock()
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
	d.commit(t)
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
	d.commit(t)
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
	d.commit(t)
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
	d.commit(t)
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
	d.commit(t)
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
	d.commit(t)
	return passvault.MutateResult{Tree: t}
}

// --- Config ------------------------------------------------------------

func (d *DummyAdapter) ReadConfig() passvault.ConfigResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	return passvault.ConfigResult{Settings: d.settings}
}

func (d *DummyAdapter) WriteConfig(s config.Settings) passvault.SaveResult {
	if msg := s.Validate(); msg != "" {
		return passvault.SaveResult{Error: msg}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.settings = s
	return passvault.SaveResult{}
}

func (d *DummyAdapter) ValidateConfig(s config.Settings) string { return s.Validate() }

// --- Generators --------------------------------------------------------

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

func (d *DummyAdapter) GeneratePIN(length int) passvault.PasswordResult {
	pw, err := passgen.PIN(length)
	if err != nil {
		return passvault.PasswordResult{Error: err.Error()}
	}
	return passvault.PasswordResult{Password: pw}
}

// --- TOTP --------------------------------------------------------------

func (d *DummyAdapter) ParseOTPAuth(uri string) totp.OTPAuth {
	return totp.Parse(uri)
}

func (d *DummyAdapter) TOTPNow(secret, algo string, digits, period int) totp.TOTPCode {
	return totp.Now(secret, algo, digits, period)
}

// --- Validators --------------------------------------------------------

func (d *DummyAdapter) ValidateName(s string) string       { return errStr(tree.ValidateName(s)) }
func (d *DummyAdapter) ValidateUsername(s string) string   { return errStr(tree.ValidatePrintable("username", s)) }
func (d *DummyAdapter) ValidatePassword(s string) string   { return errStr(tree.ValidatePrintable("password", s)) }
func (d *DummyAdapter) ValidateTOTPSecret(s string) string { return errStr(tree.ValidateTOTPSecret(s)) }
func (d *DummyAdapter) ValidateTOTPDigits(n int) string    { return errStr(tree.ValidateTOTPDigits(n)) }
func (d *DummyAdapter) ValidateTOTPPeriod(n int) string    { return errStr(tree.ValidateTOTPPeriod(n)) }
func (d *DummyAdapter) ValidateTOTPAlgo(a string) string   { return errStr(tree.ValidateTOTPAlgo(a)) }

// --- Audit / breach ---------------------------------------------------

func (d *DummyAdapter) AuditVault(opts audit.AuditOptions) passvault.AuditResult {
	d.mu.Lock()
	v := treeToAuditVault(d.vault)
	d.mu.Unlock()
	return passvault.AuditResult{Report: v.Audit(opts)}
}

// fakeBreached are passwords the offline example flags as breached so
// the audit view shows something without hitting the real HIBP API.
// Counts are illustrative — the real range query returns 7-digit
// figures for these.
var fakeBreached = map[string]int{
	"admin":    9_400_000,
	"password": 8_300_000,
	"123456":   23_000_000,
}

func (d *DummyAdapter) Search(query string) []search.SearchHit {
	d.mu.Lock()
	v := treeToSearchVault(d.vault)
	d.mu.Unlock()
	return v.Search(query)
}

func (d *DummyAdapter) CheckBreach(passwords []string) (map[string]int, error) {
	out := map[string]int{}
	for _, p := range passwords {
		if n, ok := fakeBreached[strings.ToLower(p)]; ok {
			out[p] = n
		}
	}
	return out, nil
}

// --- Device (not supported) -------------------------------------------

// GetStatus returns Connected:true so the UI's startup readiness check
// passes even though DeviceMgmt is off.
func (d *DummyAdapter) GetStatus() passvault.Status {
	return passvault.Status{Connected: true}
}

func (d *DummyAdapter) EnterAppMgmt() passvault.MgmtResult {
	return passvault.MgmtResult{Error: "not supported"}
}

func (d *DummyAdapter) ExitAppMgmt() passvault.MgmtResult {
	return passvault.MgmtResult{Error: "not supported"}
}

func (d *DummyAdapter) SyncTime() passvault.MgmtResult {
	return passvault.MgmtResult{Error: "not supported"}
}

func (d *DummyAdapter) DiscoverAll() passvault.DiscoverResult { return passvault.DiscoverResult{} }

func (d *DummyAdapter) SelectDevice(string) {}

// --- Login (mocked) ----------------------------------------------------

// BeginLogin accepts any non-empty server URL. There's no real server
// to redirect to, so the returned LoginURL just echoes the input — the
// shared UI's "continue in browser" hint becomes a no-op visit. The
// real approval happens in WaitForLogin's sleep.
func (d *DummyAdapter) BeginLogin(serverURL string) passvault.LoginInit {
	serverURL = strings.TrimSpace(serverURL)
	if serverURL == "" {
		return passvault.LoginInit{Error: "server URL must not be empty"}
	}
	d.mu.Lock()
	d.loginServer = serverURL
	d.mu.Unlock()
	return passvault.LoginInit{LoginURL: serverURL}
}

// WaitForLogin sleeps briefly then succeeds — long enough for the UI's
// "waiting for browser approval" affordance to be visible, short
// enough that the example feels snappy.
func (d *DummyAdapter) WaitForLogin() passvault.AuthStatus {
	d.mu.Lock()
	server := d.loginServer
	d.mu.Unlock()
	if server == "" {
		return passvault.AuthStatus{Error: "no login flow in progress — call BeginLogin first"}
	}
	time.Sleep(800 * time.Millisecond)
	d.mu.Lock()
	d.loggedIn = true
	d.mu.Unlock()
	return passvault.AuthStatus{LoggedIn: true, Server: server, LoginName: "demo@example.com"}
}

func (d *DummyAdapter) CancelLogin() {
	d.mu.Lock()
	d.loginServer = ""
	d.mu.Unlock()
}

func (d *DummyAdapter) GetAuthStatus() passvault.AuthStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	return passvault.AuthStatus{
		LoggedIn:  d.loggedIn,
		Server:    d.loginServer,
		LoginName: ifLoggedIn(d.loggedIn, "demo@example.com"),
	}
}

func (d *DummyAdapter) Logout() string {
	d.mu.Lock()
	d.loggedIn = false
	d.loginServer = ""
	d.mu.Unlock()
	return ""
}

// --- Helpers ----------------------------------------------------------

func (d *DummyAdapter) commit(t passvault.Tree) {
	d.mu.Lock()
	d.vault = t
	d.mu.Unlock()
}

func mutErr(t passvault.Tree, err error) passvault.MutateResult {
	return passvault.MutateResult{Tree: t, Error: err.Error()}
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func ifLoggedIn(loggedIn bool, s string) string {
	if loggedIn {
		return s
	}
	return ""
}

type errString string

func (e errString) Error() string { return string(e) }

// treeToSearchVault flattens the tree into the search package's
// snapshot shape. IDs are joined storage-key paths so the JS side can
// resolve a hit back to a node with parts.join("/") — the same scheme
// passbox-companion uses, so the shared UI's filter logic works
// against either backend.
func treeToSearchVault(t passvault.Tree) search.Vault {
	v := search.Vault{}
	var walk func(node map[string]*tree.Node, prefix string)
	walk = func(node map[string]*tree.Node, prefix string) {
		for _, name := range tree.SortedKeys(node) {
			n := node[name]
			full := name
			if prefix != "" {
				full = prefix + "/" + name
			}
			if n.IsDir() {
				walk(n.Children, full)
				continue
			}
			if n.Cred == nil {
				continue
			}
			p := search.Password{ID: full, Label: name, Password: n.Cred.Password}
			if n.Cred.Username != nil {
				p.Username = *n.Cred.Username
			}
			if n.Cred.URL != nil {
				p.URL = *n.Cred.URL
			}
			v.Passwords = append(v.Passwords, p)
		}
	}
	walk(map[string]*tree.Node(t), "")
	return v
}

// treeToAuditVault flattens the tree into the (folders, passwords)
// shape audit.Audit expects. Synthetic IDs are stable per call so the
// frontend can resolve them against the same snapshot it just got from
// ReadVault.
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
			if n.Cred.URL != nil {
				p.URL = *n.Cred.URL
			}
			v.Passwords = append(v.Passwords, p)
		}
	}
	walk(map[string]*tree.Node(t), "", "")
	return v
}

// seedTree returns a small vault that exercises folders, nested
// folders, a duplicate, a reused password, a deliberately-weak entry,
// and a TOTP-enabled cred so the audit + TOTP views have content.
func seedTree() passvault.Tree {
	s := func(v string) *string { return &v }
	totpSecret := "JBSWY3DPEHPK3PXP"
	totpDigits := 6
	totpPeriod := 30
	totpAlgo := "SHA1"
	t := passvault.Tree{
		"Work": &tree.Node{Children: map[string]*tree.Node{
			"github.com": {Cred: &tree.Cred{
				Password: "Tr0ub4dor&3xample",
				Username: s("alice"),
				TotpSecret: &totpSecret,
				TotpDigits: &totpDigits,
				TotpPeriod: &totpPeriod,
				TotpAlgo:   &totpAlgo,
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
