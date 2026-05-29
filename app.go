// Package passvault declares the contract both Passman and Passbox
// implement so a single Wails frontend (passvault/ui) can drive either
// backend.
//
// The interface, DTOs, and capability flags defined here are the
// stable surface; everything else in the module (tree, audit, search,
// passgen, breach) is consumed via these types.
//
// TODO(wiring): The shape below is the seed contract lifted from
// Passbox's existing app.go and tightened. Consumer refactors will
// likely surface additions — promote them here so both backends pick
// them up.
package passvault

import (
	"github.com/DelphicOkami/passvault/audit"
	"github.com/DelphicOkami/passvault/passgen"
	"github.com/DelphicOkami/passvault/tree"
)

// Tree, Node, Cred re-export the canonical vault schema so consumers
// can refer to them via the module root without an extra import.
type (
	Tree = tree.Tree
	Node = tree.Node
	Cred = tree.Cred
)

// Capabilities tells the frontend which UI affordances to render. Each
// flag maps to a single visible feature; the frontend reads the struct
// once at startup and gates rendering accordingly.
type Capabilities struct {
	// BatchedWrites is true when the backend accumulates mutations in
	// memory until SaveVault is called (Passbox). False = mutations
	// persist immediately (Passman / Nextcloud).
	BatchedWrites bool `json:"batchedWrites"`

	// Audit is true when AuditVault is wired and the Audit nav button
	// should render.
	Audit bool `json:"audit"`

	// BreachCheck is true when CheckBreach is reachable (HIBP enabled).
	// Gated within the Audit page, not in the nav.
	BreachCheck bool `json:"breachCheck"`

	// DeviceSettings is true when the backend exposes hardware-level
	// configuration (Passbox: OLED, screensaver, PIN policy). Drives
	// the Device Settings nav button.
	DeviceSettings bool `json:"deviceSettings"`

	// AppSettings is true when the App Settings nav button should
	// render. Both consumers turn this on in practice.
	AppSettings bool `json:"appSettings"`

	// DeviceMgmt is true when the toolbar should show device lifecycle
	// controls (Exit management, device picker, sync time).
	DeviceMgmt bool `json:"deviceMgmt"`

	// Login is true when the backend needs an explicit login flow at
	// startup before the vault loads (Passman / OAuth).
	Login bool `json:"login"`
}

// MutateResult is the standard envelope for tree-mutating App methods.
// Tree is the new vault state on success; Error is a human-readable
// message the frontend surfaces in a toast or inline form error.
type MutateResult struct {
	Tree  Tree   `json:"tree"`
	Error string `json:"error"`
}

// VaultResult wraps the initial vault load. Locked is true when the
// backend cannot currently serve the vault (Passbox not in management
// mode, Passman not logged in). The frontend should render the
// appropriate lifecycle screen instead of the vault UI.
type VaultResult struct {
	Tree   Tree   `json:"tree"`
	Locked bool   `json:"locked"`
	Error  string `json:"error"`
}

// SaveResult reports the outcome of SaveVault. No tree round-trip —
// the caller already holds the tree it just wrote.
type SaveResult struct {
	Error string `json:"error"`
}

// AuditResult wraps the audit report so the frontend gets a uniform
// {report, error} envelope regardless of why the audit failed.
type AuditResult struct {
	Report audit.AuditReport `json:"report"`
	Error  string            `json:"error"`
}

// PasswordResult is the envelope for password-generation methods.
type PasswordResult struct {
	Password string `json:"password"`
	Error    string `json:"error"`
}

// App is the contract both backends implement and bind to Wails. Method
// names and shapes are deliberately chosen to match what the frontend
// already calls — so the frontend has no per-backend conditionals
// beyond Capabilities-driven rendering.
//
// Mutation methods take a tree and return a (possibly mutated) tree
// via MutateResult. For batched backends (Passbox) the change stays in
// memory until SaveVault; for write-through backends (Passman) the
// implementation persists the change before returning.
type App interface {
	// Capabilities is the first call the frontend makes.
	Capabilities() Capabilities

	// LoadVault returns the current vault, or sets Locked when the
	// backend needs a lifecycle step first.
	LoadVault() VaultResult

	// SaveVault commits the in-memory tree. No-op (returns
	// SaveResult{}) on write-through backends.
	SaveVault(t Tree) SaveResult

	// Tree mutations. Path is a "/"-separated string as accepted by
	// tree.ParsePath.
	ApplyNewFolder(t Tree, path string) MutateResult
	// ApplyNewCred creates an empty credential leaf at path. The
	// frontend populates fields (password, URL, notes, TOTP) by
	// mutating the returned tree in memory and calls SaveVault when
	// the user commits. Backends that write through instead of
	// batching should still accept this no-content create — they can
	// persist an empty stub or defer the API call until the first
	// non-empty field surfaces in SaveVault.
	ApplyNewCred(t Tree, path string) MutateResult
	ApplyDelete(t Tree, path string) MutateResult
	ApplyRename(t Tree, path, newName string) MutateResult
	ApplyMv(t Tree, src, dst string) MutateResult
	ApplyCp(t Tree, src, dst string, recursive bool) MutateResult

	// Password generation. Two styles — character classes and XKCD
	// diceware passphrases.
	GenerateRandom(opts passgen.RandomOpts) PasswordResult
	GenerateXKCD(opts passgen.XKCDOpts) PasswordResult

	// Audit + breach. CheckBreach is capability-gated; callers should
	// check Capabilities.BreachCheck before invoking.
	AuditVault(opts audit.AuditOptions) AuditResult
	CheckBreach(passwords []string) (map[string]int, error)
}
