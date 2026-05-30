// Package passvault declares the contract both consumer apps
// (passbox-companion, ncpassui) implement and the shared Wails frontend
// (passvault/ui) drives. Method names and result shapes match what the
// UI actually calls — adding a binding to the JS layer requires adding
// it here so drift becomes a build error
// (`var _ passvault.App = (*App)(nil)` in each consumer).
//
// Capability-gated methods must still exist on the implementation when
// the capability is off — returning a "not supported" envelope keeps
// the Wails bindings injected and avoids `undefined is not a function`
// in JS. The UI hides the corresponding chrome based on Capabilities.
package passvault

import (
	"github.com/DelphicOkami/passvault/audit"
	"github.com/DelphicOkami/passvault/config"
	"github.com/DelphicOkami/passvault/passgen"
	"github.com/DelphicOkami/passvault/search"
	"github.com/DelphicOkami/passvault/totp"
	"github.com/DelphicOkami/passvault/tree"
)

// Re-export the canonical vault schema so consumers can refer to it via
// the module root without an extra import.
type (
	Tree = tree.Tree
	Node = tree.Node
	Cred = tree.Cred
)

// Capabilities tells the frontend which UI affordances to render. The
// frontend reads the struct once at startup and gates rendering
// accordingly.
type Capabilities struct {
	// BatchedWrites is true when the backend accumulates mutations in
	// memory until WriteVault is called (Passbox). False = mutations
	// persist immediately on each Apply* call (write-through).
	BatchedWrites bool `json:"batchedWrites"`

	// Audit is true when AuditVault is wired and the Audit nav button
	// should render.
	Audit bool `json:"audit"`

	// BreachCheck is true when CheckBreach is reachable (HIBP enabled).
	// Gated within the Audit page, not in the nav.
	BreachCheck bool `json:"breachCheck"`

	// DeviceSettings is true when the backend exposes hardware-level
	// configuration (OLED, screensaver, FAT volume label, timezone).
	// Drives the device-only sections inside App Settings.
	DeviceSettings bool `json:"deviceSettings"`

	// AppSettings is true when the App Settings nav button should
	// render. Both consumers turn this on in practice.
	AppSettings bool `json:"appSettings"`

	// DeviceMgmt is true when the toolbar should show device-lifecycle
	// controls (device picker, exit-management, sync-time, status ticker).
	DeviceMgmt bool `json:"deviceMgmt"`

	// Login is true when the backend needs an explicit login flow at
	// startup before the vault loads.
	Login bool `json:"login"`
}

// MutateResult is the standard envelope for tree-mutating App methods.
// Tree is the new vault state on success; Error is a human-readable
// message the frontend surfaces inline.
type MutateResult struct {
	Tree  Tree   `json:"tree"`
	Error string `json:"error"`
}

// VaultResult wraps the initial vault load. Locked is true when the
// backend cannot currently serve the vault (Passbox not in management
// mode, ncpassui not logged in). The frontend renders the appropriate
// lifecycle screen instead of the vault UI when Locked is true.
type VaultResult struct {
	Tree   Tree   `json:"tree"`
	Locked bool   `json:"locked"`
	Error  string `json:"error"`
}

// PathError reports the failure of a single node during a batched
// write. Backends that commit atomically (passbox-companion) leave
// SaveResult.FailedPaths empty; backends that write per-node
// (ncpassui's REST adapter) populate it so the UI can mark just the
// rows that didn't land.
type PathError struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

// SaveResult reports the outcome of WriteVault and WriteConfig. Error
// is the top-level failure; FailedPaths is per-node failure for
// batched WriteVault calls only.
type SaveResult struct {
	Error       string      `json:"error"`
	FailedPaths []PathError `json:"failedPaths,omitempty"`
}

// ConfigResult is the envelope for ReadConfig.
type ConfigResult struct {
	Settings config.Settings `json:"settings"`
	Error    string          `json:"error"`
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

// Status is the device backend's current health snapshot. Non-device
// backends should return Status{Connected: true} so the UI's startup
// check is satisfied even when DeviceMgmt is off.
type Status struct {
	Connected bool   `json:"connected"`
	Port      string `json:"port,omitempty"`
	State     string `json:"state,omitempty"`
	Mode      string `json:"mode,omitempty"`
	FwVersion string `json:"fwVersion,omitempty"`
	Serial    string `json:"serial,omitempty"`
	Locked    bool   `json:"locked,omitempty"`
	Error     string `json:"error,omitempty"`
}

// MgmtResult is the envelope for device-management transitions
// (EnterAppMgmt, ExitAppMgmt, SyncTime). State/Mode reflect the device
// immediately after the request.
type MgmtResult struct {
	State string `json:"state,omitempty"`
	Mode  string `json:"mode,omitempty"`
	Error string `json:"error,omitempty"`
}

// DeviceFound is one entry in DiscoverResult.
type DeviceFound struct {
	PortName string `json:"portName"`
	Serial   string `json:"serial"`
}

// DiscoverResult lists devices visible to the host. Empty Devices +
// empty Error = "no device found" (the UI renders the not-connected
// state). Non-device backends return an empty DiscoverResult.
type DiscoverResult struct {
	Devices []DeviceFound `json:"devices"`
	Error   string        `json:"error,omitempty"`
}

// AuthStatus reports the current login state for backends with
// Capabilities.Login. Non-login backends return AuthStatus{LoggedIn:true}.
type AuthStatus struct {
	LoggedIn  bool   `json:"loggedIn"`
	Server    string `json:"server,omitempty"`
	LoginName string `json:"loginName,omitempty"`
	Error     string `json:"error,omitempty"`
}

// LoginInit is the envelope BeginLogin returns. LoginURL is the
// browser-facing URL the user must visit (consumer-specific — for
// Nextcloud Flow v2 this is the server's auth landing page; for a
// mocked backend it can be a no-op placeholder).
type LoginInit struct {
	LoginURL string `json:"loginURL"`
	Error    string `json:"error,omitempty"`
}

// App is the contract both backends implement and bind to Wails.
//
// Mutation methods (Apply*) take a tree and return a possibly-mutated
// tree via MutateResult. For batched backends (BatchedWrites=true) the
// change stays in memory until WriteVault; for write-through backends
// the implementation persists the change before returning.
type App interface {
	// Lifecycle.
	Capabilities() Capabilities
	ConfirmClose() bool // true = safe to close, false = block

	// Vault.
	ReadVault() VaultResult
	WriteVault(t Tree) SaveResult
	ApplyNewFolder(t Tree, path string) MutateResult
	ApplyNewCred(t Tree, path string) MutateResult
	ApplyDelete(t Tree, path string) MutateResult
	ApplyRename(t Tree, path, newName string) MutateResult
	ApplyMv(t Tree, src, dst string) MutateResult
	ApplyCp(t Tree, src, dst string, recursive bool) MutateResult

	// Config.
	ReadConfig() ConfigResult
	WriteConfig(s config.Settings) SaveResult
	ValidateConfig(s config.Settings) string // empty = valid

	// Generators.
	GenerateRandom(opts passgen.RandomOpts) PasswordResult
	GenerateXKCD(opts passgen.XKCDOpts) PasswordResult
	GeneratePIN(length int) PasswordResult

	// TOTP.
	ParseOTPAuth(uri string) totp.OTPAuth
	TOTPNow(secret, algo string, digits, period int) totp.TOTPCode

	// Validators — empty string = valid, else the inline error message.
	ValidateName(s string) string
	ValidateUsername(s string) string
	ValidatePassword(s string) string
	ValidateTOTPSecret(s string) string
	ValidateTOTPDigits(d int) string
	ValidateTOTPPeriod(p int) string
	ValidateTOTPAlgo(a string) string

	// Audit / breach.
	AuditVault(opts audit.AuditOptions) AuditResult
	CheckBreach(passwords []string) (map[string]int, error)

	// Search returns IDs of credentials matching the query, ranked
	// best-first. Empty query returns nil; the UI falls back to the
	// full tree view in that case. IDs are consumer-defined ("/"-joined
	// path on the device backend; folder/ID on REST backends).
	Search(query string) []search.SearchHit

	// Device (capability-gated by DeviceMgmt). Implementations without
	// device support return Status{Connected:true} for GetStatus and
	// MgmtResult{Error:"not supported"} / empty DiscoverResult for the
	// rest, so the JS bindings stay injected.
	GetStatus() Status
	EnterAppMgmt() MgmtResult
	ExitAppMgmt() MgmtResult
	SyncTime() MgmtResult
	DiscoverAll() DiscoverResult
	SelectDevice(serial string)

	// Login (capability-gated). Implementations without a login flow
	// return AuthStatus{LoggedIn:true} from GetAuthStatus and an empty
	// LoginInit / no-op behaviour for the rest.
	BeginLogin(serverURL string) LoginInit
	WaitForLogin() AuthStatus
	CancelLogin()
	GetAuthStatus() AuthStatus
	Logout() string // empty = success, else the error message
}
