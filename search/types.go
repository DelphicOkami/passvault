// Package search runs a fuzzy match across a vault snapshot's
// credentials. Pure functions, no I/O.
//
// TODO(wiring): The local Vault/Password types here are a temporary
// lift from Passman's internal/vault so search can compile in
// isolation. Once the bound App interface lands, this package will
// operate against passvault/tree.Tree and these types will be removed.
package search

// Password is the GUI-facing entry shape. Field set kept identical to
// Passman's internal/vault.Password to make the eventual wiring a
// straight find-and-replace.
type Password struct {
	ID       string `json:"id"`
	FolderID string `json:"folderId"`
	Label    string `json:"label"`
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Notes    string `json:"notes"`
	Favorite bool   `json:"favorite"`
	Trashed  bool   `json:"trashed"`
}

// Vault is the in-memory snapshot the search runs against.
type Vault struct {
	Passwords []Password `json:"passwords"`
}
