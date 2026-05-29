// Package audit runs structural checks over a vault snapshot:
// duplicate / reused / weak / stale credentials. Pure functions, no I/O.
//
// TODO(wiring): The local Vault/Password types defined here are a
// temporary lift from Passman's internal/vault package so audit can
// compile in isolation. Once the bound App interface lands, this
// package will operate against passvault/tree.Tree instead and these
// types will be removed.
package audit

// Folder is the GUI-facing folder shape. Audit only needs Trashed.
type Folder struct {
	ID       string `json:"id"`
	ParentID string `json:"parentId"`
	Label    string `json:"label"`
	Favorite bool   `json:"favorite"`
	Trashed  bool   `json:"trashed"`
}

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
	Status   int    `json:"status"`
	Created  int64  `json:"created"`
	Updated  int64  `json:"updated"`
}

// Vault is a snapshot of the user's folders + passwords.
type Vault struct {
	Folders   []Folder   `json:"folders"`
	Passwords []Password `json:"passwords"`
}
