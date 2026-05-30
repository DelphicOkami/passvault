// Package vault mirrors the firmware's credential-tree schema, path
// resolver, and validation rules host-side so the `passbox vault`
// commands can read-modify-write the decrypted vault without a wasted
// CDC round-trip on input the device would reject anyway.
//
// The device remains the authority: WRITE_VAULT_COMMIT re-runs the same
// validateUpdate on every commit. The checks here exist so error
// messages are user-friendly and so structural operations (mkdir, mv,
// cp, ...) share one schema-aware implementation with the GUI phases.
package tree

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// MaxPlaintext mirrors crypto::kVaultMaxPlaintext — the device refuses a
// decrypted vault larger than this.
const MaxPlaintext = 32 * 1024

// Tree is the vault root: an object keyed by node name. It matches the
// firmware's object-rooted schema exactly.
type Tree map[string]*Node

// Node is either a directory (non-nil Children, possibly empty) or a
// credential (non-nil Cred). The firmware's type discriminator is
// structural — presence of `children` vs `password` — and so is ours.
// A node carrying both or neither is malformed; Validate rejects it,
// mirroring validateUpdate.
type Node struct {
	Children map[string]*Node
	Cred     *Cred
}

// Cred is the credential payload. Password is required (the firmware
// keys cred-ness on a string `password`); the rest are optional. Pointer
// fields distinguish "absent" from "empty string", which matters because
// the device treats an absent field differently from a present empty one.
type Cred struct {
	Password        string  `json:"password"`
	Username        *string `json:"username,omitempty"`
	URL             *string `json:"url,omitempty"`
	UsernameTrailer *string `json:"usernameTrailer,omitempty"`
	PasswordTrailer *string `json:"passwordTrailer,omitempty"`
	TotpTrailer     *string `json:"totpTrailer,omitempty"`
	TotpSecret      *string `json:"totpSecret,omitempty"`
	TotpDigits      *int    `json:"totpDigits,omitempty"`
	TotpPeriod      *int    `json:"totpPeriod,omitempty"`
	TotpAlgo        *string `json:"totpAlgo,omitempty"`
}

// IsDir reports whether the node is a directory.
func (n *Node) IsDir() bool { return n.Children != nil }

// IsCred reports whether the node is an unambiguous credential.
func (n *Node) IsCred() bool { return n.Cred != nil && n.Children == nil }

// MarshalJSON emits the firmware's structural form: a dir as
// {"children": {...}} (even when empty — an empty object is required so
// the type stays unambiguous), a cred as its bare field object.
func (n *Node) MarshalJSON() ([]byte, error) {
	if n.Children != nil {
		return json.Marshal(struct {
			Children map[string]*Node `json:"children"`
		}{n.Children})
	}
	return json.Marshal(n.Cred)
}

// UnmarshalJSON decodes a node by probing for the `children` / `password`
// keys. Both may end up populated for a malformed node; Validate flags
// that rather than silently picking one. `"children": null` is *not* a
// dir — same as the firmware's is<JsonObjectConst>() check.
func (n *Node) UnmarshalJSON(data []byte) error {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	if raw, ok := keys["children"]; ok {
		var ch map[string]*Node
		if err := json.Unmarshal(raw, &ch); err != nil {
			return err
		}
		// nil only when `"children": null` — leave it nil so the node is
		// not treated as a dir, matching the firmware.
		n.Children = ch
	}
	if _, ok := keys["password"]; ok {
		var cred Cred
		if err := json.Unmarshal(data, &cred); err != nil {
			return err
		}
		n.Cred = &cred
	}
	return nil
}

// Parse decodes a decrypted vault.
func Parse(b []byte) (Tree, error) {
	var t Tree
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("invalid vault JSON: %w", err)
	}
	if t == nil {
		t = Tree{}
	}
	return t, nil
}

// Serialize encodes the tree for WRITE_VAULT. The device re-sorts and
// re-serializes on commit, so the exact byte layout here is not
// load-bearing — compact output keeps the CDC transfer small.
func (t Tree) Serialize() ([]byte, error) {
	return json.Marshal(t)
}

// ParsePath splits a vault path into its components. A leading slash is
// optional and a single trailing slash is tolerated; "/" and "" both
// resolve to the root (empty slice). Empty interior components ("//")
// are an error. '_' is the storage form of a display space and is left
// untouched — the device stores underscores, so callers pass underscores.
func ParsePath(p string) ([]string, error) {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return nil, nil
	}
	parts := strings.Split(p, "/")
	for _, part := range parts {
		if part == "" {
			return nil, errors.New("bad path: empty component")
		}
	}
	return parts, nil
}

// findChild matches a single path component against the keys of a
// container case-insensitively, mirroring the device's case-insensitive
// sort order. An exact match wins; otherwise the first case-insensitive
// match does. Returns the stored key (preserving its real casing).
func findChild(m map[string]*Node, name string) (string, *Node, bool) {
	if n, ok := m[name]; ok {
		return name, n, true
	}
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return k, v, true
		}
	}
	return "", nil, false
}

// Resolve walks parts to a leaf node.
//
//	(node, true, nil)   leaf found (for empty parts: a synthetic dir node
//	                    whose Children is the live root map)
//	(nil, false, nil)   every parent resolved to a dir, leaf missing
//	(nil, false, err)   a parent component is missing or is not a dir
func (t Tree) Resolve(parts []string) (*Node, bool, error) {
	if len(parts) == 0 {
		return &Node{Children: map[string]*Node(t)}, true, nil
	}
	cur := map[string]*Node(t)
	for i, part := range parts {
		_, node, ok := findChild(cur, part)
		last := i == len(parts)-1
		if !ok {
			if last {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("path not found: %s",
				strings.Join(parts[:i+1], "/"))
		}
		if last {
			return node, true, nil
		}
		if node.Children == nil {
			return nil, false, fmt.Errorf("not a directory: %s",
				strings.Join(parts[:i+1], "/"))
		}
		cur = node.Children
	}
	return nil, false, nil
}

// container walks all but the last component, returning the map that
// holds (or would hold) the leaf plus the leaf key. If the leaf already
// exists the stored key is returned (real casing); otherwise the
// requested leaf is returned verbatim. Errors if any parent is missing
// or is not a dir, or if parts is empty (the root has no container).
func (t Tree) container(parts []string) (map[string]*Node, string, error) {
	if len(parts) == 0 {
		return nil, "", errors.New("cannot operate on root")
	}
	cur := map[string]*Node(t)
	for i := 0; i < len(parts)-1; i++ {
		_, node, ok := findChild(cur, parts[i])
		if !ok {
			return nil, "", fmt.Errorf("path not found: %s",
				strings.Join(parts[:i+1], "/"))
		}
		if node.Children == nil {
			return nil, "", fmt.Errorf("not a directory: %s",
				strings.Join(parts[:i+1], "/"))
		}
		cur = node.Children
	}
	leaf := parts[len(parts)-1]
	if key, _, ok := findChild(cur, leaf); ok {
		return cur, key, nil
	}
	return cur, leaf, nil
}

// Set splices node into the tree at parts, creating the leaf or replacing
// an existing one. Every parent must already exist and be a directory; an
// existing leaf's stored key casing is preserved so an edit that differs
// only in case doesn't fork the key. Refuses the root (it has no
// container). Backs `vault edit`'s splice-after-edit step.
func (t Tree) Set(parts []string, node *Node) error {
	container, key, err := t.container(parts)
	if err != nil {
		return err
	}
	container[key] = node
	return nil
}

// SortedKeys returns a container's keys in the device's display order:
// case-insensitive, dirs and creds mixed.
func SortedKeys(m map[string]*Node) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortFold(keys)
	return keys
}

// Mkdir creates an empty directory at parts. Without parents, every
// parent must already exist and the leaf must not. With parents,
// intermediate dirs are created on demand and an existing leaf dir is a
// no-op (POSIX `mkdir -p`).
func (t Tree) Mkdir(parts []string, parents bool) error {
	if len(parts) == 0 {
		return errors.New("cannot create root")
	}
	cur := map[string]*Node(t)
	for i := 0; i < len(parts)-1; i++ {
		_, node, ok := findChild(cur, parts[i])
		if !ok {
			if !parents {
				return fmt.Errorf("path not found: %s",
					strings.Join(parts[:i+1], "/"))
			}
			nn := &Node{Children: map[string]*Node{}}
			cur[parts[i]] = nn
			cur = nn.Children
			continue
		}
		if node.Children == nil {
			return fmt.Errorf("not a directory: %s",
				strings.Join(parts[:i+1], "/"))
		}
		cur = node.Children
	}
	leaf := parts[len(parts)-1]
	if _, node, ok := findChild(cur, leaf); ok {
		if parents && node.Children != nil {
			return nil
		}
		return fmt.Errorf("already exists: %s", strings.Join(parts, "/"))
	}
	cur[leaf] = &Node{Children: map[string]*Node{}}
	return nil
}

// Rmdir removes a directory. Without recursive it must be empty; with it
// the whole subtree goes. Refuses creds and the root.
func (t Tree) Rmdir(parts []string, recursive bool) error {
	if len(parts) == 0 {
		return errors.New("refusing to remove root")
	}
	container, key, err := t.container(parts)
	if err != nil {
		return err
	}
	node, ok := container[key]
	if !ok {
		return fmt.Errorf("path not found: %s", strings.Join(parts, "/"))
	}
	if node.Children == nil {
		return fmt.Errorf("not a directory: %s", strings.Join(parts, "/"))
	}
	if len(node.Children) > 0 && !recursive {
		return fmt.Errorf("directory not empty: %s", strings.Join(parts, "/"))
	}
	delete(container, key)
	return nil
}

// Rm removes a credential. With recursive it also removes a directory and
// everything under it. Without recursive on a dir it errors. Refuses the
// root.
func (t Tree) Rm(parts []string, recursive bool) error {
	if len(parts) == 0 {
		return errors.New("refusing to remove root")
	}
	container, key, err := t.container(parts)
	if err != nil {
		return err
	}
	node, ok := container[key]
	if !ok {
		return fmt.Errorf("path not found: %s", strings.Join(parts, "/"))
	}
	if node.Children != nil && !recursive {
		return fmt.Errorf("is a directory: %s", strings.Join(parts, "/"))
	}
	delete(container, key)
	return nil
}

// Mv relocates src to dst. dst semantics follow mv(1): if dst is an
// existing dir, src lands inside it under its current leaf name;
// otherwise dst is the new full path. Overwrites are refused (no -f in
// v1). Refuses moving the root or moving a node into itself.
func (t Tree) Mv(srcParts, dstParts []string) error {
	srcContainer, srcKey, node, err := t.locateSource(srcParts)
	if err != nil {
		return err
	}
	dstContainer, dstKey, effective, err := t.resolveDst(dstParts, srcKey)
	if err != nil {
		return err
	}
	if isPrefix(srcParts, effective) {
		return fmt.Errorf("cannot move %s into itself",
			strings.Join(srcParts, "/"))
	}
	if _, _, ok := findChild(dstContainer, dstKey); ok {
		return fmt.Errorf("would overwrite: %s", strings.Join(effective, "/"))
	}
	delete(srcContainer, srcKey)
	dstContainer[dstKey] = node
	return nil
}

// Cp copies src to dst. A cred copies unconditionally; a dir requires
// recursive. Same dst semantics and overwrite refusal as Mv. The copy is
// deep — the new subtree shares no state with the source.
func (t Tree) Cp(srcParts, dstParts []string, recursive bool) error {
	_, srcKey, node, err := t.locateSource(srcParts)
	if err != nil {
		return err
	}
	if node.Children != nil && !recursive {
		return fmt.Errorf("is a directory (use -r): %s",
			strings.Join(srcParts, "/"))
	}
	dstContainer, dstKey, effective, err := t.resolveDst(dstParts, srcKey)
	if err != nil {
		return err
	}
	if isPrefix(srcParts, effective) {
		return fmt.Errorf("cannot copy %s into itself",
			strings.Join(srcParts, "/"))
	}
	if _, _, ok := findChild(dstContainer, dstKey); ok {
		return fmt.Errorf("would overwrite: %s", strings.Join(effective, "/"))
	}
	clone, err := cloneNode(node)
	if err != nil {
		return err
	}
	dstContainer[dstKey] = clone
	return nil
}

// locateSource resolves a source path for mv/cp: its container, stored
// key, and node. Errors if the path is empty or the leaf is missing.
func (t Tree) locateSource(parts []string) (map[string]*Node, string, *Node, error) {
	if len(parts) == 0 {
		return nil, "", nil, errors.New("refusing to move/copy root")
	}
	container, key, err := t.container(parts)
	if err != nil {
		return nil, "", nil, err
	}
	node, ok := container[key]
	if !ok {
		return nil, "", nil, fmt.Errorf("path not found: %s",
			strings.Join(parts, "/"))
	}
	return container, key, node, nil
}

// resolveDst works out where a node named srcLeaf should land given a dst
// path. If dst is an existing dir the node goes inside under srcLeaf;
// otherwise dst names the destination directly. Returns the destination
// container, key, and the effective full path (for cycle detection).
func (t Tree) resolveDst(dstParts []string, srcLeaf string) (map[string]*Node, string, []string, error) {
	node, exists, err := t.Resolve(dstParts)
	if err != nil {
		return nil, "", nil, err
	}
	if exists && node.Children != nil {
		effective := append(append([]string{}, dstParts...), srcLeaf)
		return node.Children, srcLeaf, effective, nil
	}
	container, key, err := t.container(dstParts)
	if err != nil {
		return nil, "", nil, err
	}
	return container, key, dstParts, nil
}

// isPrefix reports whether prefix is a leading run of parts, compared
// case-insensitively. Used to reject moving/copying a node into its own
// subtree.
func isPrefix(prefix, parts []string) bool {
	if len(prefix) > len(parts) {
		return false
	}
	for i := range prefix {
		if !strings.EqualFold(prefix[i], parts[i]) {
			return false
		}
	}
	return true
}

// cloneNode deep-copies a node via a JSON round-trip — correct given our
// Marshal/Unmarshal and simpler than hand-cloning every pointer field.
func cloneNode(n *Node) (*Node, error) {
	b, err := json.Marshal(n)
	if err != nil {
		return nil, err
	}
	var c Node
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
