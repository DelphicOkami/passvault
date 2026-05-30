// passvault shared UI. Drives any backend that implements
// passvault.App: device-mgmt chrome (device picker, status ticker, PIN
// overlay) is gated on Capabilities.DeviceMgmt; the login screen is
// gated on Capabilities.Login; device-only config sections (OLED,
// screensaver, FAT label, timezone) are gated on
// Capabilities.DeviceSettings. The backend decides which chrome is
// reachable; this file decides how each section is rendered.

const card = document.getElementById("status-card");
const refreshBtn = document.getElementById("refresh");
const searchInput = document.getElementById("search-input");
const logoutBtn = document.getElementById("logout");
const loginScreen = document.getElementById("login-screen");
const loginServerInput = document.getElementById("login-server");
const loginBeginBtn = document.getElementById("login-begin");
const loginCancelBtn = document.getElementById("login-cancel");
const loginErrorEl = document.getElementById("login-error");
const loginHintEl = document.getElementById("login-hint");
const landing = document.getElementById("landing");
const landingActions = document.getElementById("landing-actions");
const appPane = document.getElementById("app-pane");
const enableBtn = document.getElementById("enable-mgmt");
const disableBtn = document.getElementById("disable-mgmt");
const overlay = document.getElementById("overlay");
const overlayError = document.getElementById("overlay-error");
const treePane = document.getElementById("tree-pane");
const detailPane = document.getElementById("detail-pane");
const reloadTreeBtn = document.getElementById("reload-tree");
const saveBtn = document.getElementById("save-vault");
const dirtyIndicator = document.getElementById("dirty-indicator");
const toastEl = document.getElementById("toast");
const discardOverlay = document.getElementById("discard-overlay");
const discardBody = document.getElementById("discard-body");
const discardWriteBtn = document.getElementById("discard-write");
const discardDropBtn = document.getElementById("discard-drop");
const discardCancelBtn = document.getElementById("discard-cancel");
const bannerEl = document.getElementById("banner");
const navVaultBtn = document.getElementById("nav-vault");
const navAuditBtn = document.getElementById("nav-audit");
const navSettingsBtn = document.getElementById("nav-settings");
const navDeviceSettingsBtn = document.getElementById("nav-device-settings");
const pageVault = document.getElementById("page-vault");
const pageAudit = document.getElementById("page-audit");
const pageSettings = document.getElementById("page-settings");
const pageDeviceSettings = document.getElementById("page-device-settings");
const settingsPane = document.getElementById("settings-pane");
const deviceSettingsPane = document.getElementById("device-settings-pane");
const auditPane = document.getElementById("audit-pane");

// Single live status from the last GetStatus call. Other views read
// this rather than re-fetching, so a click that mutates pane visibility
// doesn't trigger a second round-trip.
let lastStatus = null;
// Active overlay-poll handle so we can cancel on success / dismiss /
// component teardown.
let overlayPollTimer = null;
// Latest parsed vault tree from ReadVault. Null until the first
// successful read after entering App mode. The selection is held as the
// path of stored keys (case-preserved) from the root to the leaf.
let vaultTree = null;
let selectedPath = null;
// Per-node expansion state, keyed by the joined path. Lives only for
// the lifetime of the in-memory tree — phase 10.3 explicitly does not
// persist this across reloads.
const expanded = new Set();
// Clipboard for Cut/Copy/Paste: { op: 'mv' | 'cp', srcParts } or null.
// Mutates only on Cut/Copy and clears only on a successful Paste — same
// shape any file-manager uses.
let clipboard = null;
// Dirty flag for the in-memory tree mirror. Stays set across a failed
// write so the user can retry without losing edits; clears only on a
// successful WriteVault round-trip.
let dirty = false;
// In-flight async blur handlers (e.g. the Name field's ApplyRename).
// flushPendingEdits awaits these before checking the dirty flag so an
// edit the user hasn't tabbed out of still counts as a pending change.
const pendingBlurs = new Set();
// 12.3: per-page state. currentPage drives which pane is visible and
// which dirty bit the toolbar's Write/Reload buttons act on. settings
// holds the in-memory mirror of /config.json; settingsDirty mirrors
// `dirty` for the vault.
let currentPage = "vault";
let settings = null;
let settingsDirty = false;
// Tracks whether the host has pushed its wall clock to the device this
// session. Cleared whenever the device disappears (status error) so the
// next reconnect re-syncs. Initial detection + every ExitAppMgmt
// success set it; per the 10.7 spec the user never sees this happen
// unless it fails.
let hasSyncedThisSession = false;

// 12.1: status-ticker state. The ticker is a 2 s background poll that
// runs only while the window has focus, so a Passbox left plugged in
// over a weekend doesn't wake on every visibilitychange. The poll
// reuses the GetStatus binding the manual Refresh button calls; the
// banner state lives here rather than as a stateless render so a
// transient hiccup mid-tick doesn't flash an empty banner.
const STATUS_TICKER_MS = 2000;
let statusTickerTimer = null;
// "" / "disconnected" / "mode-flipped" — null banner means hidden.
let bannerKind = null;
// True once the user has explicitly re-enabled after a mode-flip away
// from App. Until then Write to device stays disabled even with edits.
let mgmtBlockedByModeFlip = false;

// Backend capabilities, loaded once at startup. The shape mirrors
// passvault.Capabilities; defaults below are safe (everything off) so a
// pre-load render doesn't try to call disabled methods.
let caps = {
  batchedWrites: false,
  audit: false,
  breachCheck: false,
  deviceSettings: false,
  appSettings: false,
  deviceMgmt: false,
  login: false,
};

// Login state for backends with Capabilities.Login. Only used to gate
// the login screen — the rest of the UI doesn't care about Server /
// LoginName beyond rendering them in the Settings page.
let authState = { loggedIn: false, server: "", loginName: "" };
// True while WaitForLogin is pending. The login button flips into a
// "waiting for browser…" affordance and Cancel becomes available.
let loginPending = false;

// runAudit asks the backend for the audit report and paints it into
// the Audit pane. Re-runs every time the user switches into the
// Audit tab — the vault is the source of truth and audit results
// must reflect what's saved, not what's in the dirty editor.
async function runAudit() {
  auditPane.innerHTML = '<p class="muted">Running audit…</p>';
  let res;
  try {
    // staleAfterDays=0 disables the stale check; backends without
    // an Updated timestamp (like passbox-companion) would have
    // nothing to fire on anyway. UI can grow a slider later.
    res = await window.go.gui.App.AuditVault({ StaleAfter: 0 });
  } catch (e) {
    auditPane.innerHTML = `<p class="error">${escapeHtml(e && e.message ? e.message : String(e))}</p>`;
    return;
  }
  if (res && res.error) {
    auditPane.innerHTML = `<p class="error">${escapeHtml(res.error)}</p>`;
    return;
  }
  const rep = (res && res.report) || {};
  auditPane.innerHTML = "";

  const groups = [
    { title: "Weak passwords", items: (rep.weak || []).map((w) => `${w.id}  — ${w.reason}`) },
    { title: "Reused passwords", items: (rep.reused || []).map((g) => g.join(", ")) },
    { title: "Duplicates", items: (rep.duplicates || []).map((g) => g.join(", ")) },
    { title: "Stale", items: rep.stale || [] },
  ];

  let any = false;
  for (const g of groups) {
    if (!g.items.length) continue;
    any = true;
    const h = document.createElement("h3");
    h.textContent = `${g.title} (${g.items.length})`;
    auditPane.appendChild(h);
    const ul = document.createElement("ul");
    ul.className = "audit-list";
    for (const item of g.items) {
      const li = document.createElement("li");
      li.textContent = item;
      ul.appendChild(li);
    }
    auditPane.appendChild(ul);
  }

  if (caps.breachCheck) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = "Check for breaches (HIBP)";
    btn.addEventListener("click", () => runBreachCheck(btn));
    auditPane.appendChild(btn);
  }

  if (!any && !caps.breachCheck) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "No issues found.";
    auditPane.appendChild(p);
  }
}

// runBreachCheck collects every cred's password from the cached
// vault, sends them to CheckBreach, and appends results to the audit
// pane. The plaintext stays Go-side once handed off — JS doesn't
// keep its own copy after the call returns.
async function runBreachCheck(btn) {
  btn.disabled = true;
  btn.textContent = "Checking…";
  const passwords = [];
  const seen = new Set();
  function walk(node) {
    for (const k of Object.keys(node)) {
      const n = node[k];
      if (n.children) { walk(n.children); continue; }
      if (n.password && !seen.has(n.password)) {
        seen.add(n.password);
        passwords.push(n.password);
      }
    }
  }
  if (vaultTree) walk(vaultTree);
  let counts;
  try {
    counts = await window.go.gui.App.CheckBreach(passwords);
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Check for breaches (HIBP)";
    showToast(e && e.message ? e.message : String(e), "err");
    return;
  }
  const entries = Object.entries(counts || {});
  const h = document.createElement("h3");
  h.textContent = `Breached passwords (${entries.length})`;
  auditPane.appendChild(h);
  if (!entries.length) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "No breached passwords found.";
    auditPane.appendChild(p);
  } else {
    const ul = document.createElement("ul");
    ul.className = "audit-list";
    entries.sort((a, b) => b[1] - a[1]);
    for (const [, count] of entries) {
      const li = document.createElement("li");
      li.textContent = `password seen in ${count.toLocaleString()} breaches`;
      ul.appendChild(li);
    }
    auditPane.appendChild(ul);
  }
  btn.disabled = false;
  btn.textContent = "Check for breaches (HIBP)";
}

// applyTheme pins document.documentElement.dataset.theme so the CSS
// overrides in app.css kick in. "" / "system" / unknown values clear
// the attribute and fall back to prefers-color-scheme.
function applyTheme(name) {
  const root = document.documentElement;
  if (name === "light" || name === "dark") {
    root.dataset.theme = name;
  } else {
    delete root.dataset.theme;
  }
}

// Search state. searchQuery is the current input value; searchHits is
// the Set of cred IDs the backend's Search returned (or null when the
// query is empty / no search active). Tree rendering filters against
// this set: a cred is visible iff its path is in the set, a folder is
// visible iff any descendant is.
let searchQuery = "";
let searchHits = null;
let searchDebounce = null;

// totpTimer is the active 1 s interval driving the live TOTP preview in
// the currently-rendered cred form. Cleared whenever the detail pane is
// re-rendered (selection change, reload, mutation) so a stale form
// never keeps re-polling against the host clock.
let totpTimer = null;

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

function renderLoading() {
  card.innerHTML = '<p class="muted">Querying device…</p>';
}

function renderError(msg) {
  card.innerHTML = `<p class="error">${escapeHtml(msg)}</p>`;
}

function renderStatus(s) {
  const modeClass = s.mode === "app" || s.mode === "connected" ? "ok" : "err";
  const lockedPill = s.locked
    ? '<span class="pill err">locked</span>'
    : '<span class="pill ok">unlocked</span>';
  card.innerHTML = `
    <dl class="status">
      <dt>Connection</dt><dd><span class="pill ok">${escapeHtml(s.port)}</span></dd>
      <dt>Firmware</dt><dd>${escapeHtml(s.fwVersion || "(unknown)")}</dd>
      <dt>State</dt><dd>${escapeHtml(s.state || "(unknown)")}</dd>
      <dt>Mode</dt><dd><span class="pill ${modeClass}">${escapeHtml(s.mode || "?")}</span></dd>
      <dt>Lock</dt><dd>${lockedPill}</dd>
      ${s.serial ? `<dt>Serial</dt><dd>${escapeHtml(s.serial)}</dd>` : ""}
    </dl>
  `;
}

// Tracks whether the previous applyView left us in App mode, so a
// landing→app transition can kick off a vault read without a manual
// Reload click. Falls back to landing on an app→landing transition by
// clearing the in-memory tree.
let wasInApp = false;

// applyView decides which top-level pane is visible.
//
// Login-capable backend (caps.login):
//   not logged in → login screen, everything else hidden.
//   logged in → fall through to the post-login logic below.
//
// Device-mgmt backend (caps.deviceMgmt):
//   App mode → app-pane; everything else → landing (device-not-ready
//   card + Enable Management button).
//
// Otherwise (host-side backend with no lifecycle):
//   always app-pane; landing stays hidden permanently.
function applyView() {
  if (caps.login && !authState.loggedIn) {
    loginScreen.hidden = false;
    landing.hidden = true;
    appPane.hidden = true;
    return;
  }
  loginScreen.hidden = true;

  let inApp;
  if (caps.deviceMgmt) {
    inApp = lastStatus && !lastStatus.error && lastStatus.mode === "app";
    landing.hidden = inApp;
    const canEnable = lastStatus && !lastStatus.error && lastStatus.mode === "connected";
    landingActions.hidden = !canEnable;
  } else {
    // No device lifecycle to wait on — the vault is reachable as soon
    // as we know we're logged in (or trivially logged in for backends
    // without Login).
    inApp = true;
    landing.hidden = true;
  }
  appPane.hidden = !inApp;

  if (inApp && !wasInApp) {
    // Just entered the usable state — load the tree.
    reloadTree();
  } else if (!inApp && wasInApp) {
    // Left the usable state (device dropped, or user signed out). Drop
    // the cached plaintext so a re-enter starts from a fresh read.
    vaultTree = null;
    selectedPath = null;
    expanded.clear();
    clearDirty();
    settings = null;
    clearSettingsDirty();
    settingsPane.innerHTML = '<p class="muted">Loading settings…</p>';
  }
  wasInApp = inApp;
}

async function refresh() {
  if (!caps.deviceMgmt) return;
  refreshBtn.disabled = true;
  renderLoading();
  await fetchStatus();
  refreshBtn.disabled = false;
}

// fetchStatus is the shared status-query path used by the manual Refresh
// button and the 12.1 background ticker. Mode-flip and disconnect banner
// transitions live here so a ticker tick and a button click both keep
// the user in sync.
async function fetchStatus() {
  const previous = lastStatus;
  let status;
  try {
    status = await window.go.gui.App.GetStatus();
  } catch (e) {
    // Surfaces transport-layer failures (e.g. the binding isn't injected
    // yet because the runtime hasn't finished initialising). The Wails
    // runtime emits these as Error instances with .message.
    status = { error: e && e.message ? e.message : String(e) };
  }
  lastStatus = status;
  handleStatusTransition(previous, status);
  if (status.error) {
    renderError(status.error);
    hasSyncedThisSession = false;
  } else {
    renderStatus(status);
    // First success per session pushes the host clock once — silent on
    // success, toast on failure (10.7 auto-sync trigger).
    maybeAutoSyncTime();
  }
  applyView();
}

// handleStatusTransition compares the previous and current status and
// flips banner state when the device disappears or leaves App mode out
// from under us. Idempotent: calling it with the same previous/current
// pair is a no-op.
function handleStatusTransition(previous, current) {
  const wasInAppMode = previous && !previous.error && previous.mode === "app";
  if (current.error) {
    showBanner("disconnected", "device disconnected — reconnect to continue");
    if (wasInAppMode) {
      // App session is gone with the device; the next reconnect starts
      // from a fresh ReadVault, so dirty edits would be writing against
      // a stale tree. Drop them.
      mgmtBlockedByModeFlip = true;
    }
    return;
  }
  if (wasInAppMode && current.mode !== "app") {
    showBanner("mode-flipped",
      "device left App mode — reconnect to continue editing");
    mgmtBlockedByModeFlip = true;
    return;
  }
  if (current.mode === "drive") {
    // 12.2: surface the eject hint whenever the GUI sees the device in
    // Disk mode — both on landing and after a click would have failed
    // with `wrong_mgmt_mode`. The hint stays until the user ejects on
    // the device.
    showBanner("drive-mode",
      "this device is in Disk mode — eject it on the device first");
    return;
  }
  // Either the device is healthy, or we never saw it in App mode in the
  // first place — clear any stale banner.
  if (current.mode === "app" || current.mode === "connected") {
    clearBanner();
    if (current.mode === "app") {
      // The user re-entered App mode; Write to device should be live
      // again on the next dirty edit.
      mgmtBlockedByModeFlip = false;
      applyDirty();
    }
  }
}

function showBanner(kind, msg) {
  bannerKind = kind;
  bannerEl.textContent = msg;
  bannerEl.hidden = false;
  applyDirty();
}

function clearBanner() {
  if (bannerKind === null) return;
  bannerKind = null;
  bannerEl.hidden = true;
  bannerEl.textContent = "";
}

// startStatusTicker runs fetchStatus every STATUS_TICKER_MS while the
// window has focus. visibilitychange + focus/blur events drive the
// pause so a backgrounded GUI doesn't keep poking the device's CPU.
function startStatusTicker() {
  stopStatusTicker();
  if (!caps.deviceMgmt) return;
  if (document.hidden) return;
  statusTickerTimer = setInterval(() => {
    // The overlay-poll loop in onEnable is the bespoke fast 500 ms one
    // for the PIN-entry handshake; skip the slow ticker while it runs
    // so we don't pile up GetStatus calls on the same port.
    if (!overlay.hidden) return;
    fetchStatus();
  }, STATUS_TICKER_MS);
}

function stopStatusTicker() {
  if (statusTickerTimer !== null) {
    clearInterval(statusTickerTimer);
    statusTickerTimer = null;
  }
}

// maybeAutoSyncTime fires SyncTime exactly once per session after the
// device is first reachable. Errors render via the toast, success is
// silent.
async function maybeAutoSyncTime() {
  if (!caps.deviceMgmt) return;
  if (hasSyncedThisSession) return;
  hasSyncedThisSession = true;
  try {
    const res = await window.go.gui.App.SyncTime();
    if (res && res.error) {
      hasSyncedThisSession = false;
      showToast(translateError(res.error), "err");
    }
  } catch (e) {
    hasSyncedThisSession = false;
    showToast(translateError(e && e.message ? e.message : String(e)), "err");
  }
}

function openOverlay() {
  overlayError.hidden = true;
  overlayError.textContent = "";
  overlay.hidden = false;
}

function closeOverlay() {
  overlay.hidden = true;
  if (overlayPollTimer !== null) {
    clearTimeout(overlayPollTimer);
    overlayPollTimer = null;
  }
}

function showOverlayError(msg) {
  overlayError.textContent = msg;
  overlayError.hidden = false;
}

// pollUntilApp is the bespoke 500 ms loop for the enable flow. It runs
// only while the overlay is open and terminates as soon as the device
// either reaches App mode (success) or returns to the main menu without
// entering App (the user pressed Back). Phase 12.1 will replace this
// with a global ticker.
async function pollUntilApp() {
  if (overlay.hidden) {
    return;
  }
  let status;
  try {
    status = await window.go.gui.App.GetStatus();
  } catch (e) {
    // Transport hiccup mid-PIN-entry — keep polling; the user is still
    // looking at the device, not the screen.
    overlayPollTimer = setTimeout(pollUntilApp, 500);
    return;
  }
  lastStatus = status;

  if (status.error) {
    // Device went away (unplugged, port closed). Surface and stop —
    // there's nothing to wait for.
    showOverlayError(status.error);
    return;
  }
  if (status.mode === "app") {
    closeOverlay();
    applyView();
    return;
  }
  // The device's pre-PIN screen is ConfirmPin; once the user dismisses
  // (Back), the FSM falls back to MainMenu / connected mode. Treat any
  // non-ConfirmPin connected state as a dismissal so we don't sit on a
  // dead overlay forever.
  if (status.mode === "connected" && status.state !== "ConfirmPin") {
    closeOverlay();
    applyView();
    return;
  }
  overlayPollTimer = setTimeout(pollUntilApp, 500);
}

async function onEnable() {
  // Drive mode shadows App mode at the device's FSM level — the device
  // returns `wrong_mgmt_mode` to ENTER_APP_MGMT until the user ejects on
  // the OLED. 12.2 surfaces this as a hint overlay instead of letting
  // the user click into a raw error toast.
  if (lastStatus && !lastStatus.error && lastStatus.mode === "drive") {
    showBanner("drive-mode",
      "this device is in Disk mode — eject it on the device first");
    return;
  }
  enableBtn.disabled = true;
  openOverlay();
  try {
    const res = await window.go.gui.App.EnterAppMgmt();
    if (res.error) {
      showOverlayError(res.error);
      return;
    }
    if (res.mode === "app") {
      // Edge case: device was already in app (e.g. another GUI session
      // left it that way). Skip the poll loop entirely.
      lastStatus = { ...lastStatus, state: res.state, mode: res.mode, error: "" };
      closeOverlay();
      applyView();
      return;
    }
    overlayPollTimer = setTimeout(pollUntilApp, 500);
  } catch (e) {
    showOverlayError(e && e.message ? e.message : String(e));
  } finally {
    enableBtn.disabled = false;
  }
}

async function onDisable() {
  // Dirty edits are lost on ExitAppMgmt (the device drops the session);
  // the 10.4 prompt lets the user write them first, discard, or cancel.
  const choice = await confirmDiscardIfDirty();
  if (choice === "cancel") return;
  if (choice === "write") {
    const ok = await onSave();
    if (!ok) return;
  }
  disableBtn.disabled = true;
  try {
    const res = await window.go.gui.App.ExitAppMgmt();
    if (res.error) {
      showToast(translateError(res.error), "err");
      lastStatus = { error: res.error };
      renderError(res.error);
      applyView();
      return;
    }
    // Successful ExitAppMgmt is the second auto-sync trigger from 10.7.
    // Reset the per-session flag so maybeAutoSyncTime re-fires.
    hasSyncedThisSession = false;
    await refresh();
  } catch (e) {
    lastStatus = { error: e && e.message ? e.message : String(e) };
    renderError(lastStatus.error);
    applyView();
  } finally {
    disableBtn.disabled = false;
  }
}

// flushPendingEdits commits whatever the user is currently typing. Some
// fields (notably Name → ApplyRename) defer their mutation to the blur
// handler; without this, hitting Exit Management / closing the app
// while the input still has focus would skip the unsaved-changes prompt
// because dirty was never set. Forces a blur on the active input, then
// waits for any in-flight blur handlers to settle.
async function flushPendingEdits() {
  const ae = document.activeElement;
  if (ae && (ae.tagName === "INPUT" || ae.tagName === "TEXTAREA" ||
             ae.tagName === "SELECT") && typeof ae.blur === "function") {
    ae.blur();
  }
  while (pendingBlurs.size > 0) {
    await Promise.allSettled([...pendingBlurs]);
  }
}

// confirmDiscardIfDirty resolves immediately with "discard" if there's
// nothing to lose. When dirty, it opens the modal and resolves with
// whichever button the user clicks: "write" / "discard" / "cancel".
// Inspects the *active* page's dirty flag — same modal serves the vault
// and settings pages, and cross-page navigation when leaving a dirty
// page open.
async function confirmDiscardIfDirty() {
  await flushPendingEdits();
  if (!pageDirty()) return "discard";
  return new Promise((resolve) => {
    const cleanup = (choice) => {
      discardOverlay.hidden = true;
      discardWriteBtn.removeEventListener("click", onWrite);
      discardDropBtn.removeEventListener("click", onDrop);
      discardCancelBtn.removeEventListener("click", onCancel);
      resolve(choice);
    };
    const onWrite = () => cleanup("write");
    const onDrop = () => cleanup("discard");
    const onCancel = () => cleanup("cancel");
    discardWriteBtn.addEventListener("click", onWrite);
    discardDropBtn.addEventListener("click", onDrop);
    discardCancelBtn.addEventListener("click", onCancel);
    discardOverlay.hidden = false;
  });
}

// --- 10.3: read-only tree view -------------------------------------------

// displayName mirrors vault.DisplayName — '_' is the storage form of a
// space, same rule the device uses when drawing names on the OLED.
function displayName(key) {
  return key.replace(/_/g, " ");
}

// isDir / isCred mirror the structural type discriminator used by
// internal/vault.Node — children present is a dir, password present is
// a cred. A malformed node carrying neither would have been rejected by
// vault.Validate on the device, so we don't render either branch.
function isDir(node) {
  return node && node.children && typeof node.children === "object";
}
function isCred(node) {
  return node && !isDir(node) && typeof node.password === "string";
}

// sortedKeys returns container keys with dirs first, then case-
// insensitive on display name. Dirs-first is per 10.3 spec; the CLI's
// SortedKeys mixes them, but the GUI deliberately diverges to mirror the
// way folder browsers typically separate the two.
function sortedKeys(children) {
  const keys = Object.keys(children);
  keys.sort((a, b) => {
    const da = isDir(children[a]);
    const db = isDir(children[b]);
    if (da !== db) return da ? -1 : 1;
    return displayName(a).toLowerCase().localeCompare(
      displayName(b).toLowerCase());
  });
  return keys;
}

function pathKey(parts) {
  return parts.join("/");
}

function pathsEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// renderTree paints the entire tree into treePane. Cheap to re-run from
// scratch — the vault is at most 32 KB and the DOM stays under a few
// hundred nodes.
function renderTree() {
  treePane.innerHTML = "";
  if (!vaultTree) {
    treePane.innerHTML = '<p class="muted">No vault loaded.</p>';
    return;
  }
  const root = renderChildren(vaultTree, []);
  if (root.children.length === 0) {
    // Distinguish "search returned nothing" from "vault is empty" so
    // the user knows their query filtered everything out vs. there
    // genuinely being no entries.
    if (searchHits && searchHits.size === 0) {
      treePane.innerHTML =
        `<p class="muted">No matches for "${escapeHtml(searchQuery)}".</p>`;
    } else {
      treePane.innerHTML = '<p class="muted">(empty vault)</p>';
    }
    return;
  }
  treePane.appendChild(root);
}

function renderChildren(children, parentPath) {
  const ul = document.createElement("ul");
  for (const key of sortedKeys(children)) {
    const node = children[key];
    const parts = parentPath.concat(key);
    if (searchHits && !subtreeMatches(node, parts)) continue;
    ul.appendChild(renderNode(key, node, parts));
  }
  return ul;
}

// subtreeMatches reports whether a search filter is active and the
// given node (or any descendant) hit. Used to hide both irrelevant
// creds and folders whose contents don't match.
function subtreeMatches(node, parts) {
  if (!searchHits) return true;
  if (!isDir(node)) return searchHits.has(pathKey(parts));
  for (const k of Object.keys(node.children || {})) {
    if (subtreeMatches(node.children[k], parts.concat(k))) return true;
  }
  return false;
}

function renderNode(key, node, parts) {
  const li = document.createElement("li");
  const dir = isDir(node);
  const row = document.createElement("span");
  row.className = "row" + (dir ? " dir" : " leaf");
  if (pathsEqual(parts, selectedPath)) row.classList.add("selected");
  row.dataset.path = pathKey(parts);

  const twisty = document.createElement("span");
  twisty.className = "twisty";
  // Folders containing a search hit auto-expand so the matched cred is
  // visible without a click. The user's manual expansion state still
  // wins when no search is active.
  const open = dir && (expanded.has(pathKey(parts)) || (searchHits !== null));
  twisty.textContent = dir ? (open ? "▾" : "▸") : "";
  row.appendChild(twisty);

  const icon = document.createElement("span");
  icon.className = "icon";
  icon.textContent = dir ? "📁" : "🔑";
  row.appendChild(icon);

  const name = document.createElement("span");
  name.className = "name";
  name.textContent = displayName(key);
  row.appendChild(name);

  row.addEventListener("click", () => onSelect(parts, node, dir));
  row.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    e.stopPropagation();
    selectedPath = parts;
    renderTree();
    renderDetail(parts, node);
    openContextMenu(e.clientX, e.clientY, parts, node);
  });
  // Drag-drop wiring lands in 10.6. Every row is a drag source; only
  // dirs (and the tree-pane background, handled separately) are drop
  // targets. Root has no .row, so it can't be a drag source.
  row.draggable = true;
  row.addEventListener("dragstart", (e) => {
    // Stash the source path on the dataTransfer so a drop on a
    // different window can be rejected at decode time. text/plain keeps
    // the payload visible in devtools without leaking anything more
    // than the structure of the user's vault.
    e.dataTransfer.setData("application/x-passbox-path", pathKey(parts));
    e.dataTransfer.effectAllowed = "copyMove";
  });
  if (dir) {
    row.addEventListener("dragover", (e) => {
      if (!hasPassboxDrag(e)) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = e.ctrlKey ? "copy" : "move";
      row.classList.add("drop-target");
    });
    row.addEventListener("dragleave", () => row.classList.remove("drop-target"));
    row.addEventListener("drop", (e) => {
      row.classList.remove("drop-target");
      handleDrop(e, parts);
    });
  }
  li.appendChild(row);

  if (dir && open) {
    li.appendChild(renderChildren(node.children, parts));
  }
  return li;
}

function onSelect(parts, node, dir) {
  if (dir) {
    const k = pathKey(parts);
    if (expanded.has(k)) expanded.delete(k);
    else expanded.add(k);
  }
  selectedPath = parts;
  renderTree();
  renderDetail(parts, node);
}

// renderDetail dispatches on the selected node type. Dirs and unknowns
// stay informational; creds render the editable form added in 10.4.
function renderDetail(parts, node) {
  if (totpTimer !== null) {
    clearInterval(totpTimer);
    totpTimer = null;
  }
  detailPane.innerHTML = "";
  const path = parts.length === 0
    ? "/"
    : "/" + parts.map(displayName).join("/");
  const h = document.createElement("h3");
  h.textContent = path;
  detailPane.appendChild(h);

  if (isDir(node)) {
    const count = Object.keys(node.children).length;
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = count === 0
      ? "Empty directory."
      : `Directory — ${count} ${count === 1 ? "entry" : "entries"}.`;
    detailPane.appendChild(p);
    return;
  }
  if (!isCred(node)) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "Unknown node type.";
    detailPane.appendChild(p);
    return;
  }

  detailPane.appendChild(renderCredForm(parts, node));
}

// pathToString joins stored-key parts with "/" — the same form
// vault.ParsePath round-trips on the Go side.
function pathToString(parts) {
  return parts.join("/");
}

// toStoredKey mirrors the device's display→storage rule: spaces become
// underscores. The validators on the Go side still flag '/' or any
// non-ASCII character.
function toStoredKey(s) {
  return s.trim().replace(/ /g, "_");
}

// renderCredForm builds the editable cred form. Every input mutates the
// live node in vaultTree on input/blur so Save serialises whatever is on
// screen; per-field on-blur validators surface inline errors using the
// same vocabulary as the device's `validation_failed`.
function renderCredForm(parts, node) {
  const form = document.createElement("form");
  form.className = "cred-form";
  // Prevent native submit (Enter inside a field would otherwise reload
  // the embedded webview).
  form.addEventListener("submit", (e) => e.preventDefault());

  // Name is set at creation time (see onNewCred's prompt) and changed
  // afterwards via the context-menu Rename — no inline field, since
  // it would duplicate the same ApplyRename binding.

  form.appendChild(textField({
    label: "Username",
    value: node.username == null ? "" : node.username,
    placeholder: "(not set)",
    onInput: (v) => {
      node.username = v === "" ? null : v;
      markDirty();
    },
    validate: (v) => v === "" ? "" : callValidator("ValidateUsername", v),
  }));

  form.appendChild(textField({
    label: "URL",
    value: node.url == null ? "" : node.url,
    placeholder: "(not set)",
    onInput: (v) => {
      node.url = v === "" ? null : v;
      markDirty();
    },
    // No dedicated ValidateURL binding yet — the firmware applies the
    // same printable-ASCII rule to URL as to username, so reuse the
    // username validator's vocabulary.
    validate: (v) => v === "" ? "" : callValidator("ValidateUsername", v),
  }));

  const pwField = textField({
    label: "Password",
    value: node.password || "",
    reveal: true,
    onInput: (v) => { node.password = v; markDirty(); },
    validate: (v) => callValidator("ValidatePassword", v),
  });
  // 12.5: a Generate button sits next to the Reveal toggle. Pure-JS
  // popover; no device round-trip and no Go binding.
  const wrap = pwField.querySelector(".field-input");
  const gen = document.createElement("button");
  gen.type = "button";
  gen.className = "generate-toggle";
  gen.textContent = "Generate";
  gen.addEventListener("click", (e) => {
    e.stopPropagation();
    openPasswordGenerator(pwField, (s) => {
      node.password = s;
      const input = pwField.querySelector("input");
      input.value = s;
      markDirty();
    });
  });
  wrap.appendChild(gen);
  form.appendChild(pwField);

  form.appendChild(textField({
    label: "TOTP secret",
    value: node.totpSecret == null ? "" : node.totpSecret,
    placeholder: "raw base32 or otpauth:// URL",
    reveal: true,
    onInput: (v) => {
      // Empty secret = omit the whole TOTP block on serialise. Clear the
      // companion fields so they don't get smuggled through.
      if (v === "") {
        node.totpSecret = null;
        node.totpAlgo = null;
        node.totpDigits = null;
        node.totpPeriod = null;
      } else {
        node.totpSecret = v;
      }
      markDirty();
      refreshTOTPAdvancedVisibility(form, node);
      refreshTOTPPreviewVisibility(form, node);
    },
    // An otpauth:// paste short-circuits the on-blur validator: rather
    // than reject it as "not base32", we hand it to ParseOTPAuth, push
    // the parsed fields into the node, and re-render so the input shows
    // just the secret. Raw secrets fall through to the normal validator.
    validate: async (v) => {
      if (v === "") return "";
      if (/^otpauth:\/\//i.test(v.trim())) {
        const res = await window.go.gui.App.ParseOTPAuth(v.trim());
        if (res.error) return res.error;
        applyOTPAuthToNode(node, res);
        markDirty();
        renderDetail(parts, node);
        return "";
      }
      return callValidator("ValidateTOTPSecret", v);
    },
  }));

  form.appendChild(renderAdvancedTOTP(node));
  refreshTOTPAdvancedVisibility(form, node);

  const preview = renderTOTPPreview(node);
  form.appendChild(preview);
  startTOTPPreview(preview, node);

  return form;
}

// renderTOTPPreview builds the "current code + countdown ring" row that
// sits below the Advanced block. The ring is a single SVG circle whose
// stroke-dashoffset is driven by the host clock — the device's RTC
// (and any drift) doesn't enter into what the user sees.
function renderTOTPPreview(node) {
  const row = document.createElement("div");
  row.className = "field totp-preview";
  row.hidden = !node.totpSecret;
  const lab = document.createElement("label");
  lab.textContent = "Current code";
  row.appendChild(lab);
  const body = document.createElement("div");
  body.className = "totp-preview-body";
  const code = document.createElement("span");
  code.className = "totp-code";
  code.textContent = "------";
  body.appendChild(code);
  body.appendChild(buildTOTPRing());
  row.appendChild(body);
  const err = document.createElement("span");
  err.className = "field-error";
  err.hidden = true;
  row.appendChild(err);
  return row;
}

function buildTOTPRing() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "totp-ring");
  svg.setAttribute("viewBox", "0 0 32 32");
  svg.setAttribute("width", "28");
  svg.setAttribute("height", "28");
  const track = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  track.setAttribute("class", "totp-ring-track");
  track.setAttribute("cx", "16"); track.setAttribute("cy", "16"); track.setAttribute("r", "14");
  svg.appendChild(track);
  const fill = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  fill.setAttribute("class", "totp-ring-fill");
  fill.setAttribute("cx", "16"); fill.setAttribute("cy", "16"); fill.setAttribute("r", "14");
  fill.setAttribute("transform", "rotate(-90 16 16)");
  // 2π·14 ≈ 87.96 — the path length the dasharray draws against.
  fill.setAttribute("stroke-dasharray", "87.96");
  fill.setAttribute("stroke-dashoffset", "0");
  svg.appendChild(fill);
  return svg;
}

// startTOTPPreview drives the preview row on a 1 s interval. Re-polls
// TOTPNow on every tick rather than computing client-side so the JS
// never grows its own base32 / HMAC code paths — totp.Generate is the
// single source of truth.
function startTOTPPreview(row, node) {
  const code = row.querySelector(".totp-code");
  const fill = row.querySelector(".totp-ring-fill");
  const err = row.querySelector(".field-error");
  const tick = async () => {
    const secret = node.totpSecret || "";
    row.hidden = !secret;
    if (!secret) return;
    const res = await window.go.gui.App.TOTPNow(
      secret,
      node.totpAlgo || "",
      node.totpDigits || 0,
      node.totpPeriod || 0);
    if (res.error) {
      code.textContent = "------";
      fill.setAttribute("stroke-dashoffset", "0");
      err.textContent = res.error;
      err.hidden = false;
      return;
    }
    err.hidden = true; err.textContent = "";
    code.textContent = res.code;
    const frac = res.periodMs > 0 ? res.remainingMs / res.periodMs : 0;
    // Visually drain the ring as the period elapses.
    fill.setAttribute("stroke-dashoffset", String(87.96 * (1 - frac)));
  };
  tick();
  totpTimer = setInterval(tick, 1000);
}

// textField builds one input row with optional reveal toggle and an
// inline error slot. validate runs on blur; the JS validators delegate
// to the Go bindings so the error text matches the CLI verbatim. An
// optional onBlur runs after validate passes — used by the Name field
// to apply the rename via ApplyRename.
function textField({ label, value, placeholder, reveal, onInput, validate, onBlur }) {
  const row = document.createElement("div");
  row.className = "field";
  const lab = document.createElement("label");
  lab.textContent = label;
  row.appendChild(lab);

  const wrap = document.createElement("div");
  wrap.className = "field-input";
  const input = document.createElement("input");
  input.type = reveal ? "password" : "text";
  input.value = value;
  if (placeholder) input.placeholder = placeholder;
  input.autocomplete = "off";
  input.spellcheck = false;
  wrap.appendChild(input);

  if (reveal) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "reveal-toggle";
    btn.textContent = "Reveal";
    btn.addEventListener("click", () => {
      const shown = input.type === "text";
      input.type = shown ? "password" : "text";
      btn.textContent = shown ? "Reveal" : "Hide";
    });
    wrap.appendChild(btn);
  }
  row.appendChild(wrap);

  const err = document.createElement("span");
  err.className = "field-error";
  err.hidden = true;
  row.appendChild(err);

  input.addEventListener("input", () => {
    onInput(input.value);
    // Clear a previous error optimistically; re-validates on blur.
    if (!err.hidden) {
      err.hidden = true;
      err.textContent = "";
    }
  });
  input.addEventListener("blur", () => {
    const p = (async () => {
      const msg = await Promise.resolve(validate(input.value));
      if (msg) {
        err.textContent = msg;
        err.hidden = false;
        return;
      }
      err.hidden = true;
      err.textContent = "";
      if (onBlur) {
        const applyErr = await onBlur(input);
        if (applyErr) {
          err.textContent = applyErr;
          err.hidden = false;
        }
      }
    })();
    pendingBlurs.add(p);
    p.finally(() => pendingBlurs.delete(p));
  });
  return row;
}

// --- 12.5: password generator popover ---------------------------------
// Generation itself lives in Go (internal/passgen) — the popover only
// renders the controls and calls window.go.gui.App.Generate*Password.
// Four styles: "random" (per-class character soup, optionally without
// confusable chars), "xkcd" (script-style concatenated capitalised
// words), "diceware" (same algorithm, separator-joined), and "pin"
// (digits only). Last-used settings persist in localStorage so the
// popover opens on whatever the user had configured last session.

const PWGEN_STORAGE_KEY = "passbox.pwgen.v1";

const PWGEN_DEFAULTS = () => ({
  style: "random",
  random: {
    length: 24,
    classes: { upper: true, lower: true, digits: true, symbols: true },
    excludeAmbiguous: false,
  },
  xkcd: { words: 4, separator: "", number: true, symbol: true },
  diceware: { words: 5, separator: "-", number: false, symbol: false },
  pin: { length: 6 },
});

// loadPwgenState merges persisted prefs into a fresh defaults skeleton
// so a stale localStorage payload missing keys (e.g. after we add a new
// style) doesn't leave the popover with undefined fields.
function loadPwgenState() {
  const def = PWGEN_DEFAULTS();
  try {
    const raw = localStorage.getItem(PWGEN_STORAGE_KEY);
    if (!raw) return def;
    const saved = JSON.parse(raw);
    if (saved && typeof saved === "object") {
      if (typeof saved.style === "string") def.style = saved.style;
      for (const k of ["random", "xkcd", "diceware", "pin"]) {
        if (saved[k] && typeof saved[k] === "object") {
          def[k] = { ...def[k], ...saved[k] };
          if (k === "random" && saved.random.classes) {
            def.random.classes = { ...def.random.classes, ...saved.random.classes };
          }
        }
      }
    }
  } catch (_) {
    // Corrupt JSON in storage — fall back to defaults, don't crash the popover.
  }
  return def;
}

function savePwgenState(state) {
  try {
    localStorage.setItem(PWGEN_STORAGE_KEY, JSON.stringify(state));
  } catch (_) {
    // Quota or disabled storage — preferences just won't persist.
  }
}

let activePwPopover = null;

function closePwPopover() {
  if (activePwPopover) {
    activePwPopover.remove();
    activePwPopover = null;
  }
}

document.addEventListener("click", (e) => {
  if (activePwPopover && !activePwPopover.contains(e.target)) {
    closePwPopover();
  }
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closePwPopover();
});

function openPasswordGenerator(anchorRow, onAccept) {
  closePwPopover();
  const pop = document.createElement("div");
  pop.className = "pw-popover card";
  pop.addEventListener("click", (e) => e.stopPropagation());

  // State is loaded from localStorage so per-style tweaks (length,
  // separator, toggles) survive across sessions. Switching the
  // dropdown doesn't blow away the other styles' settings — each one
  // keeps its own sub-object.
  const state = loadPwgenState();
  const persist = () => savePwgenState(state);

  // Style selector --------------------------------------------------
  const styleRow = document.createElement("div");
  styleRow.className = "pw-row";
  const styleLab = document.createElement("label");
  styleLab.textContent = "Style";
  const styleSel = document.createElement("select");
  for (const [v, label] of [
    ["random", "Random characters"],
    ["xkcd", "XKCD words"],
    ["diceware", "Diceware"],
    ["pin", "PIN"],
  ]) {
    const opt = document.createElement("option");
    opt.value = v;
    opt.textContent = label;
    styleSel.appendChild(opt);
  }
  styleSel.value = state.style;
  styleSel.addEventListener("change", () => {
    state.style = styleSel.value;
    persist();
    renderControls();
    refresh();
  });
  styleRow.appendChild(styleLab);
  styleRow.appendChild(styleSel);
  pop.appendChild(styleRow);

  const controls = document.createElement("div");
  controls.className = "pw-controls";
  pop.appendChild(controls);

  const preview = document.createElement("div");
  preview.className = "pw-preview";
  pop.appendChild(preview);

  const actions = document.createElement("div");
  actions.className = "pw-actions";
  const reroll = document.createElement("button");
  reroll.type = "button";
  reroll.textContent = "Re-roll";
  reroll.addEventListener("click", refresh);
  const use = document.createElement("button");
  use.type = "button";
  use.textContent = "Use";
  use.addEventListener("click", () => {
    if (!preview.textContent) return;
    onAccept(preview.textContent);
    closePwPopover();
  });
  actions.appendChild(reroll);
  actions.appendChild(use);
  pop.appendChild(actions);

  // sliderRow builds the `<label> <range> <value>` triplet used by the
  // length/words controls in every style.
  function sliderRow(labelText, min, max, value, onChange) {
    const row = document.createElement("div");
    row.className = "pw-row";
    const lab = document.createElement("label");
    lab.textContent = labelText;
    const val = document.createElement("span");
    val.className = "pw-length-val";
    val.textContent = String(value);
    const slider = document.createElement("input");
    slider.type = "range";
    slider.min = String(min);
    slider.max = String(max);
    slider.value = String(value);
    slider.addEventListener("input", () => {
      const n = parseInt(slider.value, 10);
      val.textContent = slider.value;
      onChange(n);
    });
    row.appendChild(lab);
    row.appendChild(slider);
    row.appendChild(val);
    return row;
  }

  function checkboxLabel(text, checked, onChange) {
    const lbl = document.createElement("label");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = checked;
    cb.addEventListener("change", () => onChange(cb.checked, cb));
    lbl.appendChild(cb);
    lbl.appendChild(document.createTextNode(" " + text));
    return lbl;
  }

  function renderControls() {
    controls.replaceChildren();
    if (state.style === "random") renderRandomControls();
    else if (state.style === "xkcd" || state.style === "diceware") renderWordsControls(state[state.style]);
    else if (state.style === "pin") renderPinControls();
  }

  function renderRandomControls() {
    const r = state.random;
    controls.appendChild(sliderRow("Length", 8, 64, r.length, (n) => {
      r.length = n; persist(); refresh();
    }));

    const classRow = document.createElement("div");
    classRow.className = "pw-classes";
    for (const cls of ["upper", "lower", "digits", "symbols"]) {
      classRow.appendChild(checkboxLabel(cls, r.classes[cls], (on, cb) => {
        // Refuse "everything off" — silently no-opping would surprise
        // users who toggled their last class off by mistake.
        const next = { ...r.classes, [cls]: on };
        if (!Object.values(next).some(Boolean)) {
          cb.checked = true;
          return;
        }
        r.classes[cls] = on;
        persist();
        refresh();
      }));
    }
    controls.appendChild(classRow);

    const ambigRow = document.createElement("div");
    ambigRow.className = "pw-classes";
    ambigRow.appendChild(checkboxLabel("exclude ambiguous (Il1O0)", r.excludeAmbiguous, (on) => {
      r.excludeAmbiguous = on; persist(); refresh();
    }));
    controls.appendChild(ambigRow);
  }

  function renderWordsControls(w) {
    controls.appendChild(sliderRow("Words", 2, 8, w.words, (n) => {
      w.words = n; persist(); refresh();
    }));

    const sepRow = document.createElement("div");
    sepRow.className = "pw-row";
    const sepLab = document.createElement("label");
    sepLab.textContent = "Separator";
    const sepInp = document.createElement("input");
    sepInp.type = "text";
    sepInp.maxLength = 3;
    sepInp.value = w.separator;
    sepInp.placeholder = "(none)";
    sepInp.addEventListener("input", () => {
      w.separator = sepInp.value;
      persist();
      refresh();
    });
    sepRow.appendChild(sepLab);
    sepRow.appendChild(sepInp);
    // Pad out the trailing grid column so the input lines up with the
    // sliders above.
    sepRow.appendChild(document.createElement("span"));
    controls.appendChild(sepRow);

    const optRow = document.createElement("div");
    optRow.className = "pw-classes";
    optRow.appendChild(checkboxLabel("number", w.number, (on) => {
      w.number = on; persist(); refresh();
    }));
    optRow.appendChild(checkboxLabel("!", w.symbol, (on) => {
      w.symbol = on; persist(); refresh();
    }));
    controls.appendChild(optRow);
  }

  function renderPinControls() {
    const p = state.pin;
    controls.appendChild(sliderRow("Digits", 4, 12, p.length, (n) => {
      p.length = n; persist(); refresh();
    }));
  }

  async function refresh() {
    let res;
    try {
      if (state.style === "random") {
        const r = state.random;
        // RandomOpts has no JSON tags so Wails marshals the Go field
        // names verbatim. Keep keys in PascalCase to match.
        res = await window.go.gui.App.GenerateRandom({
          Length: r.length,
          Upper: r.classes.upper,
          Lower: r.classes.lower,
          Digits: r.classes.digits,
          Symbols: r.classes.symbols,
          ExcludeAmbiguous: r.excludeAmbiguous,
        });
      } else if (state.style === "xkcd" || state.style === "diceware") {
        const w = state[state.style];
        res = await window.go.gui.App.GenerateXKCD({
          Words: w.words,
          Separator: w.separator,
          Number: w.number,
          Suffix: w.symbol ? "!" : "",
        });
      } else if (state.style === "pin") {
        res = await window.go.gui.App.GeneratePIN(state.pin.length);
      }
    } catch (e) {
      preview.textContent = "";
      preview.title = e && e.message ? e.message : String(e);
      return;
    }
    if (res && res.error) {
      preview.textContent = "";
      preview.title = res.error;
    } else {
      preview.textContent = res ? res.password : "";
      preview.title = "";
    }
  }

  renderControls();
  refresh();

  document.body.appendChild(pop);
  activePwPopover = pop;
  // Position below the anchor row, right-aligned with the Generate
  // button so the popover doesn't dangle off the right edge of the
  // narrow detail card.
  const r = anchorRow.getBoundingClientRect();
  const margin = 8;
  pop.style.left = `${Math.max(margin, r.right - pop.offsetWidth)}px`;
  pop.style.top = `${r.bottom + margin}px`;
}

// resolveNode walks a vault tree by stored-key parts and returns the
// node (or null). Root (empty parts) returns a synthetic dir node so the
// caller's isDir check still works.
function resolveNode(tree, parts) {
  if (!parts || parts.length === 0) return { children: tree };
  let cur = tree;
  for (let i = 0; i < parts.length; i++) {
    const node = cur[parts[i]];
    if (!node) return null;
    if (i === parts.length - 1) return node;
    if (!node.children) return null;
    cur = node.children;
  }
  return null;
}

// callValidator invokes a Wails-bound validator and surfaces transport
// errors as the message itself, so an unbound runtime doesn't silently
// mark every input "valid."
async function callValidator(name, ...args) {
  try {
    return await window.go.gui.App[name](...args);
  } catch (e) {
    return e && e.message ? e.message : String(e);
  }
}

function renderAdvancedTOTP(node) {
  const wrap = document.createElement("details");
  wrap.className = "advanced";
  wrap.open = false;
  const summary = document.createElement("summary");
  summary.textContent = "Advanced TOTP";
  wrap.appendChild(summary);

  wrap.appendChild(selectField({
    label: "Algorithm",
    value: node.totpAlgo || "SHA1",
    options: ["SHA1", "SHA256", "SHA512"],
    onInput: (v) => { node.totpAlgo = v === "SHA1" ? null : v; markDirty(); },
  }));

  wrap.appendChild(selectField({
    label: "Digits",
    value: String(node.totpDigits || 6),
    options: ["6", "8"],
    onInput: (v) => {
      const n = parseInt(v, 10);
      node.totpDigits = n === 6 ? null : n;
      markDirty();
    },
  }));

  wrap.appendChild(numberField({
    label: "Period (s)",
    value: node.totpPeriod || 30,
    onInput: (n) => { node.totpPeriod = n === 30 ? null : n; markDirty(); },
    validate: (n) => callValidator("ValidateTOTPPeriod", n),
  }));

  return wrap;
}

// selectField accepts options either as plain strings (legacy, used by
// the cred form's TOTP algo picker) or as {value, label} pairs (used by
// the settings form's theme picker).
function selectField({ label, value, options, onInput }) {
  const row = document.createElement("div");
  row.className = "field";
  const lab = document.createElement("label");
  lab.textContent = label;
  row.appendChild(lab);
  const sel = document.createElement("select");
  for (const opt of options) {
    const o = document.createElement("option");
    if (typeof opt === "string") {
      o.value = opt;
      o.textContent = opt;
      if (opt === value) o.selected = true;
    } else {
      o.value = opt.value;
      o.textContent = opt.label;
      if (opt.value === value) o.selected = true;
    }
    sel.appendChild(o);
  }
  sel.addEventListener("change", () => onInput(sel.value));
  row.appendChild(sel);
  return row;
}

function numberField({ label, value, onInput, validate }) {
  const row = document.createElement("div");
  row.className = "field";
  const lab = document.createElement("label");
  lab.textContent = label;
  row.appendChild(lab);
  const input = document.createElement("input");
  input.type = "number";
  input.min = "1";
  input.max = "600";
  input.value = String(value);
  row.appendChild(input);
  const err = document.createElement("span");
  err.className = "field-error";
  err.hidden = true;
  row.appendChild(err);
  input.addEventListener("input", () => {
    const n = parseInt(input.value, 10);
    if (!Number.isNaN(n)) onInput(n);
    if (!err.hidden) { err.hidden = true; err.textContent = ""; }
  });
  input.addEventListener("blur", async () => {
    const n = parseInt(input.value, 10);
    const msg = Number.isNaN(n)
      ? "bad TOTP period (want 1-600)"
      : await Promise.resolve(validate(n));
    if (msg) { err.textContent = msg; err.hidden = false; }
    else { err.hidden = true; err.textContent = ""; }
  });
  return row;
}

// refreshTOTPAdvancedVisibility hides the algo/digits/period block when
// the secret is empty — the serialiser would drop those fields anyway.
// applyOTPAuthToNode mirrors the schema's "absent = default" rule: an
// otpauth URI that omits algorithm/digits/period leaves those node
// fields nil so the serialiser drops them, exactly as it would for a
// hand-typed secret on default settings.
function applyOTPAuthToNode(node, res) {
  node.totpSecret = res.secret;
  node.totpAlgo = res.algorithm ? res.algorithm : null;
  node.totpDigits = res.digits ? res.digits : null;
  node.totpPeriod = res.period ? res.period : null;
}

function refreshTOTPPreviewVisibility(form, node) {
  const row = form.querySelector(".totp-preview");
  if (!row) return;
  row.hidden = !node.totpSecret;
}

function refreshTOTPAdvancedVisibility(form, node) {
  const adv = form.querySelector("details.advanced");
  if (!adv) return;
  adv.hidden = node.totpSecret == null || node.totpSecret === "";
}

function markDirty() {
  if (dirty) return;
  dirty = true;
  applyDirty();
}

function clearDirty() {
  if (!dirty) return;
  dirty = false;
  applyDirty();
}

function markSettingsDirty() {
  if (settingsDirty) return;
  settingsDirty = true;
  applyDirty();
}

function clearSettingsDirty() {
  if (!settingsDirty) return;
  settingsDirty = false;
  applyDirty();
}

// pageDirty returns the dirty flag for the active page, since toolbar
// buttons (Write to device, Reload, the unsaved-changes indicator)
// only ever act on whichever page is on screen.
function pageDirty() {
  return currentPage === "settings" ? settingsDirty : dirty;
}

function applyDirty() {
  const d = pageDirty();
  // Mode-flipped or disconnected: Write to device would fail on the
  // device side anyway, but disabling it locally surfaces *why* without
  // making the user click and read a toast.
  saveBtn.disabled = !d || mgmtBlockedByModeFlip;
  dirtyIndicator.hidden = !d;
}

async function reloadTree() {
  reloadTreeBtn.disabled = true;
  treePane.innerHTML = '<p class="muted">Loading vault…</p>';
  try {
    const res = await window.go.gui.App.ReadVault();
    if (res.error) {
      treePane.innerHTML = `<p class="error">${escapeHtml(res.error)}</p>`;
      vaultTree = null;
      detailPane.innerHTML = '<p class="muted">Select an entry to inspect.</p>';
      clearDirty();
      return;
    }
    vaultTree = res.tree || {};
    // Selection from a previous read may no longer resolve; drop it
    // rather than carry over a stale highlight.
    selectedPath = null;
    clearDirty();
    renderTree();
    detailPane.innerHTML = '<p class="muted">Select an entry to inspect.</p>';
  } catch (e) {
    treePane.innerHTML =
      `<p class="error">${escapeHtml(e && e.message ? e.message : String(e))}</p>`;
  } finally {
    reloadTreeBtn.disabled = false;
  }
}

// --- 10.5: structural ops (context menu) -------------------------------

const contextMenu = document.createElement("ul");
contextMenu.className = "context-menu";
contextMenu.hidden = true;
document.body.appendChild(contextMenu);

function closeContextMenu() {
  if (!contextMenu.hidden) {
    contextMenu.hidden = true;
    contextMenu.innerHTML = "";
  }
}

document.addEventListener("click", closeContextMenu);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeContextMenu();
});

function openContextMenu(x, y, parts, node) {
  const items = contextMenuItems(parts, node);
  if (items.length === 0) return;
  contextMenu.innerHTML = "";
  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = item.label;
    li.addEventListener("click", (e) => {
      e.stopPropagation();
      closeContextMenu();
      item.run();
    });
    contextMenu.appendChild(li);
  }
  contextMenu.style.left = `${x}px`;
  contextMenu.style.top = `${y}px`;
  contextMenu.hidden = false;
}

// contextMenuItems decides which items apply to the right-clicked node.
// Root (parts.length === 0) can host new children but not be renamed or
// deleted; dirs add both; creds get rename + delete only.
function contextMenuItems(parts, node) {
  const items = [];
  const isRoot = parts.length === 0;
  const dir = isDir(node);
  if (isRoot || dir) {
    items.push({ label: "New folder", run: () => onNewFolder(parts) });
    items.push({ label: "New credential", run: () => onNewCred(parts) });
  }
  if (!isRoot) {
    items.push({ label: "Rename", run: () => onRename(parts) });
    items.push({ label: "Delete", run: () => onDelete(parts, dir) });
    items.push({ label: "Cut", run: () => onCutOrCopy(parts, "mv") });
    items.push({ label: "Copy", run: () => onCutOrCopy(parts, "cp") });
  }
  if (clipboard && (isRoot || dir)) {
    items.push({ label: pasteLabel(), run: () => onPaste(parts) });
  }
  return items;
}

function pasteLabel() {
  if (!clipboard) return "Paste";
  const name = displayName(clipboard.srcParts[clipboard.srcParts.length - 1]);
  return `Paste ${name} (${clipboard.op})`;
}

function onCutOrCopy(parts, op) {
  clipboard = { op, srcParts: parts.slice() };
}

async function onPaste(dstDirParts) {
  if (!clipboard) return;
  const src = pathToString(clipboard.srcParts);
  const dst = pathToString(dstDirParts);
  let res;
  if (clipboard.op === "mv") {
    res = await window.go.gui.App.ApplyMv(vaultTree, src, dst);
  } else {
    // -r mirrors the CLI: copying a dir requires recursive consent.
    // Paste users have already opted in via the menu, so default true.
    res = await window.go.gui.App.ApplyCp(vaultTree, src, dst, true);
  }
  if (res.error) { announceSaveError(res.error); return; }
  vaultTree = res.tree;
  markDirty();
  const srcLeaf = clipboard.srcParts[clipboard.srcParts.length - 1];
  // Cut consumes the clipboard; Copy can be pasted repeatedly until
  // explicitly replaced.
  if (clipboard.op === "mv") clipboard = null;
  // Selection moves with the node so the user can keep editing it.
  selectedPath = dstDirParts.concat(srcLeaf);
  renderTree();
  const node = resolveNode(vaultTree, selectedPath);
  if (node) renderDetail(selectedPath, node);
}

async function onNewFolder(parentParts) {
  const name = window.prompt("New folder name");
  if (!name) return;
  const key = toStoredKey(name);
  const path = pathToString(parentParts.concat(key));
  const res = await window.go.gui.App.ApplyNewFolder(vaultTree, path);
  if (res.error) { announceSaveError(res.error); return; }
  vaultTree = res.tree;
  markDirty();
  expanded.add(pathKey(parentParts));
  selectedPath = parentParts.concat(key);
  renderTree();
  renderDetail(selectedPath, resolveNode(vaultTree, selectedPath));
}

async function onNewCred(parentParts) {
  const name = window.prompt("New credential name");
  if (!name) return;
  const key = toStoredKey(name);
  const path = pathToString(parentParts.concat(key));
  const res = await window.go.gui.App.ApplyNewCred(vaultTree, path);
  if (res.error) { announceSaveError(res.error); return; }
  vaultTree = res.tree;
  markDirty();
  expanded.add(pathKey(parentParts));
  selectedPath = parentParts.concat(key);
  renderTree();
  renderDetail(selectedPath, resolveNode(vaultTree, selectedPath));
}

async function onRename(parts) {
  const current = parts[parts.length - 1];
  const next = window.prompt("Rename to", displayName(current));
  if (!next) return;
  const newKey = toStoredKey(next);
  if (newKey === current) return;
  const res = await window.go.gui.App.ApplyRename(
    vaultTree, pathToString(parts), newKey);
  if (res.error) { announceSaveError(res.error); return; }
  vaultTree = res.tree;
  selectedPath = parts.slice(0, -1).concat(newKey);
  markDirty();
  renderTree();
  renderDetail(selectedPath, resolveNode(vaultTree, selectedPath));
}

async function onDelete(parts, isDirNode) {
  // Confirm recursive deletes — a single misclick on a folder would
  // otherwise drop arbitrary children silently.
  if (isDirNode) {
    const node = resolveNode(vaultTree, parts);
    const childCount = node && node.children ? Object.keys(node.children).length : 0;
    const label = "/" + parts.map(displayName).join("/");
    const msg = childCount === 0
      ? `Delete empty folder ${label}?`
      : `Delete folder ${label} and its ${childCount} ${childCount === 1 ? "entry" : "entries"}?`;
    if (!window.confirm(msg)) return;
  }
  const res = await window.go.gui.App.ApplyDelete(vaultTree, pathToString(parts));
  if (res.error) { announceSaveError(res.error); return; }
  vaultTree = res.tree;
  // Drop the selection; the deleted path no longer resolves.
  selectedPath = null;
  markDirty();
  renderTree();
  detailPane.innerHTML = '<p class="muted">Select an entry to inspect.</p>';
}

// hasPassboxDrag inspects the dragover dataTransfer for our payload so
// dropping a file from outside the window doesn't trigger a phantom mv.
function hasPassboxDrag(e) {
  if (!e.dataTransfer) return false;
  return Array.from(e.dataTransfer.types).includes("application/x-passbox-path");
}

async function handleDrop(e, dstDirParts) {
  e.preventDefault();
  e.stopPropagation();
  const srcKey = e.dataTransfer.getData("application/x-passbox-path");
  if (!srcKey) return;
  const srcParts = srcKey.split("/");
  if (srcParts.length === 0) return;
  // No-op when src would land in its own current container.
  if (srcParts.slice(0, -1).join("/") === dstDirParts.join("/")) return;
  const src = pathToString(srcParts);
  const dst = pathToString(dstDirParts);
  const copy = e.ctrlKey;
  const res = copy
    ? await window.go.gui.App.ApplyCp(vaultTree, src, dst, true)
    : await window.go.gui.App.ApplyMv(vaultTree, src, dst);
  if (res.error) { announceSaveError(res.error); return; }
  vaultTree = res.tree;
  markDirty();
  const srcLeaf = srcParts[srcParts.length - 1];
  selectedPath = dstDirParts.concat(srcLeaf);
  expanded.add(pathKey(dstDirParts));
  renderTree();
  const node = resolveNode(vaultTree, selectedPath);
  if (node) renderDetail(selectedPath, node);
}

// onSave commits the active page's in-memory state. On any error the
// dirty flag stays — the user can fix the field, fix the device state,
// and try again without losing edits. On success the page is reloaded
// from the device so the visible state matches what was persisted (the
// device re-canonicalises the JSON on commit). Returns true on success
// so the discard-prompt "Write to device" path can chain on it.
async function onSave() {
  await flushPendingEdits();
  if (currentPage === "settings") return saveSettings();
  return saveVault();
}

async function saveVault() {
  if (!dirty || !vaultTree) return true;
  saveBtn.disabled = true;
  try {
    const res = await window.go.gui.App.WriteVault(vaultTree);
    if (res.error) {
      announceSaveError(res.error);
      return false;
    }
    clearDirty();
    await reloadTree();
    showToast("Written to device.", "ok");
    return true;
  } catch (e) {
    announceSaveError(e && e.message ? e.message : String(e));
    return false;
  } finally {
    saveBtn.disabled = !pageDirty();
  }
}

async function saveSettings() {
  if (!settingsDirty || !settings) return true;
  saveBtn.disabled = true;
  try {
    const res = await window.go.gui.App.WriteConfig(settings);
    if (res.error) {
      announceSaveError(res.error);
      return false;
    }
    clearSettingsDirty();
    await reloadSettings();
    showToast("Written to device.", "ok");
    return true;
  } catch (e) {
    announceSaveError(e && e.message ? e.message : String(e));
    return false;
  } finally {
    saveBtn.disabled = !pageDirty();
  }
}

// announceSaveError surfaces a device or validation failure via the
// toast. Kept as a named entry point so the call sites added in 10.5 /
// 10.6 continue to read sensibly.
function announceSaveError(msg) {
  showToast(translateError(msg), "err");
}

// translateError applies the phase-10.7 error-text policy: device codes
// pass through verbatim; transport-shape failures collapse to a single
// "device disconnected" message so the user gets a clear next step.
function translateError(msg) {
  if (!msg) return "";
  const m = String(msg);
  if (/port|closed|EOF|i\/o|timeout|deadline|broken pipe|unreachable/i.test(m)) {
    return "device disconnected — reconnect and try again";
  }
  return m;
}

// showToast renders msg with the requested kind ("ok" / "err"). Only one
// toast is visible at a time; a new call replaces the previous toast
// outright (including its timeout). Success toasts auto-dismiss after
// 2 s per the phase-10.7 spec; error toasts are sticky until the user
// clicks the dismiss button.
let toastTimer = null;
function showToast(msg, kind) {
  if (toastTimer !== null) {
    clearTimeout(toastTimer);
    toastTimer = null;
  }
  if (!msg) {
    toastEl.hidden = true;
    toastEl.textContent = "";
    return;
  }
  toastEl.className = "toast " + (kind === "ok" ? "toast-ok" : "toast-err");
  toastEl.textContent = "";
  const text = document.createElement("span");
  text.textContent = msg;
  toastEl.appendChild(text);
  const dismiss = document.createElement("button");
  dismiss.type = "button";
  dismiss.className = "toast-dismiss";
  dismiss.setAttribute("aria-label", "Dismiss");
  dismiss.textContent = "×";
  dismiss.addEventListener("click", () => showToast("", kind));
  toastEl.appendChild(dismiss);
  toastEl.hidden = false;
  if (kind === "ok") {
    toastTimer = setTimeout(() => showToast("", kind), 2000);
  }
}

// onReloadClick gates the toolbar Reload on the discard prompt. The
// in-app auto-load (from applyView when entering App mode) intentionally
// skips this — there are no dirty edits before the first read. Reload
// dispatches by active page.
async function onReloadClick() {
  const choice = await confirmDiscardIfDirty();
  if (choice === "cancel") return;
  if (choice === "write") {
    const ok = await onSave();
    if (!ok) return;
  }
  if (currentPage === "settings") await reloadSettings();
  else await reloadTree();
}

// switchPage flips between Vault and Settings, gating on the leaving
// page's discard prompt. The "Write to device" / Discard / Cancel modal
// serves cross-page navigation as well as Exit-management, per the
// 12.3 "10.4 prompt extends here" note.
async function switchPage(target) {
  if (currentPage === target) return;
  const choice = await confirmDiscardIfDirty();
  if (choice === "cancel") return;
  if (choice === "write") {
    const ok = await onSave();
    if (!ok) return;
  }
  currentPage = target;
  pageVault.hidden = target !== "vault";
  pageAudit.hidden = target !== "audit";
  pageSettings.hidden = target !== "settings";
  pageDeviceSettings.hidden = target !== "device-settings";
  navVaultBtn.classList.toggle("active", target === "vault");
  navAuditBtn.classList.toggle("active", target === "audit");
  navSettingsBtn.classList.toggle("active", target === "settings");
  navDeviceSettingsBtn.classList.toggle("active", target === "device-settings");
  applyDirty();
  if (target === "settings" && settings === null) {
    await reloadSettings();
  } else if (target === "device-settings" && settings === null) {
    await reloadSettings();
  } else if (target === "device-settings") {
    renderDeviceSettings();
  } else if (target === "audit") {
    await runAudit();
  }
}

async function reloadSettings() {
  settingsPane.innerHTML = '<p class="muted">Loading settings…</p>';
  try {
    const res = await window.go.gui.App.ReadConfig();
    if (res.error) {
      settingsPane.innerHTML =
        `<p class="error">${escapeHtml(res.error)}</p>`;
      settings = null;
      clearSettingsDirty();
      return;
    }
    settings = res.settings;
    // Apply the persisted theme as soon as settings land — startup
    // calls this once before the user ever opens the Settings tab,
    // so the whole window paints in the chosen palette from the get-go.
    if (settings && settings.appearance) applyTheme(settings.appearance.theme);
    clearSettingsDirty();
    renderSettings();
    if (caps.deviceSettings) renderDeviceSettings();
  } catch (e) {
    settingsPane.innerHTML =
      `<p class="error">${escapeHtml(e && e.message ? e.message : String(e))}</p>`;
  }
}

// renderSettings paints the whole form against the unified
// passvault.config.Settings schema. App-level sections always render;
// device-only sections (under settings.device) render only when
// caps.deviceSettings is on. Cheap to re-run end-to-end — re-rendering
// on every cross-field re-validate keeps the "what does the backend
// see right now" invariant trivial to reason about.
function renderSettings() {
  settingsPane.innerHTML = "";
  if (!settings) {
    settingsPane.innerHTML = '<p class="muted">No settings loaded.</p>';
    return;
  }
  ensureDefaultSubSections(settings);

  const globalErr = document.createElement("p");
  globalErr.className = "global-error error";
  globalErr.hidden = true;
  settingsPane.appendChild(globalErr);

  // --- App-level sections, always shown ---------------------------

  const appearance = section("Appearance");
  appearance.appendChild(selectField({
    label: "Theme",
    value: settings.appearance.theme || "system",
    options: [
      { value: "system", label: "Match system" },
      { value: "light",  label: "Light" },
      { value: "dark",   label: "Dark" },
    ],
    onInput: (v) => { settings.appearance.theme = v; applyTheme(v); markSettingsDirty(); revalidateConfig(); },
  }));
  settingsPane.appendChild(appearance);

  const sec = section("Security");
  sec.appendChild(uintField({
    label: "Auto-lock after (s)",
    value: settings.security.autoLockSeconds,
    onInput: (n) => { settings.security.autoLockSeconds = n; markSettingsDirty(); revalidateConfig(); },
  }));
  sec.appendChild(boolField({
    label: "Lock when idle",
    value: settings.security.lockOnIdle,
    onInput: (v) => { settings.security.lockOnIdle = v; markSettingsDirty(); revalidateConfig(); },
  }));
  sec.appendChild(boolField({
    label: "Enable breach checks (HIBP)",
    value: settings.security.breachCheckEnabled,
    onInput: (v) => { settings.security.breachCheckEnabled = v; markSettingsDirty(); revalidateConfig(); },
  }));
  sec.appendChild(boolField({
    label: "Remember last folder",
    value: settings.security.rememberLastFolderPath,
    onInput: (v) => { settings.security.rememberLastFolderPath = v; markSettingsDirty(); revalidateConfig(); },
  }));
  settingsPane.appendChild(sec);

  if (caps.login) {
    const srv = section("Server");
    srv.appendChild(textFieldSimple({
      label: "URL",
      value: settings.server.url || "",
      onInput: (v) => { settings.server.url = v; markSettingsDirty(); revalidateConfig(); },
      hint: "edited via Sign in / Sign out — manual changes won't re-authenticate",
    }));
    srv.appendChild(textFieldSimple({
      label: "Login name",
      value: settings.server.loginName || "",
      onInput: (v) => { settings.server.loginName = v; markSettingsDirty(); revalidateConfig(); },
    }));
    settingsPane.appendChild(srv);
  }

  revalidateConfig();
}

// renderDeviceSettings paints the device-only sections into the
// separate Device Settings pane. Only called when caps.deviceSettings
// is true; the nav tab is hidden otherwise so this never runs on
// host-side backends.
function renderDeviceSettings() {
  deviceSettingsPane.innerHTML = "";
  if (!settings) {
    deviceSettingsPane.innerHTML = '<p class="muted">No settings loaded.</p>';
    return;
  }
  ensureDefaultSubSections(settings);
  const dev = settings.device;

  const devSec = section("Device security");
  devSec.appendChild(uintField({
    label: "Auto-lock timeout (s)",
    value: dev.security.timeoutBeforeAutoLock,
    onInput: (n) => { dev.security.timeoutBeforeAutoLock = n; markSettingsDirty(); revalidateConfig(); },
  }));
  devSec.appendChild(uintField({
    label: "USB disconnect lock timeout (s)",
    value: dev.security.timeoutBeforeUSBDisconnectLock,
    onInput: (n) => { dev.security.timeoutBeforeUSBDisconnectLock = n; markSettingsDirty(); revalidateConfig(); },
  }));
  deviceSettingsPane.appendChild(devSec);

  const oled = section("OLED Protection");
  oled.appendChild(uintField({
    label: "Screensaver after (s)",
    value: dev.oledProtection.timeoutBeforeScreenSaver,
    onInput: (n) => { dev.oledProtection.timeoutBeforeScreenSaver = n; markSettingsDirty(); revalidateConfig(); },
  }));
  oled.appendChild(uintField({
    label: "Sleep after (s)",
    value: dev.oledProtection.timeoutBeforeSleep,
    onInput: (n) => { dev.oledProtection.timeoutBeforeSleep = n; markSettingsDirty(); revalidateConfig(); },
  }));

  const clk = subSection("Screensaver — Clock");
  clk.appendChild(boolField({
    label: "Enabled",
    value: dev.oledProtection.screenSaver.clock.enabled,
    onInput: (v) => { dev.oledProtection.screenSaver.clock.enabled = v; markSettingsDirty(); revalidateConfig(); },
  }));
  clk.appendChild(uintField({
    label: "Timeout between animations (s)",
    value: dev.oledProtection.screenSaver.clock.timeoutBetweenAnimations,
    onInput: (n) => { dev.oledProtection.screenSaver.clock.timeoutBetweenAnimations = n; markSettingsDirty(); revalidateConfig(); },
  }));
  oled.appendChild(clk);

  const anim = subSection("Screensaver — Animations");
  anim.appendChild(boolField({
    label: "Enabled",
    value: dev.oledProtection.screenSaver.animations.enabled,
    onInput: (v) => { dev.oledProtection.screenSaver.animations.enabled = v; markSettingsDirty(); revalidateConfig(); },
  }));
  anim.appendChild(uintField({
    label: "Timeout between clock (s)",
    value: dev.oledProtection.screenSaver.animations.timeoutBetweenClock,
    onInput: (n) => { dev.oledProtection.screenSaver.animations.timeoutBetweenClock = n; markSettingsDirty(); revalidateConfig(); },
  }));
  anim.appendChild(boolField({
    label: "Raindrops",
    value: dev.oledProtection.screenSaver.animations.raindrops.enabled,
    onInput: (v) => { dev.oledProtection.screenSaver.animations.raindrops.enabled = v; markSettingsDirty(); revalidateConfig(); },
  }));
  oled.appendChild(anim);
  deviceSettingsPane.appendChild(oled);

  const cl = section("Clock");
  cl.appendChild(intField({
    label: "Timezone offset (minutes)",
    value: dev.clock.timezoneOffset,
    onInput: (n) => { dev.clock.timezoneOffset = n; markSettingsDirty(); revalidateConfig(); },
  }));
  deviceSettingsPane.appendChild(cl);

  const vl = section("Volume Label");
  vl.appendChild(textFieldSimple({
    label: "Label",
    value: dev.volumeLabel,
    onInput: (v) => { dev.volumeLabel = v; markSettingsDirty(); revalidateConfig(); },
    hint: "takes effect next Disk mount",
  }));
  deviceSettingsPane.appendChild(vl);

  revalidateConfig();
}

// ensureDefaultSubSections fills in missing sub-objects so the form
// can dereference them safely. Go's omitzero drops zero-valued
// sub-structs from the JSON payload — without this, a freshly-defaulted
// Settings with no Device/Server section would crash the renderer on
// `settings.device.security.timeoutBeforeAutoLock`.
function ensureDefaultSubSections(s) {
  if (!s.appearance) s.appearance = { theme: "system" };
  if (!s.clipboard) s.clipboard = { clearAfterSeconds: 0 };
  if (!s.security) s.security = {
    autoLockSeconds: 0, lockOnIdle: false,
    breachCheckEnabled: false, rememberLastFolderPath: false,
  };
  if (!s.server) s.server = { url: "", loginName: "" };
  if (!s.device) s.device = {};
  const d = s.device;
  if (!d.security) d.security = { timeoutBeforeAutoLock: 0, timeoutBeforeUSBDisconnectLock: 0 };
  if (!d.oledProtection) d.oledProtection = {};
  if (!d.oledProtection.screenSaver) d.oledProtection.screenSaver = {};
  if (!d.oledProtection.screenSaver.clock) d.oledProtection.screenSaver.clock = { enabled: false, timeoutBetweenAnimations: 0 };
  if (!d.oledProtection.screenSaver.animations) d.oledProtection.screenSaver.animations = { enabled: false, timeoutBetweenClock: 0 };
  if (!d.oledProtection.screenSaver.animations.raindrops) d.oledProtection.screenSaver.animations.raindrops = { enabled: false };
  if (d.oledProtection.timeoutBeforeScreenSaver === undefined) d.oledProtection.timeoutBeforeScreenSaver = 0;
  if (d.oledProtection.timeoutBeforeSleep === undefined) d.oledProtection.timeoutBeforeSleep = 0;
  if (!d.clock) d.clock = { timezoneOffset: 0 };
  if (d.volumeLabel === undefined) d.volumeLabel = "";
}

function section(title) {
  const sec = document.createElement("div");
  sec.className = "section";
  const h = document.createElement("h3");
  h.textContent = title;
  sec.appendChild(h);
  return sec;
}

function subSection(title) {
  const sub = document.createElement("div");
  sub.className = "nested";
  const h = document.createElement("h3");
  h.textContent = title;
  sub.appendChild(h);
  return sub;
}

function uintField({ label, value, onInput }) {
  const row = document.createElement("div");
  row.className = "field";
  const lab = document.createElement("label");
  lab.textContent = label;
  row.appendChild(lab);
  const input = document.createElement("input");
  input.type = "number";
  input.min = "0";
  input.value = String(value);
  input.addEventListener("input", () => {
    const n = parseInt(input.value, 10);
    if (!Number.isNaN(n) && n >= 0) onInput(n);
  });
  row.appendChild(input);
  return row;
}

function intField({ label, value, onInput }) {
  const row = document.createElement("div");
  row.className = "field";
  const lab = document.createElement("label");
  lab.textContent = label;
  row.appendChild(lab);
  const input = document.createElement("input");
  input.type = "number";
  input.value = String(value);
  input.addEventListener("input", () => {
    const n = parseInt(input.value, 10);
    if (!Number.isNaN(n)) onInput(n);
  });
  row.appendChild(input);
  return row;
}

function boolField({ label, value, onInput }) {
  const row = document.createElement("div");
  row.className = "field";
  const lab = document.createElement("label");
  lab.textContent = label;
  row.appendChild(lab);
  const input = document.createElement("input");
  input.type = "checkbox";
  input.checked = !!value;
  input.addEventListener("change", () => onInput(input.checked));
  row.appendChild(input);
  return row;
}

function textFieldSimple({ label, value, onInput, hint }) {
  const row = document.createElement("div");
  row.className = "field";
  const lab = document.createElement("label");
  lab.textContent = label;
  row.appendChild(lab);
  const input = document.createElement("input");
  input.type = "text";
  input.value = value || "";
  input.addEventListener("input", () => onInput(input.value));
  row.appendChild(input);
  if (hint) {
    const h = document.createElement("span");
    h.className = "hint";
    h.textContent = hint;
    row.appendChild(h);
  }
  return row;
}

// revalidateConfig runs the same Validate the CLI invokes pre-write so
// the cross-field invariant (animations enabled but no animation type
// enabled, FAT label charset, timeout ranges) surfaces inline as the
// user toggles fields — not just on Write. Disables the Write button
// when invalid so a bad commit is impossible.
let revalidateTimer = null;
async function revalidateConfig() {
  if (!settings) return;
  if (revalidateTimer !== null) {
    clearTimeout(revalidateTimer);
  }
  // Debounce the round-trip so dragging a slider doesn't fire a binding
  // call per keystroke. 120 ms is the same budget the CLI's friendly
  // error toasts use.
  revalidateTimer = setTimeout(async () => {
    revalidateTimer = null;
    const err = await window.go.gui.App.ValidateConfig(settings);
    const banner = settingsPane.querySelector(".global-error");
    if (!banner) return;
    if (err) {
      banner.textContent = err;
      banner.hidden = false;
      saveBtn.disabled = true;
    } else {
      banner.hidden = true;
      banner.textContent = "";
      applyDirty();
    }
  }, 120);
}

// onCloseRequested handles the Go-emitted `app:close-requested` event.
// OnBeforeClose blocks the close until we call ConfirmClose; the user
// may also abort, in which case the window stays open.
async function onCloseRequested() {
  const choice = await confirmDiscardIfDirty();
  if (choice === "cancel") return;
  if (choice === "write") {
    const ok = await onSave();
    if (!ok) return;
  }
  window.go.gui.App.ConfirmClose();
}

// Search input — debounced 150 ms so a fast typist doesn't queue up a
// Search round-trip per keystroke. Clearing the input restores the
// unfiltered tree.
searchInput.addEventListener("input", () => {
  if (searchDebounce) clearTimeout(searchDebounce);
  searchDebounce = setTimeout(() => runSearch(searchInput.value), 150);
});

async function runSearch(query) {
  searchQuery = query.trim();
  if (searchQuery === "") {
    searchHits = null;
    renderTree();
    return;
  }
  let hits;
  try {
    hits = await window.go.gui.App.Search(searchQuery);
  } catch (e) {
    hits = null;
  }
  searchHits = new Set();
  if (Array.isArray(hits)) {
    for (const h of hits) {
      if (h && typeof h.id === "string") searchHits.add(h.id);
    }
  }
  renderTree();
}

refreshBtn.addEventListener("click", refresh);
enableBtn.addEventListener("click", onEnable);
disableBtn.addEventListener("click", onDisable);
reloadTreeBtn.addEventListener("click", onReloadClick);
saveBtn.addEventListener("click", onSave);
navVaultBtn.addEventListener("click", () => switchPage("vault"));
navAuditBtn.addEventListener("click", () => switchPage("audit"));
navSettingsBtn.addEventListener("click", () => switchPage("settings"));
navDeviceSettingsBtn.addEventListener("click", () => switchPage("device-settings"));
logoutBtn.addEventListener("click", onLogout);
loginBeginBtn.addEventListener("click", onBeginLogin);
loginCancelBtn.addEventListener("click", onCancelLogin);
loginServerInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !loginPending) {
    e.preventDefault();
    onBeginLogin();
  }
});

// onBeginLogin kicks off the backend's login flow and then polls
// WaitForLogin. The shared UI is intentionally backend-agnostic: it
// never knows what BeginLogin actually does (Nextcloud Flow v2, a
// mocked in-process server, anything else). All it does is collect a
// server URL, show a "continue in browser" affordance, and wait.
async function onBeginLogin() {
  const server = (loginServerInput.value || "").trim();
  if (!server) {
    showLoginError("Enter a server URL to continue.");
    return;
  }
  setLoginPending(true);
  showLoginError("");
  let init;
  try {
    init = await window.go.gui.App.BeginLogin(server);
  } catch (e) {
    setLoginPending(false);
    showLoginError(e && e.message ? e.message : String(e));
    return;
  }
  if (init && init.error) {
    setLoginPending(false);
    showLoginError(init.error);
    return;
  }
  loginHintEl.textContent =
    "Approve the request in your browser, then return here.";
  // The backend has already attempted to open the URL where supported.
  // Show it as a fallback so headless / unusual environments still have
  // a clickable target.
  if (init && init.loginURL) {
    const link = document.createElement("a");
    link.href = init.loginURL;
    link.textContent = init.loginURL;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    loginHintEl.appendChild(document.createElement("br"));
    loginHintEl.appendChild(link);
  }

  let status;
  try {
    status = await window.go.gui.App.WaitForLogin();
  } catch (e) {
    setLoginPending(false);
    showLoginError(e && e.message ? e.message : String(e));
    return;
  }
  if (!status || status.error) {
    setLoginPending(false);
    showLoginError((status && status.error) || "login failed");
    return;
  }
  authState = {
    loggedIn: !!status.loggedIn,
    server: status.server || "",
    loginName: status.loginName || "",
  };
  setLoginPending(false);
  loginHintEl.textContent = "Enter your server URL to begin.";
  loginServerInput.value = "";
  applyView();
}

async function onCancelLogin() {
  try {
    await window.go.gui.App.CancelLogin();
  } catch (e) {
    // Best-effort — the backend's flow may already have torn down.
  }
  setLoginPending(false);
  loginHintEl.textContent = "Enter your server URL to begin.";
  showLoginError("");
}

async function onLogout() {
  try {
    const err = await window.go.gui.App.Logout();
    if (err) {
      showToast(translateError(err), "err");
      return;
    }
  } catch (e) {
    showToast(translateError(e && e.message ? e.message : String(e)), "err");
    return;
  }
  authState = { loggedIn: false, server: "", loginName: "" };
  // Force the wasInApp transition so applyView clears in-memory state.
  wasInApp = true;
  applyView();
}

function setLoginPending(pending) {
  loginPending = pending;
  loginBeginBtn.disabled = pending;
  loginBeginBtn.textContent = pending ? "Waiting for approval…" : "Continue";
  loginCancelBtn.hidden = !pending;
  loginServerInput.disabled = pending;
}

function showLoginError(msg) {
  if (!msg) {
    loginErrorEl.hidden = true;
    loginErrorEl.textContent = "";
    return;
  }
  loginErrorEl.hidden = false;
  loginErrorEl.textContent = msg;
}

// Right-clicking the empty area of the tree pane (not on a row) targets
// the root, so "New folder" / "New credential" work even on a vault
// that's currently empty.
treePane.addEventListener("contextmenu", (e) => {
  if (e.target.closest(".row")) return;
  e.preventDefault();
  if (!vaultTree) return;
  openContextMenu(e.clientX, e.clientY, [], { children: vaultTree });
});

// Dropping on the empty area of the tree pane (or on '/') drops onto
// the root container — the same semantics as the CLI's `vault mv x /`.
treePane.addEventListener("dragover", (e) => {
  if (!hasPassboxDrag(e)) return;
  if (e.target.closest(".row.dir")) return;
  e.preventDefault();
  e.dataTransfer.dropEffect = e.ctrlKey ? "copy" : "move";
  treePane.classList.add("drop-target");
});
treePane.addEventListener("dragleave", (e) => {
  if (e.target === treePane) treePane.classList.remove("drop-target");
});
treePane.addEventListener("drop", (e) => {
  treePane.classList.remove("drop-target");
  if (e.target.closest(".row.dir")) return;
  handleDrop(e, []);
});
// Wails v2 injects window.go.<package>.<Struct> via its own bootstrap
// script, but doesn't expose a documented "ready" event we can listen
// for. DOMContentLoaded sometimes races ahead of the injection, so poll
// briefly until the binding namespace appears.
function whenBindingsReady(fn) {
  if (window.go && window.go.gui && window.go.gui.App) {
    fn();
    return;
  }
  setTimeout(() => whenBindingsReady(fn), 50);
}

// pickDeviceIfMany shows the picker modal when DiscoverAll returns more
// than one Passbox. With 0 or 1, it's a no-op — the existing
// not-connected card / auto-selected single device covers those.
async function pickDeviceIfMany() {
  if (!caps.deviceMgmt) return;
  let res;
  try {
    res = await window.go.gui.App.DiscoverAll();
  } catch (e) {
    return;
  }
  if (!res || !res.devices || res.devices.length <= 1) return;
  return new Promise((resolve) => {
    const overlayEl = document.getElementById("picker-overlay");
    const listEl = document.getElementById("picker-list");
    listEl.innerHTML = "";
    for (const d of res.devices) {
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.type = "button";
      const name = document.createElement("span");
      name.textContent = d.portName;
      btn.appendChild(name);
      const serial = document.createElement("span");
      serial.className = "serial";
      serial.textContent = d.serial || "(no serial)";
      btn.appendChild(serial);
      btn.addEventListener("click", async () => {
        await window.go.gui.App.SelectDevice(d.serial || "");
        overlayEl.hidden = true;
        resolve();
      });
      li.appendChild(btn);
      listEl.appendChild(li);
    }
    overlayEl.hidden = false;
  });
}

window.addEventListener("DOMContentLoaded", () => whenBindingsReady(async () => {
  // Capabilities is the very first call — every subsequent decision
  // (login screen vs vault, status ticker vs static, settings sections
  // visible) reads from it, so loading it before anything else paints
  // avoids a flash of device-flavored chrome on host-only backends.
  try {
    caps = await window.go.gui.App.Capabilities();
  } catch (e) {
    // Fall back to host-only defaults if the binding isn't there yet —
    // the runtime will eventually inject and the next user action will
    // re-fetch. Don't render the device-mgmt chrome until we know.
    caps = { ...caps };
  }

  // Show / hide chrome that's permanent for the session.
  refreshBtn.hidden = !caps.deviceMgmt;
  disableBtn.hidden = !caps.deviceMgmt;
  navSettingsBtn.hidden = !caps.appSettings;
  navAuditBtn.hidden = !caps.audit;
  navDeviceSettingsBtn.hidden = !caps.deviceSettings;
  logoutBtn.hidden = !caps.login;

  if (caps.login) {
    try {
      const st = await window.go.gui.App.GetAuthStatus();
      if (st) {
        authState = {
          loggedIn: !!st.loggedIn,
          server: st.server || "",
          loginName: st.loginName || "",
        };
      }
    } catch (e) {
      // Stay logged-out on a failed status query — the login screen is
      // the only safe default for a Login-capable backend.
    }
  } else {
    // Non-login backends are trivially "logged in" so applyView never
    // gates on auth state.
    authState.loggedIn = true;
  }

  if (caps.deviceMgmt) {
    await pickDeviceIfMany();
    await refresh();
    startStatusTicker();
  } else {
    // Host-side backend: fabricate a "device present" status so the
    // rest of the UI's lastStatus reads succeed without a real device.
    lastStatus = { connected: true, mode: "app" };
    applyView();
  }

  // Preload settings so the persisted theme applies at startup,
  // before the user ever opens the Settings tab. Safe to do as soon
  // as we know we're logged in (or have a non-login backend) — the
  // ReadConfig binding doesn't require an unlocked vault.
  if (authState.loggedIn) reloadSettings();

  // The runtime injects EventsOn alongside the bound App; we register
  // the close-request listener here so the prompt runs even on the very
  // first close attempt.
  if (window.runtime && window.runtime.EventsOn) {
    window.runtime.EventsOn("app:close-requested", onCloseRequested);
  }
}));

// Pause the ticker when the window loses focus or is hidden — backgrounded
// GUIs don't need to keep the device awake. The poll resumes from a fresh
// fetch (not a cached tick) so any change while hidden is reflected on
// the first re-render after focus.
document.addEventListener("visibilitychange", () => {
  if (document.hidden) stopStatusTicker();
  else if (window.go && window.go.gui && window.go.gui.App) {
    fetchStatus();
    startStatusTicker();
  }
});
window.addEventListener("blur", stopStatusTicker);

// 12.6 keyboard shortcuts: Ctrl/Cmd+S writes the active page; Esc
// dismisses overlays and toasts (the existing context-menu / popover
// Esc handlers stay — this handler covers what they don't).
document.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && (e.key === "s" || e.key === "S")) {
    e.preventDefault();
    if (pageDirty() && !saveBtn.disabled) onSave();
    return;
  }
  if (e.key === "Escape") {
    // Order matters: dismiss the topmost transient layer first so the
    // user never has to press Esc twice for a single visible thing.
    if (!overlay.hidden) { closeOverlay(); return; }
    if (!discardOverlay.hidden) { discardOverlay.hidden = true; return; }
    if (!toastEl.hidden) { showToast("", "ok"); return; }
  }
});
window.addEventListener("focus", () => {
  if (window.go && window.go.gui && window.go.gui.App && !document.hidden) {
    startStatusTicker();
  }
});
