// Package config defines the unified Settings schema both passvault
// consumers persist and the shared Wails UI renders. The struct is
// capability-gated, not capability-typed: device-only fields live on
// the same Settings under [Device], and the UI hides those sections
// when Capabilities.DeviceSettings is false. Server-only fields work
// the same way under [Server].
//
// Persistence is consumer-owned. ncpassui writes JSON to
// $XDG_CONFIG_HOME/ncpassui/config.json. passbox-companion translates
// the Device sub-struct into the firmware's flat config.json shape on
// WRITE_CONFIG (the firmware predates this package and expects
// security/oledProtection/clock/volumeLabel at the top level).
//
// Validate runs the union of both consumers' rules so a write is
// rejected before round-tripping over USB or HTTPS. The device
// re-validates on WRITE_CONFIG regardless; the firmware is still the
// authority on what it persists.
package config

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

const (
	maxTimeout       = 86400 // seconds — auto-lock, clipboard clear, OLED timers
	minClipboardSec  = 5     // shorter than this and the user can't paste in time
	maxTzOffsetMin   = 14 * 60
	minTzOffsetMin   = -14 * 60
	maxVolumeLabel   = 11 // FAT 8.3 volume label, sans null
	fatLabelSpecials = " !#$%&'()-@^_`{}~"
)

// Settings is the full configuration surface. App-level sections apply
// to every consumer; Server applies only when Capabilities.Login is
// true; Device applies only when Capabilities.DeviceSettings is true.
type Settings struct {
	Appearance Appearance `json:"appearance"`
	Clipboard  Clipboard  `json:"clipboard"`
	Security   Security   `json:"security"`
	Server     Server     `json:"server,omitzero"`
	Device     Device     `json:"device,omitzero"`
}

type Appearance struct {
	Theme string `json:"theme"` // "" | "system" | "light" | "dark"
}

type Clipboard struct {
	// ClearAfterSeconds = 0 disables auto-clear. Otherwise must be ≥ minClipboardSec.
	ClearAfterSeconds uint32 `json:"clearAfterSeconds"`
}

// Security holds host-side security/UX flags. The device-side
// USB-disconnect lock and PIN-policy timeouts live under [Device.Security].
type Security struct {
	AutoLockSeconds        uint32 `json:"autoLockSeconds"`
	LockOnIdle             bool   `json:"lockOnIdle"`
	BreachCheckEnabled     bool   `json:"breachCheckEnabled"` // HIBP opt-in
	RememberLastFolderPath bool   `json:"rememberLastFolderPath"`
}

// Server holds the remote-vault target for login-capable backends.
// The credential itself is NOT stored here — it lives in the OS
// keyring; only the public URL and the chosen login name persist.
type Server struct {
	URL       string `json:"url"`
	LoginName string `json:"loginName"`
}

// Device mirrors the Passbox firmware's config::Settings sections. The
// device adapter flattens this into the firmware's top-level shape on
// WRITE_CONFIG; other consumers leave it zero.
type Device struct {
	Security       DeviceSecurity `json:"security"`
	OledProtection OledProtection `json:"oledProtection"`
	Clock          Clock          `json:"clock"`
	VolumeLabel    string         `json:"volumeLabel"`
}

type DeviceSecurity struct {
	TimeoutBeforeAutoLock          uint32 `json:"timeoutBeforeAutoLock"`
	TimeoutBeforeUSBDisconnectLock uint32 `json:"timeoutBeforeUSBDisconnectLock"`
}

type OledProtection struct {
	TimeoutBeforeScreenSaver uint32      `json:"timeoutBeforeScreenSaver"`
	TimeoutBeforeSleep       uint32      `json:"timeoutBeforeSleep"`
	ScreenSaver              ScreenSaver `json:"screenSaver"`
}

type ScreenSaver struct {
	Clock      ScreenSaverClock      `json:"clock"`
	Animations ScreenSaverAnimations `json:"animations"`
}

type ScreenSaverClock struct {
	Enabled                  bool   `json:"enabled"`
	TimeoutBetweenAnimations uint32 `json:"timeoutBetweenAnimations"`
}

type ScreenSaverAnimations struct {
	Enabled             bool                 `json:"enabled"`
	TimeoutBetweenClock uint32               `json:"timeoutBetweenClock"`
	Raindrops           ScreenSaverRaindrops `json:"raindrops"`
}

type ScreenSaverRaindrops struct {
	Enabled bool `json:"enabled"`
}

type Clock struct {
	TimezoneOffset int16 `json:"timezoneOffset"` // minutes from UTC
}

// Defaults returns the initial Settings written on first launch.
// Device + Server sub-sections stay zero — consumers that need them
// populate them at backend init time.
func Defaults() Settings {
	return Settings{
		Appearance: Appearance{Theme: "system"},
		Clipboard:  Clipboard{ClearAfterSeconds: 30},
		Security: Security{
			AutoLockSeconds:    600,
			LockOnIdle:         true,
			BreachCheckEnabled: false,
		},
	}
}

// Validate runs the union of both consumers' rules. Returns the empty
// string on success; otherwise the human-readable message the UI
// surfaces in the settings form.
func (s *Settings) Validate() string {
	// App-level timeouts.
	for _, f := range []struct {
		name string
		v    uint32
	}{
		{"security.autoLockSeconds", s.Security.AutoLockSeconds},
		{"clipboard.clearAfterSeconds", s.Clipboard.ClearAfterSeconds},
	} {
		if f.v > maxTimeout {
			return fmt.Sprintf("%s: %d out of range (0-%d seconds)", f.name, f.v, maxTimeout)
		}
	}
	if c := s.Clipboard.ClearAfterSeconds; c != 0 && c < minClipboardSec {
		return fmt.Sprintf("clipboard.clearAfterSeconds: %d is below the %d-second floor (use 0 to disable)",
			c, minClipboardSec)
	}
	switch s.Appearance.Theme {
	case "", "system", "light", "dark":
	default:
		return fmt.Sprintf("appearance.theme: %q is not one of system|light|dark", s.Appearance.Theme)
	}
	if s.Server.URL != "" &&
		!strings.HasPrefix(s.Server.URL, "https://") &&
		!strings.HasPrefix(s.Server.URL, "http://") {
		return fmt.Sprintf("server.url: %q must start with http:// or https://", s.Server.URL)
	}

	// Device timeouts (zero is fine for non-device consumers).
	for _, f := range []struct {
		name string
		v    uint32
	}{
		{"device.security.timeoutBeforeAutoLock", s.Device.Security.TimeoutBeforeAutoLock},
		{"device.security.timeoutBeforeUSBDisconnectLock", s.Device.Security.TimeoutBeforeUSBDisconnectLock},
		{"device.oledProtection.timeoutBeforeScreenSaver", s.Device.OledProtection.TimeoutBeforeScreenSaver},
		{"device.oledProtection.timeoutBeforeSleep", s.Device.OledProtection.TimeoutBeforeSleep},
		{"device.oledProtection.screenSaver.clock.timeoutBetweenAnimations", s.Device.OledProtection.ScreenSaver.Clock.TimeoutBetweenAnimations},
		{"device.oledProtection.screenSaver.animations.timeoutBetweenClock", s.Device.OledProtection.ScreenSaver.Animations.TimeoutBetweenClock},
	} {
		if f.v > maxTimeout {
			return fmt.Sprintf("%s: %d out of range (0-%d seconds)", f.name, f.v, maxTimeout)
		}
	}
	if tz := s.Device.Clock.TimezoneOffset; tz < minTzOffsetMin || tz > maxTzOffsetMin {
		return fmt.Sprintf("device.clock.timezoneOffset: %d out of range (%d..%d minutes)",
			tz, minTzOffsetMin, maxTzOffsetMin)
	}
	if s.Device.VolumeLabel != "" {
		if msg := validateVolumeLabel(s.Device.VolumeLabel); msg != "" {
			return msg
		}
	}
	// Mirrors the firmware's animations.enabled && !raindrops.enabled
	// rejection: an enabled animation block with no animation type to
	// render has nothing to show.
	anim := s.Device.OledProtection.ScreenSaver.Animations
	if anim.Enabled && !anim.Raindrops.Enabled {
		return "device.oledProtection.screenSaver.animations.enabled is true " +
			"but raindrops.enabled is false — enable an animation type or disable animations"
	}
	return ""
}

func validateVolumeLabel(s string) string {
	if len(s) > maxVolumeLabel {
		return fmt.Sprintf("device.volumeLabel: %q is %d chars (max %d)", s, len(s), maxVolumeLabel)
	}
	if s[0] == ' ' || s[len(s)-1] == ' ' {
		return fmt.Sprintf("device.volumeLabel: %q may not start or end with a space", s)
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			continue
		case strings.IndexByte(fatLabelSpecials, c) >= 0:
			continue
		default:
			return fmt.Sprintf("device.volumeLabel: %q contains a non-FAT character %q", s, string(c))
		}
	}
	return ""
}

// Get resolves a dotted key (case-insensitive on JSON field names) to
// its scalar value, formatted for printing. A non-scalar key returns an
// error — callers can dump the whole struct as JSON instead.
func (s *Settings) Get(key string) (string, error) {
	v, err := resolve(reflect.ValueOf(s).Elem(), key)
	if err != nil {
		return "", err
	}
	switch v.Kind() {
	case reflect.Bool:
		return strconv.FormatBool(v.Bool()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10), nil
	case reflect.String:
		return v.String(), nil
	default:
		return "", fmt.Errorf("%s is not a scalar — get the whole config instead", key)
	}
}

// Set parses value to the type of the field at the dotted key, assigns
// it, then runs Validate. Unknown key, type mismatch, or out-of-range
// value all error before any round-trip.
func (s *Settings) Set(key, value string) error {
	v, err := resolve(reflect.ValueOf(s).Elem(), key)
	if err != nil {
		return err
	}
	switch v.Kind() {
	case reflect.Bool:
		b, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("%s: want a bool (true/false), got %q", key, value)
		}
		v.SetBool(b)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil || v.OverflowUint(n) {
			return fmt.Errorf("%s: want a non-negative integer, got %q", key, value)
		}
		v.SetUint(n)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || v.OverflowInt(n) {
			return fmt.Errorf("%s: want an integer, got %q", key, value)
		}
		v.SetInt(n)
	case reflect.String:
		v.SetString(value)
	default:
		return fmt.Errorf("%s is not a scalar — edit the whole config instead", key)
	}
	if msg := s.Validate(); msg != "" {
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func resolve(v reflect.Value, key string) (reflect.Value, error) {
	for part := range strings.SplitSeq(key, ".") {
		if v.Kind() != reflect.Struct {
			return reflect.Value{}, fmt.Errorf("no such config key: %s", key)
		}
		field, ok := fieldByJSONName(v, part)
		if !ok {
			return reflect.Value{}, fmt.Errorf("no such config key: %s", key)
		}
		v = field
	}
	return v, nil
}

func fieldByJSONName(v reflect.Value, name string) (reflect.Value, bool) {
	t := v.Type()
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" {
			continue
		}
		if jsonName := strings.Split(tag, ",")[0]; strings.EqualFold(jsonName, name) {
			return v.Field(i), true
		}
	}
	return reflect.Value{}, false
}
