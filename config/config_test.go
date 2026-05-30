package config

import (
	"strings"
	"testing"
)

func TestDefaultsValidate(t *testing.T) {
	d := Defaults()
	if msg := d.Validate(); msg != "" {
		t.Fatalf("defaults should validate, got %q", msg)
	}
}

func TestValidateAppLevel(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Settings)
		wantMsg string
	}{
		{"theme bad", func(s *Settings) { s.Appearance.Theme = "neon" }, "appearance.theme"},
		{"autoLock too big", func(s *Settings) { s.Security.AutoLockSeconds = maxTimeout + 1 }, "security.autoLockSeconds"},
		{"clipboard floor", func(s *Settings) { s.Clipboard.ClearAfterSeconds = 3 }, "clipboard.clearAfterSeconds"},
		{"clipboard zero ok", func(s *Settings) { s.Clipboard.ClearAfterSeconds = 0 }, ""},
		{"server url no scheme", func(s *Settings) { s.Server.URL = "cloud.example.com" }, "server.url"},
		{"server url empty ok", func(s *Settings) { s.Server.URL = "" }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Defaults()
			tc.mutate(&s)
			got := s.Validate()
			if tc.wantMsg == "" && got != "" {
				t.Errorf("expected valid, got %q", got)
			}
			if tc.wantMsg != "" && !strings.Contains(got, tc.wantMsg) {
				t.Errorf("want msg containing %q, got %q", tc.wantMsg, got)
			}
		})
	}
}

func TestValidateDeviceSection(t *testing.T) {
	s := Defaults()
	s.Device.Clock.TimezoneOffset = 15 * 60
	if msg := s.Validate(); !strings.Contains(msg, "timezoneOffset") {
		t.Errorf("expected tz range error, got %q", msg)
	}

	s = Defaults()
	s.Device.VolumeLabel = "  bad"
	if msg := s.Validate(); !strings.Contains(msg, "volumeLabel") {
		t.Errorf("expected volume-label error, got %q", msg)
	}

	s = Defaults()
	s.Device.OledProtection.ScreenSaver.Animations.Enabled = true
	s.Device.OledProtection.ScreenSaver.Animations.Raindrops.Enabled = false
	if msg := s.Validate(); !strings.Contains(msg, "animations.enabled") {
		t.Errorf("expected animations invariant error, got %q", msg)
	}
}

func TestGetSet(t *testing.T) {
	s := Defaults()
	if err := s.Set("security.autoLockSeconds", "300"); err != nil {
		t.Fatal(err)
	}
	if s.Security.AutoLockSeconds != 300 {
		t.Errorf("set didn't take: %d", s.Security.AutoLockSeconds)
	}
	got, err := s.Get("Security.AutoLockSeconds")
	if err != nil || got != "300" {
		t.Errorf("get: %q err %v", got, err)
	}
	if err := s.Set("device.clock.timezoneOffset", "-300"); err != nil {
		t.Fatal(err)
	}
	if s.Device.Clock.TimezoneOffset != -300 {
		t.Errorf("nested set didn't take: %d", s.Device.Clock.TimezoneOffset)
	}
	if err := s.Set("security.autoLockSeconds", "999999"); err == nil {
		t.Error("expected validation error on out-of-range set")
	}
	if _, err := s.Get("nope.nope"); err == nil {
		t.Error("expected error on bad key")
	}
}
