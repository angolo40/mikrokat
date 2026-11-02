package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var t0 = time.Unix(1_800_000_000, 0)

// earnAuto adds an automatic entry the way a pinned app does.
func earnAuto(b *Bypass, device, name string, now time.Time) {
	b.Failed(device, name, now)
	b.Failed(device, name, now)
}

func TestSuffixMatch(t *testing.T) {
	b := NewBypass(nil)
	b.SetOwn([]string{"bank.example"})
	for _, n := range []string{"bank.example", "www.bank.example"} {
		if got := b.Match("d", n, t0); got != "bypass" {
			t.Errorf("%s: got %q", n, got)
		}
	}
	if got := b.Match("d", "notbank.example", t0); got != "" {
		t.Errorf("notbank.example: got %q", got)
	}
}

func TestCaseInsensitive(t *testing.T) {
	b := NewBypass([]string{"Bank.Example"})
	if got := b.Match("d", "WWW.BANK.example", t0); got != "bypass" {
		t.Errorf("got %q", got)
	}
}

func TestOwnNormalised(t *testing.T) {
	b := NewBypass(nil)
	b.SetOwn([]string{"a.example.", "*.b.example", "", " ", "."})
	for _, n := range []string{"a.example", "x.b.example", "b.example"} {
		if got := b.Match("d", n, t0); got != "bypass" {
			t.Errorf("%s: got %q", n, got)
		}
	}
	if got := b.Match("d", "example", t0); got != "" {
		t.Errorf("empty entry matched: %q", got)
	}
}

func TestAutoExpires(t *testing.T) {
	b := NewBypass(nil)
	earnAuto(b, "d", "pin.example", t0)
	if got := b.Match("d", "pin.example", t0); got != "auto_bypass" {
		t.Errorf("at now: got %q", got)
	}
	if got := b.Match("d", "pin.example", t0.Add(24*time.Hour+time.Second)); got != "" {
		t.Errorf("after 24h: got %q", got)
	}
}

func TestAutoIsPerDevice(t *testing.T) {
	b := NewBypass(nil)
	earnAuto(b, "d1", "pin.example", t0)
	if got := b.Match("d2", "pin.example", t0); got != "" {
		t.Errorf("other device: got %q", got)
	}
}

func TestBypassWinsOverAuto(t *testing.T) {
	b := NewBypass([]string{"pin.example"})
	earnAuto(b, "d", "pin.example", t0)
	if got := b.Match("d", "pin.example", t0); got != "bypass" {
		t.Errorf("got %q", got)
	}
}

func TestApplyRemoves(t *testing.T) {
	b := NewBypass(nil)
	earnAuto(b, "d", "pin.example", t0)
	rm := []AutoRemoval{{Device: "d", Name: "pin.example", At: t0.Unix() - 10}}
	b.Apply(rm)
	if got := b.Match("d", "pin.example", t0); got != "auto_bypass" {
		t.Errorf("removal before the entry: got %q", got)
	}
	rm = []AutoRemoval{{Device: "d", Name: "pin.example", At: t0.Unix() + 10}}
	b.Apply(rm)
	b.Apply(rm) // idempotent
	if got := b.Match("d", "pin.example", t0); got != "" {
		t.Errorf("removal after the entry: got %q", got)
	}
	// A later entry is not touched by the same removal.
	earnAuto(b, "d", "pin.example", t0.Add(time.Minute))
	b.Apply(rm)
	if got := b.Match("d", "pin.example", t0.Add(time.Minute)); got != "auto_bypass" {
		t.Errorf("later entry: got %q", got)
	}
}

func TestAutoRenewAndList(t *testing.T) {
	b := NewBypass(nil)
	earnAuto(b, "d", "a.example", t0)
	earnAuto(b, "d", "a.example", t0.Add(time.Hour))
	got := b.Auto(t0.Add(time.Hour))
	want := []AutoEntry{{Device: "d", Name: "a.example", Until: t0.Add(25 * time.Hour).Unix()}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
	if got := b.Auto(t0.Add(26 * time.Hour)); len(got) != 0 {
		t.Errorf("expired entries listed: %v", got)
	}
}

func TestAutoCapEvictsEarliest(t *testing.T) {
	b := NewBypass(nil)
	for i := 0; i < maxAuto; i++ {
		earnAuto(b, "d", fmt.Sprintf("h%d.example", i), t0.Add(time.Duration(i)*time.Second))
	}
	earnAuto(b, "d", "new.example", t0.Add(time.Hour))
	if n := len(b.Auto(t0.Add(time.Hour))); n != maxAuto {
		t.Fatalf("len %d", n)
	}
	if got := b.Match("d", "h0.example", t0.Add(time.Hour)); got != "" {
		t.Errorf("earliest not evicted: %q", got)
	}
	if got := b.Match("d", "new.example", t0.Add(time.Hour)); got != "auto_bypass" {
		t.Errorf("new entry missing: %q", got)
	}
}

func TestAutoIsExactName(t *testing.T) {
	b := NewBypass(nil)
	earnAuto(b, "d", "pin.example", t0)
	for _, n := range []string{"www.pin.example", "a.b.pin.example"} {
		if got := b.Match("d", n, t0); got != "" {
			t.Errorf("%s: got %q", n, got)
		}
	}
	if got := b.Match("d", "PIN.example.", t0); got != "auto_bypass" {
		t.Errorf("same name in another form: got %q", got)
	}
	earnAuto(b, "d", "com", t0)
	if got := b.Match("d", "other.com", t0); got != "" {
		t.Errorf("other.com: got %q", got)
	}
}

func TestAutoNeedsTwoFailures(t *testing.T) {
	b := NewBypass(nil)
	b.Failed("d", "pin.example", t0)
	if got := b.Match("d", "pin.example", t0); got != "" {
		t.Fatalf("after one failure: got %q", got)
	}
	second := t0.Add(failWindow - time.Second)
	b.Failed("d", "pin.example", second)
	if got := b.Match("d", "pin.example", second); got != "auto_bypass" {
		t.Fatalf("after two failures: got %q", got)
	}
	want := []AutoEntry{{Device: "d", Name: "pin.example", Until: second.Add(autoTTL).Unix()}}
	if got := b.Auto(second); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestFailuresTooFarApart(t *testing.T) {
	b := NewBypass(nil)
	b.Failed("d", "pin.example", t0)
	late := t0.Add(failWindow + time.Second)
	b.Failed("d", "pin.example", late)
	if got := b.Match("d", "pin.example", late); got != "" {
		t.Fatalf("got %q", got)
	}
	// The late failure counts as a new first one.
	b.Failed("d", "pin.example", late.Add(time.Minute))
	if got := b.Match("d", "pin.example", late.Add(time.Minute)); got != "auto_bypass" {
		t.Fatalf("got %q", got)
	}
}

func TestFailuresCountPerDeviceAndName(t *testing.T) {
	b := NewBypass(nil)
	b.Failed("d1", "a.example", t0)
	b.Failed("d2", "a.example", t0)
	b.Failed("d1", "b.example", t0)
	if got := b.Auto(t0); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestCompletedHandshakeBlocksAuto(t *testing.T) {
	b := NewBypass(nil)
	b.Completed("d", "site.example", t0)
	at := t0.Add(goodTTL - 10*time.Second)
	b.Failed("d", "site.example", at)
	b.Failed("d", "site.example", at.Add(time.Second))
	if got := b.Match("d", "site.example", at); got != "" {
		t.Fatalf("within a day: got %q", got)
	}
	// Only for this device and this name.
	b.Failed("d2", "site.example", at)
	b.Failed("d2", "site.example", at)
	b.Failed("d", "www.site.example", at)
	b.Failed("d", "www.site.example", at)
	if n := len(b.Auto(at)); n != 2 {
		t.Fatalf("%d entries", n)
	}
	// It is forgotten after a day.
	at = t0.Add(goodTTL + time.Second)
	b.Failed("d", "site.example", at)
	b.Failed("d", "site.example", at)
	if got := b.Match("d", "site.example", at); got != "auto_bypass" {
		t.Fatalf("after a day: got %q", got)
	}
}

func TestCompletedForgetsFailure(t *testing.T) {
	b := NewBypass(nil)
	b.Failed("d", "site.example", t0)
	b.Completed("d", "site.example", t0)
	if n := len(b.fails); n != 0 {
		t.Fatalf("%d failures kept", n)
	}
}

func TestMemoryIsCapped(t *testing.T) {
	b := NewBypass(nil)
	b.Completed("d", "oldest.example", t0)
	b.Failed("d", "oldest-failure.example", t0)
	later := t0.Add(time.Second)
	for i := range maxMemory {
		name := fmt.Sprintf("h%d.example", i)
		b.Completed("d", name, later)
		b.Failed("d", "fail-"+name, later)
	}
	if n, m := len(b.good), len(b.fails); n != maxMemory || m != maxMemory {
		t.Fatalf("good %d, fails %d", n, m)
	}
	if _, ok := b.good[autoKey{"d", "oldest.example"}]; ok {
		t.Error("the oldest good handshake was kept")
	}
	if _, ok := b.fails[autoKey{"d", "oldest-failure.example"}]; ok {
		t.Error("the oldest failure was kept")
	}
	if _, ok := b.good[autoKey{"d", fmt.Sprintf("h%d.example", maxMemory-1)}]; !ok {
		t.Error("the newest good handshake is missing")
	}
}

func TestParseList(t *testing.T) {
	got := parseList("# comment\n\n  Example.COM  \nfoo.org\n   # indented\r\n")
	want := []string{"example.com", "foo.org"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

func TestBuiltinSkipsGoogle(t *testing.T) {
	b := NewBypass(BuiltinBypass)
	for _, name := range []string{"www.google.com", "www.google.it", "www.google.ch", "fonts.gstatic.com", "www.youtube.com", "www.recaptcha.net", "maps.googleapis.com"} {
		if got := b.Match("d", name, t0); got != "bypass" {
			t.Errorf("%s: got %q", name, got)
		}
	}
	if got := b.Match("d", "notgoogle.com", t0); got == "bypass" {
		t.Error("a name that only ends in google.com matched")
	}
}

func TestCustomListReplacesTheDefaults(t *testing.T) {
	b := NewBypass(BuiltinBypass)
	b.SetOwn([]string{"example.org"})
	if got := b.Match("d", "www.google.com", t0); got != "bypass" {
		t.Fatalf("a default does not match before: %q", got)
	}
	b.SetCustom(true)
	for name, want := range map[string]string{
		"www.google.com": "", "www.paypal.com": "", // removed from the list, so decrypted
		"www.example.org": "bypass", "cloudflare-ech.com": "bypass", // the owner's, and the one that stays
	} {
		if got := b.Match("d", name, t0); got != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}
	b.SetCustom(false)
	if got := b.Match("d", "www.google.com", t0); got != "bypass" {
		t.Errorf("back to the defaults: %q", got)
	}
}

func TestDefaultsFile(t *testing.T) {
	dir := t.TempDir()
	if err := writeBypassDefaults(dir, "# note\ncloudflare-ech.com\nGoogle.com\n\nbank.example\n"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "bypass-defaults.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "google.com\nbank.example\n" {
		t.Fatalf("file %q", raw)
	}
	if err := writeBypassDefaults(dir, builtinText); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, "bypass-defaults.txt"))
	if strings.Contains(string(raw), "#") || strings.Contains(string(raw), "cloudflare-ech.com") || !strings.Contains(string(raw), "paypal.com\n") {
		t.Fatalf("file %q", raw)
	}
}

func TestServerAppliesTheCustomFlag(t *testing.T) {
	r := newOwnRig(t)
	r.cfg.Bypass = []string{"example.org"}
	r.Apply(r.cfg)
	e := r.Engine
	e.Bypass.mu.Lock()
	e.Bypass.builtin = []string{"paypal.com"}
	e.Bypass.mu.Unlock()
	if got := e.Bypass.Match("d", "paypal.com", t0); got != "bypass" {
		t.Fatalf("got %q", got)
	}
	r.cfg.BypassCustom = true
	r.Apply(r.cfg)
	if got := e.Bypass.Match("d", "paypal.com", t0); got != "" {
		t.Fatalf("a removed default still matches: %q", got)
	}
}

func TestBuiltinHasECHName(t *testing.T) {
	b := NewBypass(BuiltinBypass)
	if got := b.Match("d", "cloudflare-ech.com", t0); got != "bypass" {
		t.Errorf("got %q", got)
	}
	if len(BuiltinBypass) > 60 {
		t.Errorf("builtin list too long: %d", len(BuiltinBypass))
	}
}
