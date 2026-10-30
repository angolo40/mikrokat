package main

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

var t0 = time.Unix(1_800_000_000, 0)

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
	b.AddAuto("d", "pin.example", t0)
	if got := b.Match("d", "pin.example", t0); got != "auto_bypass" {
		t.Errorf("at now: got %q", got)
	}
	if got := b.Match("d", "pin.example", t0.Add(24*time.Hour+time.Second)); got != "" {
		t.Errorf("after 24h: got %q", got)
	}
}

func TestAutoIsPerDevice(t *testing.T) {
	b := NewBypass(nil)
	b.AddAuto("d1", "pin.example", t0)
	if got := b.Match("d2", "pin.example", t0); got != "" {
		t.Errorf("other device: got %q", got)
	}
}

func TestBypassWinsOverAuto(t *testing.T) {
	b := NewBypass([]string{"pin.example"})
	b.AddAuto("d", "pin.example", t0)
	if got := b.Match("d", "pin.example", t0); got != "bypass" {
		t.Errorf("got %q", got)
	}
}

func TestApplyRemoves(t *testing.T) {
	b := NewBypass(nil)
	b.AddAuto("d", "pin.example", t0)
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
	b.AddAuto("d", "pin.example", t0.Add(time.Minute))
	b.Apply(rm)
	if got := b.Match("d", "pin.example", t0.Add(time.Minute)); got != "auto_bypass" {
		t.Errorf("later entry: got %q", got)
	}
}

func TestAutoRenewAndList(t *testing.T) {
	b := NewBypass(nil)
	b.AddAuto("d", "a.example", t0)
	b.AddAuto("d", "a.example", t0.Add(time.Hour))
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
		b.AddAuto("d", fmt.Sprintf("h%d.example", i), t0.Add(time.Duration(i)*time.Second))
	}
	b.AddAuto("d", "new.example", t0.Add(time.Hour))
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

func TestParseList(t *testing.T) {
	got := parseList("# comment\n\n  Example.COM  \nfoo.org\n   # indented\r\n")
	want := []string{"example.com", "foo.org"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
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
