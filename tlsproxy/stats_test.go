package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStatsFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "stats.json")
	s := NewStats()
	s.Inspected()
	s.Relayed("bypass")
	s.Relayed("bypass")
	s.Refused()
	s.HandshakeFailed()
	s.Copied(10)
	s.Copied(5)
	s.CopyDropped()
	if err := s.WriteFile(p, []AutoEntry{{Device: "192.0.2.5", Name: "x", Until: 99}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"at", "started", "inspected", "relayed", "refused",
		"handshake_failures", "copied_bytes", "copies_dropped", "auto_bypass"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	var relayed map[string]int64
	if err := json.Unmarshal(m["relayed"], &relayed); err != nil || relayed["bypass"] != 2 {
		t.Fatalf("relayed = %v, %v", relayed, err)
	}
	var copied int64
	json.Unmarshal(m["copied_bytes"], &copied)
	if copied != 15 {
		t.Fatalf("copied_bytes = %d", copied)
	}
	var auto []AutoEntry
	if err := json.Unmarshal(m["auto_bypass"], &auto); err != nil || len(auto) != 1 || auto[0].Until != 99 {
		t.Fatalf("auto_bypass = %v, %v", auto, err)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.Name() != "stats.json" {
			t.Errorf("leftover file %s", e.Name())
		}
	}
}

func TestStatsEmptyAutoIsList(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	if err := NewStats().WriteFile(p, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	var m map[string]json.RawMessage
	json.Unmarshal(raw, &m)
	if string(m["auto_bypass"]) != "[]" || string(m["relayed"]) != "{}" {
		t.Fatalf("got %s / %s", m["auto_bypass"], m["relayed"])
	}
}
