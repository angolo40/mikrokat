package main

import (
	"encoding/json"
	"net"
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
	s.SetListening(false, "port taken")
	s.SetCA(true, "CN=Own", 2, 1234)
	s.SetImportError("the key is damaged")
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
		"handshake_failures", "copied_bytes", "copies_dropped", "auto_bypass",
		"listening", "error", "ca_expires"} {
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
	if got := string(m["listening"]) + " " + string(m["error"]) + " " + string(m["ca_expires"]); got != `false "port taken" 1234` {
		t.Fatalf("listening, error, ca_expires = %s", got)
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

func TestLastRefusedNamesTheSource(t *testing.T) {
	st := NewStats()
	st.RefusedFrom(net.ParseIP("::ffff:192.0.2.9"))
	st.Refused() // over a cap: no source
	path := filepath.Join(t.TempDir(), "stats.json")
	if err := st.WriteFile(path, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["refused"] != float64(2) || m["last_refused"] != "192.0.2.9" || m["last_refused_at"].(float64) < 1e9 {
		t.Fatalf("stats %v", m)
	}
}

func TestStrangerSetsLastRefusedButACapDoesNot(t *testing.T) {
	e := &Engine{Stats: NewStats()}
	s := NewServer(e, t.TempDir(), t.TempDir())
	ln := &net.TCPListener{}
	s.ln = ln
	s.cfg = Config{Devices: []string{"10.1.1.1"}}
	if _, _, ok := s.admit(ln, net.ParseIP("10.1.1.2")); ok {
		t.Fatal("a stranger was admitted")
	}
	s.total = maxConns
	s.admit(ln, net.ParseIP("10.1.1.1"))
	if e.Stats.lastRefused != "10.1.1.2" || e.Stats.refused != 2 {
		t.Fatalf("last %q refused %d", e.Stats.lastRefused, e.Stats.refused)
	}
}
