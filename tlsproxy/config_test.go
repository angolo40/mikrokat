package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestMissingConfigIsOff(t *testing.T) {
	c := LoadConfig(filepath.Join(t.TempDir(), "none.json"), Config{Enabled: true})
	if c.Enabled {
		t.Fatal("a missing file must turn the feature off")
	}
}

func TestBadConfigKeepsLast(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, []byte(`{"enab`), 0o644); err != nil {
		t.Fatal(err)
	}
	c := LoadConfig(p, Config{Enabled: true})
	if !c.Enabled {
		t.Fatal("a broken file must keep the last good config")
	}
}

func TestLoadConfigParses(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	body := `{"enabled":true,"socks":true,"socks_port":1080,"devices":["192.0.2.5"],"bypass":["bank.example"],"ca_generation":3,"auto_remove":[{"device":"192.0.2.5","name":"x","at":7}]}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c := LoadConfig(p, Config{})
	if !c.Enabled || !c.Socks || c.SocksPort != 1080 || c.CAGeneration != 3 ||
		len(c.Devices) != 1 || len(c.Bypass) != 1 || len(c.AutoRemove) != 1 || c.AutoRemove[0].At != 7 {
		t.Fatalf("unexpected config: %+v", c)
	}
}

func TestAllowed(t *testing.T) {
	c := Config{Devices: []string{"192.0.2.5", "not-an-ip"}}
	if !c.Allowed(net.ParseIP("192.0.2.5")) {
		t.Fatal("listed device must be allowed")
	}
	if c.Allowed(net.ParseIP("192.0.2.6")) {
		t.Fatal("unlisted device must not be allowed")
	}
	if c.Allowed(nil) {
		t.Fatal("nil IP must not be allowed")
	}
}
