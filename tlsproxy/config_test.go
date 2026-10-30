package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMissingConfigIsOff(t *testing.T) {
	c, err := LoadConfig(filepath.Join(t.TempDir(), "none.json"), Config{Enabled: true})
	if err != nil {
		t.Fatalf("a missing file is not an error: %v", err)
	}
	if c.Enabled {
		t.Fatal("a missing file must turn the feature off")
	}
}

func TestBadConfigKeepsLast(t *testing.T) {
	for name, body := range map[string]string{
		"half written": `{"enab`,
		"wrong type":   `{"enabled":false,"socks_port":"1080"}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "c.json")
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			c, err := LoadConfig(p, Config{Enabled: true})
			if !c.Enabled {
				t.Fatal("a broken file must keep the last good config")
			}
			if err == nil {
				t.Fatal("a broken file must return its error")
			}
		})
	}
	t.Run("unreadable", func(t *testing.T) {
		c, err := LoadConfig(t.TempDir(), Config{Enabled: true}) // a folder cannot be read
		if !c.Enabled {
			t.Fatal("an unreadable file must keep the last good config")
		}
		if err == nil {
			t.Fatal("an unreadable file must return its error")
		}
	})
}

func TestControlFailureLoggedOnce(t *testing.T) {
	logs := captureLog(t)
	p := filepath.Join(t.TempDir(), "c.json")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	lines := func() int { return strings.Count(logs.String(), "control file") }
	r := controlReader{path: p}

	write(`{"enabled":true}`)
	if !r.read().Enabled {
		t.Fatal("good file not read")
	}
	write(`{"enabled":false,"socks_port":"1080"}`)
	for range 3 {
		if !r.read().Enabled {
			t.Fatal("last good config not kept")
		}
	}
	if n := lines(); n != 1 {
		t.Fatalf("%d lines for one failure: %q", n, logs)
	}
	write(`{"enabled":false}`)
	if r.read().Enabled {
		t.Fatal("good file not read after a failure")
	}
	if n := lines(); n != 1 {
		t.Fatalf("%d lines after a good read: %q", n, logs)
	}
	// A failure after a good read is a new one, and keeps the newer config.
	write(`{"enab`)
	for range 2 {
		if r.read().Enabled {
			t.Fatal("older config restored")
		}
	}
	if n := lines(); n != 2 {
		t.Fatalf("%d lines for two failures: %q", n, logs)
	}
}

func TestLoadConfigParses(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	body := `{"enabled":true,"socks":true,"socks_port":1080,"devices":["192.0.2.5"],"bypass":["bank.example"],"ca_generation":3,"auto_remove":[{"device":"192.0.2.5","name":"x","at":7}]}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p, Config{})
	if err != nil {
		t.Fatal(err)
	}
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
