package main

import (
	"encoding/json"
	"net"
	"os"
)

// AutoRemoval records a device name that was dropped automatically.
type AutoRemoval struct {
	Device string `json:"device"`
	Name   string `json:"name"`
	At     int64  `json:"at"`
}

// Config is the control file written by the app and read by the proxy.
type Config struct {
	Enabled      bool          `json:"enabled"`
	Socks        bool          `json:"socks"`
	SocksPort    int           `json:"socks_port"`
	Devices      []string      `json:"devices"`
	Bypass       []string      `json:"bypass"`
	CAGeneration int           `json:"ca_generation"`
	AutoRemove   []AutoRemoval `json:"auto_remove"`
}

// LoadConfig reads the control file. A missing file means the feature is off;
// a file that cannot be read or parsed keeps the last good configuration.
func LoadConfig(path string, last Config) Config {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}
		}
		return last
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return last
	}
	return c
}

// Allowed reports whether traffic from ip may be inspected. Entries that are
// not valid IP addresses never match.
func (c Config) Allowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, d := range c.Devices {
		if dip := net.ParseIP(d); dip != nil && dip.Equal(ip) {
			return true
		}
	}
	return false
}
