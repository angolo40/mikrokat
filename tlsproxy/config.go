package main

import (
	"encoding/json"
	"log"
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
	Enabled      bool     `json:"enabled"`
	Socks        bool     `json:"socks"`
	SocksPort    int      `json:"socks_port"`
	Devices      []string `json:"devices"`
	Bypass       []string `json:"bypass"`
	CAGeneration int      `json:"ca_generation"`
	// The app raises a counter to ask for something. A request makes a key and a
	// signing request for the owner's own root, a cancel drops them.
	CARequest       int           `json:"ca_request"`
	CARequestName   string        `json:"ca_request_name"`
	CARequestCancel int           `json:"ca_request_cancel"`
	AutoRemove      []AutoRemoval `json:"auto_remove"`
}

// LoadConfig reads the control file. A missing file means the feature is off.
// A file that cannot be read or parsed keeps the last good configuration, which
// is returned with the error.
func LoadConfig(path string, last Config) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, nil
		}
		return last, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return last, err
	}
	return c, nil
}

// controlReader polls the control file. It logs a failure once, and a failure
// after a good read counts as a new one.
type controlReader struct {
	path   string
	cfg    Config
	failed bool // the current failure is already logged
}

func (r *controlReader) read() Config {
	var err error
	r.cfg, err = LoadConfig(r.path, r.cfg)
	if err != nil && !r.failed {
		log.Printf("control file: %v, keeping the last configuration", err)
	}
	r.failed = err != nil
	return r.cfg
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
