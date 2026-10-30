package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AutoEntry is a temporary automatic bypass, active until Until (Unix seconds).
type AutoEntry struct {
	Device string `json:"device"`
	Name   string `json:"name"`
	Until  int64  `json:"until"`
}

// Stats holds the proxy counters. It is safe for concurrent use.
type Stats struct {
	mu         sync.Mutex
	started    int64
	inspected  int64
	relayed    map[string]int64
	refused    int64
	handshakes int64
	copied     int64
	dropped    int64
	listening  bool
	problem    string
	caExpires  int64
}

// NewStats returns counters whose start time is now.
func NewStats() *Stats {
	return &Stats{started: time.Now().Unix()}
}

func (s *Stats) Inspected() {
	s.mu.Lock()
	s.inspected++
	s.mu.Unlock()
}

// Relayed counts a connection passed through uninspected, by reason.
func (s *Stats) Relayed(reason string) {
	s.mu.Lock()
	if s.relayed == nil {
		s.relayed = map[string]int64{}
	}
	s.relayed[reason]++
	s.mu.Unlock()
}

func (s *Stats) Refused() {
	s.mu.Lock()
	s.refused++
	s.mu.Unlock()
}

func (s *Stats) HandshakeFailed() {
	s.mu.Lock()
	s.handshakes++
	s.mu.Unlock()
}

// Copied adds n bytes sent to the emitter.
func (s *Stats) Copied(n int) {
	s.mu.Lock()
	s.copied += int64(n)
	s.mu.Unlock()
}

// CopyDropped counts a copy dropped because the emitter queue was full.
func (s *Stats) CopyDropped() {
	s.mu.Lock()
	s.dropped++
	s.mu.Unlock()
}

// SetListening records whether the port is open, and if the configuration wants
// it open but it is not, why.
func (s *Stats) SetListening(listening bool, problem string) {
	s.mu.Lock()
	s.listening, s.problem = listening, problem
	s.mu.Unlock()
}

// SetCAExpires records when the loaded CA expires, in Unix seconds.
func (s *Stats) SetCAExpires(at int64) {
	s.mu.Lock()
	s.caExpires = at
	s.mu.Unlock()
}

type statsFile struct {
	At         int64            `json:"at"`
	Started    int64            `json:"started"`
	Inspected  int64            `json:"inspected"`
	Relayed    map[string]int64 `json:"relayed"`
	Refused    int64            `json:"refused"`
	Handshakes int64            `json:"handshake_failures"`
	Copied     int64            `json:"copied_bytes"`
	Dropped    int64            `json:"copies_dropped"`
	AutoBypass []AutoEntry      `json:"auto_bypass"`
	Listening  bool             `json:"listening"`
	Error      string           `json:"error"`
	CAExpires  int64            `json:"ca_expires"`
}

// WriteFile writes the counters to path through a temporary file and a rename,
// so readers never see a partial file.
func (s *Stats) WriteFile(path string, auto []AutoEntry) error {
	s.mu.Lock()
	f := statsFile{
		At:         time.Now().Unix(),
		Started:    s.started,
		Inspected:  s.inspected,
		Relayed:    make(map[string]int64, len(s.relayed)),
		Refused:    s.refused,
		Handshakes: s.handshakes,
		Copied:     s.copied,
		Dropped:    s.dropped,
		AutoBypass: auto,
		Listening:  s.listening,
		Error:      s.problem,
		CAExpires:  s.caExpires,
	}
	for k, v := range s.relayed {
		f.Relayed[k] = v
	}
	s.mu.Unlock()
	if f.AutoBypass == nil {
		f.AutoBypass = []AutoEntry{}
	}
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".stats-*.tmp")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(raw)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		if werr != nil {
			return werr
		}
		return cerr
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}
