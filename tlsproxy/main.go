// Command tlsproxy is the HTTPS inspection proxy of Mikrokat. It reads its
// configuration from a control file written by the app and stays off, with no
// port open, until that file turns it on.
package main

import (
	"log"
	"sync/atomic"
	"time"
)

const (
	controlPath = "/tls/control/config.json"
	stateDir    = "/tls/state"
	privateDir  = "/tls/private"
	statsPath   = "/tls/state/stats.json"

	emitAddr  = "127.0.0.1:37008"
	emitQueue = 64 << 20

	controlEvery = 2 * time.Second
	statsEvery   = 10 * time.Second
)

func main() {
	stats := NewStats()
	emitter, err := NewEmitter(emitAddr, emitQueue, stats)
	if err != nil {
		log.Fatalf("emitter: %v", err)
	}
	go emitter.Run()

	bypass := NewBypass(BuiltinBypass)
	server := NewServer(&Engine{
		CA:      new(atomic.Pointer[CA]),
		Bypass:  bypass,
		Emitter: emitter,
		Stats:   stats,
		Dial:    Dial,
	}, privateDir, stateDir)

	var cfg Config
	readControl := func() {
		cfg = LoadConfig(controlPath, cfg)
		server.Apply(cfg)
	}
	writeStats := func() {
		if err := stats.WriteFile(statsPath, bypass.Auto(time.Now())); err != nil {
			log.Printf("stats: %v", err)
		}
	}

	readControl()
	writeStats()
	control := time.NewTicker(controlEvery)
	status := time.NewTicker(statsEvery)
	for {
		select {
		case <-control.C:
			readControl()
		case <-status.C:
			writeStats()
		}
	}
}
