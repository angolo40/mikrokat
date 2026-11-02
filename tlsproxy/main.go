// Command tlsproxy is the HTTPS inspection proxy of Mikrokat. It reads its
// configuration from a control file written by the app and stays off, with no
// port open, until that file turns it on.
package main

import (
	"log"
	"os"
	"runtime/debug"
	"sync/atomic"
	"time"
)

const (
	controlPath = "/tls/control/config.json"
	stateDir    = "/tls/state"
	privateDir  = "/tls/private"
	incomingDir = "/tls/incoming"
	statsPath   = "/tls/state/stats.json"
	connLogPath = "/tls/state/connections.jsonl"

	emitAddr  = "127.0.0.1:37008"
	emitQueue = 64 << 20
	// Without a limit the heap grows to twice a full queue, past the 100 MB
	// the proxy may use. The queue is what fills, so the limit follows it.
	// At 80 MiB the peak was the same and the collector ran without pause,
	// which cost the relay 30 to 46% of its speed while the queue was full.
	memoryLimit = emitQueue + 32<<20

	controlEvery = 2 * time.Second
	statsEvery   = 10 * time.Second
)

func main() {
	debug.SetMemoryLimit(memoryLimit)
	stats := NewStats()
	emitter, err := NewEmitter(emitAddr, emitQueue, stats)
	if err != nil {
		log.Fatalf("emitter: %v", err)
	}
	go emitter.Run()

	if err := writeBypassDefaults(stateDir, builtinText); err != nil {
		log.Printf("bypass defaults: %v", err)
	}
	bypass := NewBypass(BuiltinBypass)
	bankList := NewBankList()
	bypass.SetBankList(bankList)
	url := bankListURL
	if v := os.Getenv("TLS_BANK_LIST_URL"); v != "" { // for tests
		url = v
	}
	bank := NewBankLoader(bankList, stats, stateDir, url)
	bank.Start()
	server := NewServer(&Engine{
		CA:      new(atomic.Pointer[CA]),
		Bypass:  bypass,
		Emitter: emitter,
		Stats:   stats,
		Log:     NewConnLog(connLogPath, stats),
		Dial:    Dial,
	}, privateDir, stateDir)
	server.IncomingDir = incomingDir

	reader := controlReader{path: controlPath}
	writeStats := func() {
		if err := stats.WriteFile(statsPath, bypass.Auto(time.Now())); err != nil {
			log.Printf("stats: %v", err)
		}
	}

	cfg := reader.read()
	server.Apply(cfg)
	bank.Tick(cfg.Enabled && cfg.BankList)
	writeStats()
	control := time.NewTicker(controlEvery)
	status := time.NewTicker(statsEvery)
	for {
		select {
		case <-control.C:
			// At once, or the alarm could read the old state just after a switch-on.
			cfg := reader.read()
			changed := server.Apply(cfg)
			bank.Tick(cfg.Enabled && cfg.BankList)
			if changed {
				writeStats()
			}
		case <-status.C:
			writeStats()
		}
	}
}
