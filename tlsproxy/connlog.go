package main

import (
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxLogSize = 5 << 20 // the file is rotated at this size, so two files hold about 10 MiB
	logQueue   = 4096

	maxRefusedPerSecond = 50 // refused lines in all, for each second, whatever the number of sources
)

// ConnRecord is one line of the connection log. It holds what the proxy did
// with a connection and never any content: no URL, path, header or payload.
type ConnRecord struct {
	At     int64  `json:"at"`     // when the connection ended, Unix seconds
	Device string `json:"device"` // the source address
	Name   string `json:"name"`   // the SNI, else the SOCKS host name, else empty
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Action string `json:"action"` // inspected, relayed or refused
	Reason string `json:"reason"` // the relay reason, or why it was refused
	Up     int64  `json:"up"`     // bytes from the device
	Down   int64  `json:"down"`   // bytes to the device
	Ms     int64  `json:"ms"`     // how long it lasted
}

// ConnLog writes ConnRecords to a file through a bounded queue and one writer
// goroutine, so logging never slows or blocks a connection. When the queue is
// full a record is dropped and counted. It is safe for concurrent use, and a
// nil *ConnLog logs nothing.
type ConnLog struct {
	path    string
	stats   *Stats
	maxSize int64
	now     func() time.Time // for the refusal limit

	ch      chan ConnRecord
	enabled atomic.Bool

	mu   sync.Mutex
	stop chan struct{} // closed to stop the running writer
	done chan struct{} // closed when the last writer has ended

	refMu   sync.Mutex
	refused map[string]bool // sources logged in the second refSec
	refSec  int64
}

func NewConnLog(path string, stats *Stats) *ConnLog {
	return &ConnLog{
		path:    path,
		stats:   stats,
		maxSize: maxLogSize,
		now:     time.Now,
		ch:      make(chan ConnRecord, logQueue),
		refused: make(map[string]bool),
	}
}

// SetEnabled starts or stops the writer. While off, Add drops records without
// counting them and nothing is written. A stopping writer first writes what
// is already queued. It does not wait: use Wait for that.
func (l *ConnLog) SetEnabled(on bool) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if on == l.enabled.Load() {
		return
	}
	l.enabled.Store(on)
	if !on {
		close(l.stop)
		return
	}
	prev := l.done
	l.stop, l.done = make(chan struct{}), make(chan struct{})
	go l.run(l.stop, l.done, prev)
}

// Wait returns once the writer has stopped, or at once if it never ran.
func (l *ConnLog) Wait() {
	l.mu.Lock()
	done := l.done
	l.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Add queues r for writing, filling in the end time.
func (l *ConnLog) Add(r ConnRecord) {
	if l == nil || !l.enabled.Load() {
		return
	}
	if r.At == 0 {
		r.At = l.now().Unix()
	}
	select {
	case l.ch <- r:
	default:
		l.stats.LogDropped()
	}
}

// AddRefused is Add for a refused connection, at most once per second for each
// source and 50 per second in all, so a port scan, even from many addresses,
// cannot fill the file. The rest are counted.
func (l *ConnLog) AddRefused(r ConnRecord) {
	if l == nil || !l.enabled.Load() {
		return
	}
	sec := l.now().Unix()
	l.refMu.Lock()
	if sec != l.refSec { // every entry is from an earlier second now
		clear(l.refused)
		l.refSec = sec
	}
	_, seen := l.refused[r.Device]
	skip := seen || len(l.refused) >= maxRefusedPerSecond
	if !skip {
		l.refused[r.Device] = true
	}
	l.refMu.Unlock()
	if skip {
		l.stats.LogSkipped()
		return
	}
	r.At = sec
	l.Add(r)
}

// Clear deletes the log and its backup, and goes on logging if it was on. The
// writer is stopped while the files go, so it cannot write into a deleted one.
func (l *ConnLog) Clear() {
	if l == nil {
		return
	}
	l.mu.Lock()
	on := l.enabled.Load()
	if on {
		l.enabled.Store(false)
		close(l.stop)
	}
	done := l.done
	l.mu.Unlock()
	if done != nil {
		<-done
	}
	os.Remove(l.path)
	os.Remove(l.path + ".1")
	if on {
		l.SetEnabled(true)
	}
}

// run writes records until stop, then what is queued, then ends. A writer
// started right after another one waits for it, so two never share the file.
func (l *ConnLog) run(stop, done, prev chan struct{}) {
	defer close(done)
	if prev != nil {
		<-prev
	}
	w := &logWriter{path: l.path, max: l.maxSize, stats: l.stats}
	defer w.close()
	for {
		select {
		case r := <-l.ch:
			w.write(r)
		case <-stop:
			for {
				select {
				case r := <-l.ch:
					w.write(r)
				default:
					return
				}
			}
		}
	}
}

// logWriter appends lines to the file and rotates it. It belongs to one
// goroutine.
type logWriter struct {
	path  string
	max   int64
	stats *Stats
	f     *os.File
	size  int64
}

func (w *logWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	f.Chmod(0o644) // the umask may have narrowed it
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.size = f, fi.Size()
	return nil
}

func (w *logWriter) close() {
	if w.f != nil {
		w.f.Close()
		w.f = nil
	}
}

// write appends one record. A failure drops it and counts it, and the next
// record tries again.
func (w *logWriter) write(r ConnRecord) {
	line, err := json.Marshal(r)
	if err != nil {
		w.stats.LogDropped()
		return
	}
	line = append(line, '\n')
	if w.f == nil {
		if err := w.open(); err != nil {
			w.stats.LogDropped()
			return
		}
	}
	if w.size > 0 && w.size+int64(len(line)) > w.max {
		w.close()
		os.Rename(w.path, w.path+".1") // replaces the older backup
		if err := w.open(); err != nil {
			w.stats.LogDropped()
			return
		}
	}
	n, err := w.f.Write(line)
	w.size += int64(n)
	if err != nil {
		w.stats.LogDropped()
		w.close()
	}
}
