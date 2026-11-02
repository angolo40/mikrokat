package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// logRig is a ConnLog that writes into a temporary folder.
type logRig struct {
	*ConnLog
	path string
}

func newLogRig(t *testing.T, stats *Stats) *logRig {
	t.Helper()
	return newSmallLogRig(t, stats, maxLogSize)
}

// newSmallLogRig rotates the file at size bytes.
func newSmallLogRig(t *testing.T, stats *Stats, size int64) *logRig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "connections.jsonl")
	l := NewConnLog(path, stats)
	l.maxSize = size
	l.SetEnabled(true)
	t.Cleanup(func() { l.SetEnabled(false); l.Wait() })
	return &logRig{ConnLog: l, path: path}
}

// lines stops the writer, so everything queued is on disk, and returns the
// lines of the file.
func (l *logRig) lines(t *testing.T) []map[string]any {
	t.Helper()
	l.SetEnabled(false)
	l.Wait()
	return readLines(t, l.path)
}

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// onlyLine returns the one line the file must hold, and checks its keys.
func onlyLine(t *testing.T, lines []map[string]any) map[string]any {
	t.Helper()
	if len(lines) != 1 {
		t.Fatalf("%d lines, want 1: %v", len(lines), lines)
	}
	checkKeys(t, lines[0])
	return lines[0]
}

func checkKeys(t *testing.T, m map[string]any) {
	t.Helper()
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := "action at device down ip ms name port reason up"
	if got := strings.Join(keys, " "); got != want {
		t.Fatalf("keys %q, want %q", got, want)
	}
}

func num(m map[string]any, k string) int64 { return int64(m[k].(float64)) }

func (r *rig) withLog(t *testing.T) *logRig {
	t.Helper()
	l := newLogRig(t, r.Stats)
	r.Log = l.ConnLog
	return l
}

func TestConnLogInspected(t *testing.T) {
	srv := tlsServer(t)
	r := newRig(t, srv.Listener.Addr().String())
	r.Roots = poolOf(srv.Certificate())
	l := r.withLog(t)
	raw, done := r.connect(t.Context(), t, testDest)

	c := tls.Client(raw, r.clientConfig())
	req := "GET /private/path?token=abc123 HTTP/1.1\r\nHost: " + testName +
		"\r\nCookie: session=SECRETCOOKIE\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reply), "reply to /private/path") {
		t.Fatalf("reply %q", reply)
	}
	raw.Close()
	waitFor(t, done)
	before := time.Now().Unix()

	line := onlyLine(t, l.lines(t))
	if line["action"] != "inspected" || line["reason"] != "" {
		t.Fatalf("action %v reason %v", line["action"], line["reason"])
	}
	if line["name"] != testName || line["device"] != testDevice.String() ||
		line["ip"] != testDest.IP.String() || num(line, "port") != 443 {
		t.Fatalf("line %v", line)
	}
	if num(line, "up") != int64(len(req)) || num(line, "down") != int64(len(reply)) {
		t.Fatalf("up %v down %v, want %d and %d", line["up"], line["down"], len(req), len(reply))
	}
	if at := num(line, "at"); at < before-5 || at > before+1 {
		t.Fatalf("at %d, now %d", at, before)
	}

	// The file holds what was listed and nothing from the request or the reply.
	file, _ := os.ReadFile(l.path)
	for _, bad := range []string{"private", "abc123", "SECRETCOOKIE", "Cookie", "GET", "HTTP/1.1", "reply to"} {
		if bytes.Contains(file, []byte(bad)) {
			t.Errorf("the log contains %q: %s", bad, file)
		}
	}
}

func TestConnLogRelayBytes(t *testing.T) {
	banner := "220 ready\r\n"
	r := newRig(t, echoServer(t, banner))
	l := r.withLog(t)
	raw, done := r.connect(t.Context(), t, Dest{IP: testDest.IP, Port: 25, Name: "mail.example"})

	payload := strings.Repeat("x", 100000)
	go io.WriteString(raw, payload)
	if got := readN(t, raw, len(banner)+len(payload)); got != banner+payload {
		t.Fatal("echo differs")
	}
	raw.Close()
	waitFor(t, done)

	line := onlyLine(t, l.lines(t))
	if line["action"] != "relayed" || line["reason"] != "not_443" || line["name"] != "mail.example" ||
		num(line, "port") != 25 || line["ip"] != testDest.IP.String() {
		t.Fatalf("line %v", line)
	}
	if num(line, "up") != int64(len(payload)) || num(line, "down") != int64(len(banner)+len(payload)) {
		t.Fatalf("up %v down %v", line["up"], line["down"])
	}
}

func TestConnLogRelayReasons(t *testing.T) {
	srv := tlsServer(t)
	cases := []struct {
		reason string
		d      Dest
		name   string // the SNI sent, "" for none
		want   string // the name logged
		setup  func(r *rig)
	}{
		{"bypass", testDest, testName, testName, func(r *rig) { r.Bypass.SetOwn([]string{testName}) }},
		{"auto_bypass", testDest, testName, testName, func(r *rig) {
			r.Bypass.Failed(testDevice.String(), testName, time.Now())
			r.Bypass.Failed(testDevice.String(), testName, time.Now())
		}},
		{"no_name", testDest, "", "", nil},
		{"no_name", Dest{IP: testDest.IP, Port: 443, Name: "socks.example"}, "", "socks.example", nil},
		{"ipv6", Dest{IP: net.ParseIP("2001:db8::1"), Port: 443}, testName, testName, nil},
		{"private", Dest{IP: net.IPv4(192, 168, 1, 1), Port: 443}, testName, testName, nil},
		{"ca_expired", testDest, testName, testName, func(r *rig) { r.CA.Load().cert.NotAfter = time.Now().Add(-time.Minute) }},
		{"upstream", testDest, testName, testName, func(r *rig) { r.Roots = x509.NewCertPool() }},
	}
	for _, tc := range cases {
		t.Run(tc.reason+"/"+tc.want, func(t *testing.T) {
			r := newRig(t, srv.Listener.Addr().String())
			r.Roots = poolOf(srv.Certificate())
			if tc.setup != nil {
				tc.setup(r)
			}
			l := r.withLog(t)
			raw, done := r.connect(t.Context(), t, tc.d)
			c := tls.Client(raw, &tls.Config{ServerName: tc.name, InsecureSkipVerify: true})
			if reply := get(t, c, "/x"); !strings.Contains(reply, "reply to /x") {
				t.Fatalf("reply %q", reply)
			}
			raw.Close()
			waitFor(t, done)
			line := onlyLine(t, l.lines(t))
			if line["action"] != "relayed" || line["reason"] != tc.reason || line["name"] != tc.want {
				t.Fatalf("line %v", line)
			}
			if num(line, "up") == 0 || num(line, "down") == 0 {
				t.Fatalf("no bytes counted: %v", line)
			}
		})
	}
}

func TestConnLogNotTLS(t *testing.T) {
	r := newRig(t, echoServer(t, ""))
	l := r.withLog(t)
	raw, done := r.connect(t.Context(), t, testDest)
	msg := "GET / HTTP/1.0\r\n\r\n"
	io.WriteString(raw, msg)
	if got := readN(t, raw, len(msg)); got != msg {
		t.Fatalf("echo %q", got)
	}
	raw.Close()
	waitFor(t, done)
	line := onlyLine(t, l.lines(t))
	if line["reason"] != "not_tls" || line["name"] != "" ||
		num(line, "up") != int64(len(msg)) || num(line, "down") != int64(len(msg)) {
		t.Fatalf("line %v", line)
	}
	if file, _ := os.ReadFile(l.path); bytes.Contains(file, []byte("GET")) {
		t.Fatalf("the log holds the request: %s", file)
	}
}

func TestConnLogRefused(t *testing.T) {
	cases := []struct {
		reason string
		run    func(t *testing.T, r *socksRig)
		device string
		ip     string
	}{
		{"not_listed", func(t *testing.T, r *socksRig) {
			c := r.open(t, "127.0.0.1")
			c.Write([]byte{5, 1, 0})
			ended(t, c)
		}, "127.0.0.1", ""},
		{"cap", func(t *testing.T, r *socksRig) {
			r.fill(t, "127.0.0.1", maxPerDevice)
			c := r.open(t, "127.0.0.1")
			c.Write([]byte{5, 1, 0})
			ended(t, c)
		}, "127.0.0.1", ""},
		{"destination", func(t *testing.T, r *socksRig) {
			c := r.open(t, "127.0.0.1")
			if code := socksConnect(t, c, 3, domain("intranet.example"), 80); code != ReplyNotAllowed {
				t.Fatalf("code %d", code)
			}
			ended(t, c)
		}, "127.0.0.1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			r := newSocksRig(t, echoServer(t, ""))
			if tc.reason == "not_listed" {
				r.cfg.Devices = []string{"10.0.0.9"}
			}
			if tc.reason == "destination" {
				r.Resolve = func(_ context.Context, host string) ([]net.IP, error) {
					return []net.IP{net.ParseIP("127.0.0.1")}, nil
				}
			}
			l := newLogRig(t, r.Engine.Stats)
			r.Engine.Log = l.ConnLog
			r.cfg.LogConnections = true
			r.Apply(r.cfg)
			tc.run(t, r)
			line := onlyLine(t, l.lines(t))
			if line["action"] != "refused" || line["reason"] != tc.reason || line["device"] != tc.device {
				t.Fatalf("line %v", line)
			}
			if num(line, "up") != 0 || num(line, "down") != 0 {
				t.Fatalf("bytes on a refused connection: %v", line)
			}
			if tc.reason == "destination" && (line["name"] != "intranet.example" || num(line, "port") != 80) {
				t.Fatalf("line %v", line)
			}
		})
	}
}

func TestConnLogRefusedRateLimit(t *testing.T) {
	st := NewStats()
	l := newLogRig(t, st)
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }
	scan := func(src string, n int) {
		for range n {
			l.AddRefused(ConnRecord{Device: src, Action: "refused", Reason: "not_listed"})
		}
	}
	scan("192.0.2.1", 1000) // a port scan
	scan("192.0.2.2", 3)    // another source has its own line
	now = now.Add(time.Second)
	scan("192.0.2.1", 5) // a new second, a new line
	lines := l.lines(t)
	if len(lines) != 3 {
		t.Fatalf("%d lines, want 3", len(lines))
	}
	if n := st.logSkipped; n != 999+2+4 {
		t.Fatalf("skipped %d", n)
	}
}

func TestConnLogOtherLinesNotLimited(t *testing.T) {
	l := newLogRig(t, NewStats())
	for range 50 {
		l.Add(ConnRecord{Device: "192.0.2.1", Action: "relayed", Reason: "bypass"})
	}
	if n := len(l.lines(t)); n != 50 {
		t.Fatalf("%d lines", n)
	}
}

func TestConnLogRotates(t *testing.T) {
	st := NewStats()
	l := newSmallLogRig(t, st, 2000)
	for i := range 20 {
		l.Add(ConnRecord{Device: "192.0.2.1", Name: fmt.Sprintf("site%02d.example", i), Action: "relayed", Reason: "bypass"})
	}
	cur := l.lines(t)
	old := readLines(t, l.path+".1")
	if len(old) == 0 || len(cur) == 0 {
		t.Fatalf("current %d lines, old %d lines", len(cur), len(old))
	}
	if len(old)+len(cur) != 20 {
		t.Fatalf("%d + %d lines, want 20 together", len(old), len(cur))
	}
	for _, p := range []string{l.path, l.path + ".1"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() > 2000+200 {
			t.Fatalf("%s is %d bytes", p, fi.Size())
		}
		if fi.Mode().Perm() != 0o644 {
			t.Fatalf("%s mode %v", p, fi.Mode())
		}
	}
	if old[len(old)-1]["name"] == cur[0]["name"] {
		t.Fatal("a line is in both files")
	}
	if _, err := os.Stat(l.path + ".2"); err == nil {
		t.Fatal("a second backup")
	}
}

func TestConnLogRotationKeepsOnlyOneBackup(t *testing.T) {
	l := newSmallLogRig(t, NewStats(), 500)
	for i := range 200 {
		l.Add(ConnRecord{Device: "192.0.2.1", Name: fmt.Sprintf("s%d", i), Action: "relayed", Reason: "bypass"})
	}
	l.lines(t)
	var total int64
	for _, p := range []string{l.path, l.path + ".1"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		total += fi.Size()
	}
	if total > 2*(500+200) {
		t.Fatalf("%d bytes kept", total)
	}
}

func TestConnLogDefaultSize(t *testing.T) {
	if maxLogSize != 5<<20 {
		t.Fatalf("rotation at %d", maxLogSize)
	}
	if l := NewConnLog("x", NewStats()); l.maxSize != 5<<20 {
		t.Fatalf("maxSize %d", l.maxSize)
	}
}

func TestConnLogFullQueueNeverBlocks(t *testing.T) {
	st := NewStats()
	l := NewConnLog(filepath.Join(t.TempDir(), "c.jsonl"), st)
	l.enabled.Store(true) // on, with no writer to empty the queue
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range logQueue + 100 {
			l.Add(ConnRecord{Device: "192.0.2.1", Action: "relayed"})
		}
		l.AddRefused(ConnRecord{Device: "192.0.2.9", Action: "refused", Reason: "cap"})
	}()
	select {
	case <-done:
	case <-time.After(ioWait):
		t.Fatal("Add blocked on a full queue")
	}
	if st.logDropped != 101 {
		t.Fatalf("dropped %d", st.logDropped)
	}
}

func TestConnLogOffWritesNothing(t *testing.T) {
	st := NewStats()
	path := filepath.Join(t.TempDir(), "connections.jsonl")
	l := NewConnLog(path, st)
	l.Add(ConnRecord{Device: "192.0.2.1", Action: "relayed"})
	l.AddRefused(ConnRecord{Device: "192.0.2.1", Action: "refused"})
	l.SetEnabled(true)
	l.SetEnabled(false)
	l.Wait()
	l.Add(ConnRecord{Device: "192.0.2.1", Action: "relayed"})
	l.Wait()
	if _, err := os.Stat(path); err == nil {
		b, _ := os.ReadFile(path)
		if len(b) != 0 {
			t.Fatalf("written while off: %s", b)
		}
	}
	if st.logDropped != 0 {
		t.Fatalf("dropped %d while off", st.logDropped)
	}
}

func TestConnLogSwitchRestarts(t *testing.T) {
	l := newLogRig(t, NewStats())
	l.Add(ConnRecord{Device: "192.0.2.1", Name: "a", Action: "relayed"})
	l.SetEnabled(false)
	l.Add(ConnRecord{Device: "192.0.2.1", Name: "b", Action: "relayed"})
	l.SetEnabled(true)
	l.Add(ConnRecord{Device: "192.0.2.1", Name: "c", Action: "relayed"})
	var names []string
	for _, m := range l.lines(t) {
		names = append(names, m["name"].(string))
	}
	if got := strings.Join(names, ","); got != "a,c" {
		t.Fatalf("names %s", got)
	}
}

func TestConnLogServerApplySwitches(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	l := newLogRig(t, r.Engine.Stats)
	l.SetEnabled(false)
	r.Engine.Log = l.ConnLog
	r.Apply(r.cfg) // log_connections is not set
	r.relayed(t, "127.0.0.1").Close()
	r.waitConns(t, 0)
	if lines := readLines(t, l.path); len(lines) != 0 {
		t.Fatalf("written while off: %v", lines)
	}
	r.cfg.LogConnections = true
	r.Apply(r.cfg)
	r.relayed(t, "127.0.0.1").Close()
	r.waitConns(t, 0)
	line := onlyLine(t, l.lines(t))
	if line["action"] != "relayed" || line["reason"] != "not_443" || num(line, "port") != 80 {
		t.Fatalf("line %v", line)
	}
}

func TestConnLogSocksHostName(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	l := newLogRig(t, r.Engine.Stats)
	r.Engine.Log = l.ConnLog
	r.cfg.LogConnections = true
	r.Resolve = func(_ context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("198.51.100.7")}, nil
	}
	r.Apply(r.cfg)
	c := r.open(t, "127.0.0.1")
	if code := socksConnect(t, c, 3, domain("files.example"), 80); code != ReplyOK {
		t.Fatalf("code %d", code)
	}
	roundTrip(t, c)
	c.Close()
	r.waitConns(t, 0)
	line := onlyLine(t, l.lines(t))
	if line["name"] != "files.example" || line["ip"] != "198.51.100.7" {
		t.Fatalf("line %v", line)
	}
}

func TestStatsCountLogDrops(t *testing.T) {
	s := NewStats()
	s.LogDropped()
	s.LogDropped()
	s.LogSkipped()
	p := filepath.Join(t.TempDir(), "stats.json")
	if err := s.WriteFile(p, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	var m map[string]any
	json.Unmarshal(raw, &m)
	if m["log_dropped"] != float64(2) || m["log_skipped"] != float64(1) {
		t.Fatalf("stats %s", raw)
	}
}

func TestConfigLogConnections(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(p, []byte(`{"enabled": true, "log_connections": true}`), 0o644)
	c, err := LoadConfig(p, Config{})
	if err != nil || !c.LogConnections {
		t.Fatalf("%+v, %v", c, err)
	}
}

func TestConnLogRefusedGlobalCap(t *testing.T) {
	st := NewStats()
	l := newLogRig(t, st)
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }
	flood := func(n int) {
		for i := range n {
			l.AddRefused(ConnRecord{Device: fmt.Sprintf("198.51.100.%d", i), Action: "refused", Reason: "not_listed"})
		}
	}
	flood(200) // 200 different sources in one second
	now = now.Add(time.Second)
	flood(60) // the count starts again
	if lines := l.lines(t); len(lines) != 100 {
		t.Fatalf("%d lines, want 50 for each second", len(lines))
	}
	if st.logSkipped != 150+10 {
		t.Fatalf("skipped %d, want 160", st.logSkipped)
	}
}

func TestConnLogClearRemovesBothFilesAndKeepsLogging(t *testing.T) {
	l := newSmallLogRig(t, NewStats(), 300)
	for range 10 {
		l.Add(ConnRecord{Device: "192.0.2.1", Name: "a.example", Action: "relayed"})
	}
	time.Sleep(100 * time.Millisecond)
	l.Clear()
	for _, p := range []string{l.path, l.path + ".1"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s is still there: %v", p, err)
		}
	}
	l.Add(ConnRecord{Device: "192.0.2.1", Name: "b.example", Action: "relayed"})
	line := onlyLine(t, l.lines(t))
	if line["name"] != "b.example" {
		t.Fatalf("line %v", line)
	}
}

func TestConnLogClearWhileOff(t *testing.T) {
	l := newLogRig(t, NewStats())
	l.Add(ConnRecord{Device: "192.0.2.1", Action: "relayed"})
	l.lines(t) // stops the writer, the file is on disk
	l.Clear()
	if _, err := os.Stat(l.path); !os.IsNotExist(err) {
		t.Fatalf("the file is still there: %v", err)
	}
	l.Add(ConnRecord{Device: "192.0.2.1", Action: "relayed"})
	l.Wait()
	if _, err := os.Stat(l.path); !os.IsNotExist(err) {
		t.Fatal("written while off")
	}
}

func TestServerDeletesTheLogOnRequest(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	l := newLogRig(t, r.Engine.Stats)
	r.Engine.Log = l.ConnLog
	r.IncomingDir = t.TempDir()
	r.cfg.LogConnections = true
	r.Apply(r.cfg)
	l.Add(ConnRecord{Device: "192.0.2.1", Action: "relayed"})
	time.Sleep(100 * time.Millisecond)
	os.WriteFile(l.path+".1", []byte("{}\n"), 0o644)
	request := filepath.Join(r.IncomingDir, "delete-conn-log")
	if err := os.WriteFile(request, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r.Apply(r.cfg)
	for _, p := range []string{l.path, l.path + ".1", request} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s is still there: %v", p, err)
		}
	}
	l.Add(ConnRecord{Device: "192.0.2.1", Name: "after.example", Action: "relayed"})
	if line := onlyLine(t, l.lines(t)); line["name"] != "after.example" {
		t.Fatalf("line %v", line)
	}
}
