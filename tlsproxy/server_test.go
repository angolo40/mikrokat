package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func statsRefused(s *Stats) int64 { s.mu.Lock(); defer s.mu.Unlock(); return s.refused }

// socksRig is a Server whose Dial reaches target whatever the Dest says. cfg
// turns it on, on a free port, for 127.0.0.1 only.
type socksRig struct {
	*Server
	cfg   Config
	dials atomic.Int64
	last  atomic.Pointer[Dest]
	logs  *bytes.Buffer
}

func newSocksRig(t *testing.T, target string) *socksRig {
	t.Helper()
	r := &socksRig{logs: captureLog(t)}
	em, _, st := startEmitter(t, 1<<20)
	r.Server = NewServer(&Engine{
		CA:      new(atomic.Pointer[CA]),
		Bypass:  NewBypass(nil),
		Emitter: em,
		Stats:   st,
		Dial: func(ctx context.Context, d Dest) (net.Conn, error) {
			r.dials.Add(1)
			r.last.Store(&d)
			return new(net.Dialer).DialContext(ctx, "tcp4", target)
		},
	}, t.TempDir(), t.TempDir())
	r.cfg = Config{Enabled: true, Socks: true, SocksPort: freePort(t), Devices: []string{"127.0.0.1"}}
	t.Cleanup(func() {
		r.Apply(Config{})
		r.waitConns(t, 0)
	})
	return r
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func (r *socksRig) addr() string { return fmt.Sprintf("127.0.0.1:%d", r.cfg.SocksPort) }

// open connects to the proxy from the given loopback address.
func (r *socksRig) open(t *testing.T, from string) *net.TCPConn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(from)}, Timeout: ioWait}
	c, err := d.Dial("tcp4", r.addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(ioWait))
	return c.(*net.TCPConn)
}

// socksConnect runs the client side of the handshake and returns the reply code.
func socksConnect(t *testing.T, c net.Conn, atyp byte, addr []byte, port uint16) byte {
	t.Helper()
	if _, err := c.Write(append([]byte{5, 1, 0}, request(atyp, addr, port)...)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 12) // method selection, then the reply
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if reply[0] != 5 || reply[1] != 0 || reply[2] != 5 {
		t.Fatalf("reply: %v", reply)
	}
	return reply[3]
}

func domain(host string) []byte { return append([]byte{byte(len(host))}, host...) }

// relayed opens a connection through the proxy and checks that it carries bytes.
func (r *socksRig) relayed(t *testing.T, from string) *net.TCPConn {
	t.Helper()
	c := r.open(t, from)
	if code := socksConnect(t, c, 1, []byte{198, 51, 100, 7}, 80); code != ReplyOK {
		t.Fatalf("reply code %d", code)
	}
	roundTrip(t, c)
	return c
}

func roundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetDeadline(time.Now().Add(ioWait))
	if _, err := io.WriteString(c, "ping"); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, c, 4); got != "ping" {
		t.Fatalf("got %q", got)
	}
}

// ended reads until c ends, fails if it stays open, and returns the bytes read.
func ended(t *testing.T, c net.Conn) int64 {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(ioWait))
	n, err := io.Copy(io.Discard, c)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("connection still open")
	}
	return n
}

func portClosed(t *testing.T, addr string) {
	t.Helper()
	c, err := net.DialTimeout("tcp4", addr, ioWait)
	if err == nil {
		c.Close()
		t.Fatal("port still open")
	}
}

// waitConns waits until the server holds exactly n connections.
func (r *socksRig) waitConns(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(ioWait)
	for {
		r.mu.Lock()
		held := 0
		for _, group := range r.conns {
			held += len(group)
		}
		r.mu.Unlock()
		if held == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d connections held, want %d", held, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestForbidden(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "127.1.2.3", "::1", "::ffff:127.0.0.1",
		"169.254.169.254", "::ffff:169.254.169.254", "fe80::1",
		"224.0.0.1", "239.255.255.250", "::ffff:224.0.0.1", "ff01::1", "ff02::1", "ff0e::1",
		"0.0.0.0", "::", "::ffff:0.0.0.0",
	} {
		if !Forbidden(net.ParseIP(s)) {
			t.Errorf("%s is allowed", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "::ffff:8.8.8.8", "10.0.0.1", "192.168.1.1", "fd00::1", "2001:4860:4860::8888"} {
		if Forbidden(net.ParseIP(s)) {
			t.Errorf("%s is forbidden", s)
		}
	}
}

func TestDeviceOutsideListRefused(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.cfg.Devices = []string{"10.0.0.9"}
	r.Apply(r.cfg)
	c := r.open(t, "127.0.0.1")
	c.Write([]byte{5, 1, 0})
	if n := ended(t, c); n != 0 {
		t.Fatalf("%d bytes sent to a refused device", n)
	}
	if n := statsRefused(r.Engine.Stats); n != 1 {
		t.Fatalf("refused = %d", n)
	}
	if n := r.dials.Load(); n != 0 {
		t.Fatalf("%d dials", n)
	}
}

func TestAllowedDeviceIsRelayed(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.Apply(r.cfg)
	r.relayed(t, "127.0.0.1")
	if n := statsRelayed(r.Engine.Stats, "not_443"); n != 1 {
		t.Fatalf("relayed = %d", n)
	}
	if n := statsRefused(r.Engine.Stats); n != 0 {
		t.Fatalf("refused = %d", n)
	}
}

func TestForbiddenDestination(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.Apply(r.cfg)
	for _, tc := range []struct {
		atyp byte
		ip   net.IP
	}{
		{1, net.ParseIP("127.0.0.1").To4()},
		{1, net.ParseIP("169.254.169.254").To4()},
		{4, net.ParseIP("::ffff:127.0.0.1")},
		{4, net.ParseIP("::1")},
	} {
		c := r.open(t, "127.0.0.1")
		if code := socksConnect(t, c, tc.atyp, tc.ip, 80); code != ReplyNotAllowed {
			t.Errorf("%s: reply code %d", tc.ip, code)
		}
		ended(t, c)
	}
	if n := r.dials.Load(); n != 0 {
		t.Fatalf("%d dials", n)
	}
}

func TestForbiddenAfterResolve(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.Resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	r.Apply(r.cfg)
	c := r.open(t, "127.0.0.1")
	if code := socksConnect(t, c, 3, domain("inside.test"), 80); code != ReplyNotAllowed {
		t.Fatalf("reply code %d", code)
	}
	if n := r.dials.Load(); n != 0 {
		t.Fatalf("%d dials", n)
	}
}

func TestResolveChoosesAddress(t *testing.T) {
	v6, v4, v4b := net.ParseIP("2001:db8::1"), net.ParseIP("198.51.100.7"), net.ParseIP("198.51.100.8")
	for name, tc := range map[string]struct {
		ips  []net.IP
		want net.IP
	}{
		"first ipv4": {[]net.IP{v6, v4, v4b}, v4},
		"first ipv6": {[]net.IP{v6, net.ParseIP("2001:db8::2")}, v6},
	} {
		t.Run(name, func(t *testing.T) {
			r := newSocksRig(t, echoServer(t, ""))
			r.Resolve = func(_ context.Context, host string) ([]net.IP, error) {
				if host != "site.test" {
					t.Errorf("resolved %q", host)
				}
				return tc.ips, nil
			}
			r.Apply(r.cfg)
			c := r.open(t, "127.0.0.1")
			if code := socksConnect(t, c, 3, domain("site.test"), 8080); code != ReplyOK {
				t.Fatalf("reply code %d", code)
			}
			d := r.last.Load()
			if !d.IP.Equal(tc.want) || d.Host != "" || d.Port != 8080 {
				t.Fatalf("dialled %+v, want %s", d, tc.want)
			}
		})
	}
}

func TestResolveFailure(t *testing.T) {
	for name, resolve := range map[string]func(context.Context, string) ([]net.IP, error){
		"error":        func(context.Context, string) ([]net.IP, error) { return nil, errors.New("no such host") },
		"no addresses": func(context.Context, string) ([]net.IP, error) { return nil, nil },
	} {
		t.Run(name, func(t *testing.T) {
			r := newSocksRig(t, echoServer(t, ""))
			r.Resolve = resolve
			r.Apply(r.cfg)
			c := r.open(t, "127.0.0.1")
			if code := socksConnect(t, c, 3, domain("gone.test"), 80); code != ReplyUnreachable {
				t.Fatalf("reply code %d", code)
			}
			if n := r.dials.Load(); n != 0 {
				t.Fatalf("%d dials", n)
			}
		})
	}
}

func TestDialFailureIsUnreachable(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.Engine.Dial = func(context.Context, Dest) (net.Conn, error) { return nil, errors.New("no route") }
	r.Apply(r.cfg)
	c := r.open(t, "127.0.0.1")
	if code := socksConnect(t, c, 1, []byte{198, 51, 100, 7}, 80); code != ReplyUnreachable {
		t.Fatalf("reply code %d", code)
	}
	ended(t, c)
}

func TestDialKeepsTCPConn(t *testing.T) {
	addr, err := net.ResolveTCPAddr("tcp4", echoServer(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Dial(context.Background(), Dest{IP: addr.IP, Port: addr.Port})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, ok := c.(*net.TCPConn); !ok {
		t.Fatalf("got %T", c)
	}
	roundTrip(t, c)
}

func TestDisableClosesPortAndConnections(t *testing.T) {
	for name, off := range map[string]func(*Config){
		"disabled":  func(c *Config) { c.Enabled = false },
		"socks off": func(c *Config) { c.Socks = false },
	} {
		t.Run(name, func(t *testing.T) {
			r := newSocksRig(t, echoServer(t, ""))
			r.Apply(r.cfg)
			c := r.relayed(t, "127.0.0.1")
			next := r.cfg
			off(&next)
			r.Apply(next)
			portClosed(t, r.addr())
			ended(t, c)
			r.waitConns(t, 0)
		})
	}
}

func TestPortClosedByDefault(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.Apply(Config{Socks: true, SocksPort: r.cfg.SocksPort, Devices: r.cfg.Devices})
	portClosed(t, r.addr())
}

func TestNoPortSet(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.cfg.SocksPort = 0
	r.Apply(r.cfg)
	if r.ln != nil {
		t.Fatalf("listening on %s", r.ln.Addr())
	}
}

func TestRemovedDeviceLosesConnections(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.cfg.Devices = []string{"127.0.0.1", "127.0.0.2"}
	r.Apply(r.cfg)
	keep := r.relayed(t, "127.0.0.1")
	gone := r.relayed(t, "127.0.0.2")
	r.cfg.Devices = []string{"127.0.0.1"}
	r.Apply(r.cfg)
	ended(t, gone)
	r.waitConns(t, 1)
	roundTrip(t, keep)
}

func TestApplyTwiceKeepsListener(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.Apply(r.cfg)
	c := r.relayed(t, "127.0.0.1")
	ln := r.ln
	r.Apply(r.cfg)
	r.Apply(r.cfg)
	if r.ln != ln {
		t.Fatal("listener reopened")
	}
	roundTrip(t, c)
	r.relayed(t, "127.0.0.1")
	if n := statsRelayed(r.Engine.Stats, "not_443"); n != 2 {
		t.Fatalf("relayed = %d", n)
	}
}

func TestUnrelatedChangeKeepsConnections(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.Apply(r.cfg)
	c := r.relayed(t, "127.0.0.1")
	ln := r.ln
	r.cfg.Devices = []string{"127.0.0.1", "10.0.0.9"}
	r.cfg.Bypass = []string{"bank.test"}
	r.Apply(r.cfg)
	if r.ln != ln {
		t.Fatal("listener reopened")
	}
	roundTrip(t, c)
}

func TestChangedPortReopensListener(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.Apply(r.cfg)
	c := r.relayed(t, "127.0.0.1")
	old := r.addr()
	r.cfg.SocksPort = freePort(t)
	r.Apply(r.cfg)
	portClosed(t, old)
	r.relayed(t, "127.0.0.1")
	roundTrip(t, c)
}

func TestReopenAfterDisable(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.Apply(r.cfg)
	r.Apply(Config{})
	r.Apply(r.cfg)
	r.relayed(t, "127.0.0.1")
}

func TestPortInUseIsRetried(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	l, err := net.Listen("tcp", r.addr())
	if err != nil {
		t.Fatal(err)
	}
	r.Apply(r.cfg)
	if r.ln != nil {
		t.Fatal("listening on a taken port")
	}
	l.Close()
	r.Apply(r.cfg)
	r.relayed(t, "127.0.0.1")
}

func TestAppliesBypass(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	now := time.Now()
	r.Engine.Bypass.AddAuto("10.0.0.9", "site.test", now)
	r.Apply(Config{
		Bypass:     []string{"bank.test"},
		AutoRemove: []AutoRemoval{{Device: "10.0.0.9", Name: "site.test", At: now.Unix() + 1}},
	})
	if got := r.Engine.Bypass.Match("10.0.0.9", "www.bank.test", now); got != "bypass" {
		t.Fatalf("own list: %q", got)
	}
	if got := r.Engine.Bypass.Match("10.0.0.9", "site.test", now); got != "" {
		t.Fatalf("removed entry: %q", got)
	}
}

func TestCAOnlyOnceEnabled(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	pem := filepath.Join(r.StateDir, "ca.pem")
	r.Apply(Config{Socks: true, SocksPort: r.cfg.SocksPort, CAGeneration: 3})
	if r.Engine.CA.Load() != nil {
		t.Fatal("CA loaded while off")
	}
	if _, err := os.Stat(pem); !os.IsNotExist(err) {
		t.Fatalf("ca.pem while off: %v", err)
	}
	r.Apply(Config{Enabled: true, CAGeneration: 3})
	if r.Engine.CA.Load() == nil {
		t.Fatal("no CA once enabled")
	}
	if _, err := os.Stat(pem); err != nil {
		t.Fatal(err)
	}
	portClosed(t, r.addr())
}

func TestCAFailureKeepsPortClosed(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	good := r.PrivateDir
	r.PrivateDir = filepath.Join(t.TempDir(), "not-a-folder")
	if err := os.WriteFile(r.PrivateDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r.Apply(r.cfg)
	if r.Engine.CA.Load() != nil {
		t.Fatal("CA stored")
	}
	portClosed(t, r.addr())
	if !strings.Contains(r.logs.String(), "not-a-folder") {
		t.Fatalf("not logged: %q", r.logs)
	}
	// The next poll tries again.
	r.PrivateDir = good
	r.Apply(r.cfg)
	r.relayed(t, "127.0.0.1")
}

func TestCAReload(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.Apply(r.cfg)
	first := r.Engine.CA.Load()
	r.Apply(r.cfg)
	r.Apply(Config{})
	r.Apply(r.cfg)
	if r.Engine.CA.Load() != first {
		t.Fatal("CA reloaded without a new generation")
	}
	c := r.relayed(t, "127.0.0.1")
	ln := r.ln
	r.cfg.CAGeneration++
	r.Apply(r.cfg)
	second := r.Engine.CA.Load()
	if second == first || second.cert.Equal(first.cert) {
		t.Fatal("CA not replaced")
	}
	if r.ln != ln {
		t.Fatal("listener reopened")
	}
	roundTrip(t, c)
	// A generation that changed while off counts at the next switch-on.
	r.Apply(Config{})
	r.cfg.CAGeneration++
	r.Apply(r.cfg)
	if r.Engine.CA.Load() == second {
		t.Fatal("CA not replaced after a change while off")
	}
}

func TestCAReloadFailureClosesPort(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.Apply(r.cfg)
	c := r.relayed(t, "127.0.0.1")
	good := r.PrivateDir
	r.PrivateDir = filepath.Join(t.TempDir(), "not-a-folder")
	if err := os.WriteFile(r.PrivateDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r.cfg.CAGeneration++
	r.Apply(r.cfg)
	portClosed(t, r.addr())
	ended(t, c)
	r.PrivateDir = good
	r.Apply(r.cfg)
	r.relayed(t, "127.0.0.1")
}

func TestSilentClientIsDropped(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.GreetLimit = 50 * time.Millisecond
	r.Apply(r.cfg)
	ended(t, r.open(t, "127.0.0.1"))
}

func TestGreetLimitIsCleared(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.GreetLimit = 50 * time.Millisecond
	r.Apply(r.cfg)
	c := r.relayed(t, "127.0.0.1")
	time.Sleep(150 * time.Millisecond)
	roundTrip(t, c)
}

func TestDisableDuringGreet(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.GreetLimit = time.Minute
	r.Apply(r.cfg)
	c := r.open(t, "127.0.0.1")
	r.waitConns(t, 1)
	r.Apply(Config{})
	ended(t, c)
}

func TestDisableDuringResolve(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	asked := make(chan struct{})
	r.Resolve = func(ctx context.Context, _ string) ([]net.IP, error) {
		close(asked)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	r.Apply(r.cfg)
	c := r.open(t, "127.0.0.1")
	if _, err := c.Write(append([]byte{5, 1, 0}, request(3, domain("slow.test"), 80)...)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, asked)
	r.Apply(Config{})
	ended(t, c)
	r.waitConns(t, 0)
}

// A connection accepted while Apply runs must not outlive the switch-off, even
// though the device stays on the list, as it does when the app turns off.
func TestDisableRacesAccept(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.GreetLimit = time.Minute
	off := r.cfg
	off.Enabled = false
	var left atomic.Int64
	for i := range 100 {
		r.Apply(r.cfg)
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() {
				c, err := net.DialTimeout("tcp4", r.addr(), ioWait)
				if err != nil {
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(ioWait))
				// Speak first, as a real client does. A handshake that lost the
				// race leaves this end established with nothing behind it, and
				// only a write finds that out.
				c.Write([]byte{5, 1, 0})
				var ne net.Error
				if _, err := io.Copy(io.Discard, c); errors.As(err, &ne) && ne.Timeout() {
					left.Add(1)
				}
			})
		}
		time.Sleep(time.Duration(i) * 10 * time.Microsecond) // walk across the window
		r.Apply(off)
		wg.Wait()
		if n := left.Load(); n != 0 {
			t.Fatalf("%d connections outlived the switch-off", n)
		}
	}
}

func TestClosedListenerAdmitsNothing(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	r.Apply(r.cfg)
	ln := r.ln
	off := r.cfg
	off.Enabled = false
	r.Apply(off)
	if _, _, ok := r.admit(ln, net.ParseIP("127.0.0.1")); ok {
		t.Fatal("admitted from a closed listener")
	}
}

func TestLogsEachChangeOnce(t *testing.T) {
	r := newSocksRig(t, echoServer(t, ""))
	lines := func() int { return strings.Count(r.logs.String(), "\n") }
	r.Apply(Config{})
	if n := lines(); n != 1 {
		t.Fatalf("%d lines after the first apply: %q", n, r.logs)
	}
	r.Apply(Config{})
	if n := lines(); n != 1 {
		t.Fatalf("%d lines after the same config: %q", n, r.logs)
	}
	r.Apply(r.cfg)
	on := lines()
	if on < 2 {
		t.Fatalf("switching on was not logged: %q", r.logs)
	}
	r.relayed(t, "127.0.0.1")
	r.Apply(r.cfg)
	if n := lines(); n != on {
		t.Fatalf("%d lines, want %d: %q", n, on, r.logs)
	}
}
