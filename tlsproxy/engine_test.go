package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testName = "example.com" // a name in the httptest certificate
	ioWait   = 5 * time.Second
)

var (
	testDest   = Dest{IP: net.IPv4(198, 51, 100, 7), Port: 443}
	testDevice = net.IPv4(10, 0, 0, 9)
)

func statsRelayed(s *Stats, reason string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.relayed[reason]
}
func statsInspected(s *Stats) int64  { s.mu.Lock(); defer s.mu.Unlock(); return s.inspected }
func statsHandshakes(s *Stats) int64 { s.mu.Lock(); defer s.mu.Unlock(); return s.handshakes }

// trackedConn lowers its counter on the first Close.
type trackedConn struct {
	*net.TCPConn
	once sync.Once
	open *atomic.Int64
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.open.Add(-1) })
	return c.TCPConn.Close()
}

// rig is an Engine with an emitter, a private CA and a Dial that reaches addr
// whatever the Dest says. Every connection given to Handle is tracked, and
// the test fails if one is left open.
type rig struct {
	*Engine
	sink  *sink
	open  atomic.Int64
	ready chan bool
}

func newRig(t *testing.T, addr string) *rig {
	t.Helper()
	em, sk, st := startEmitter(t, 1<<20)
	ca, err := LoadCA(t.TempDir(), t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	ptr := new(atomic.Pointer[CA])
	ptr.Store(ca)
	r := &rig{sink: sk, ready: make(chan bool, 8)}
	r.Engine = &Engine{CA: ptr, Bypass: NewBypass(nil), Emitter: em, Stats: st}
	r.Dial = func(ctx context.Context, _ Dest) (net.Conn, error) { return r.dial(ctx, addr) }
	t.Cleanup(func() {
		if n := r.open.Load(); n != 0 {
			t.Errorf("%d connections left open", n)
		}
	})
	return r
}

func (r *rig) track(c net.Conn) net.Conn {
	r.open.Add(1)
	return &trackedConn{TCPConn: c.(*net.TCPConn), open: &r.open}
}

func (r *rig) dial(ctx context.Context, addr string) (net.Conn, error) {
	c, err := new(net.Dialer).DialContext(ctx, "tcp4", addr)
	if err != nil {
		return nil, err
	}
	return r.track(c), nil
}

// connect gives Handle one end of a real loopback TCP connection and returns
// the other, with a channel closed when Handle has returned. The cleanup
// checks that Handle returned and called ready exactly once.
func (r *rig) connect(ctx context.Context, t *testing.T, d Dest) (*net.TCPConn, <-chan struct{}) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	raw := c.(*net.TCPConn)
	raw.SetDeadline(time.Now().Add(ioWait))
	s, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	var readies atomic.Int64
	done := make(chan struct{})
	tracked := r.track(s)
	go func() {
		defer close(done)
		r.Handle(ctx, tracked, testDevice, d, func(ok bool) {
			readies.Add(1)
			r.ready <- ok
		})
	}()
	t.Cleanup(func() {
		raw.Close()
		waitFor(t, done)
		if n := readies.Load(); n != 1 {
			t.Errorf("ready called %d times", n)
		}
	})
	return raw, done
}

func (r *rig) waitReady(t *testing.T) bool {
	t.Helper()
	select {
	case ok := <-r.ready:
		return ok
	case <-time.After(ioWait):
		t.Fatal("ready was not called")
		return false
	}
}

// clientConfig is a client that trusts our CA.
func (r *rig) clientConfig() *tls.Config {
	return &tls.Config{ServerName: testName, RootCAs: poolOf(r.CA.Load().cert)}
}

func waitFor(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(ioWait):
		t.Fatal("Handle did not return")
	}
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

// tlsServer starts an HTTPS server that does not log failed handshakes, which
// several tests provoke on purpose.
func tlsServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "reply to %s over %s", r.URL.Path, r.Proto)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// tcpServer runs serve for each connection accepted on loopback. serve runs
// on its own goroutine and must not touch t.
func tcpServer(t *testing.T, serve func(c *net.TCPConn)) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(20 * time.Second))
				serve(c.(*net.TCPConn))
			}()
		}
	}()
	return l.Addr().String()
}

// echoServer sends banner, then returns every byte it reads.
func echoServer(t *testing.T, banner string) string {
	t.Helper()
	return tcpServer(t, func(c *net.TCPConn) {
		io.WriteString(c, banner)
		io.Copy(c, c)
	})
}

// tlsEnd runs serve on TLS connections with a certificate for testName from a
// CA of its own, and returns the address and that CA as a pool.
func tlsEnd(t *testing.T, serve func(s *tls.Conn)) (string, *x509.CertPool) {
	t.Helper()
	return tlsEndWith(t, func(*tls.Config) {}, serve)
}

// tlsEndWith is tlsEnd with a say in the server's configuration.
func tlsEndWith(t *testing.T, configure func(*tls.Config), serve func(s *tls.Conn)) (string, *x509.CertPool) {
	t.Helper()
	ca, err := LoadCA(t.TempDir(), t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf(testName)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{*leaf}}
	configure(cfg)
	addr := tcpServer(t, func(c *net.TCPConn) {
		s := tls.Server(c, cfg)
		defer s.Close()
		if s.Handshake() == nil {
			serve(s)
		}
	})
	return addr, poolOf(ca.cert)
}

// get sends one request and returns the whole reply.
func get(t *testing.T, c io.ReadWriter, path string) string {
	t.Helper()
	if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, testName); err != nil {
		t.Fatalf("request: %v", err)
	}
	reply, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("reply: %v", err)
	}
	return string(reply)
}

func readN(t *testing.T, r io.Reader, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b)
}

// collect reads the rebuilt conversation up to its last ACK and returns its
// first frame and the payload of each direction.
func collect(t *testing.T, sk *sink) (syn []byte, fromClient, fromServer string) {
	t.Helper()
	for fins := 0; ; {
		f := sk.frame(t)
		if syn == nil {
			syn = f
		}
		if dstPort(f) == 80 {
			fromClient += string(f[dataAt:])
		} else {
			fromServer += string(f[dataAt:])
		}
		if flagsOf(f)&flagFIN != 0 {
			fins++
		} else if fins == 2 {
			return syn, fromClient, fromServer
		}
	}
}

func TestClassify(t *testing.T) {
	public := net.IPv4(198, 51, 100, 7)
	private := net.IPv4(192, 168, 1, 1)
	v6 := net.ParseIP("2001:db8::1")
	named := Hello{TLS: true, Name: "example.com"}
	cases := []struct {
		name  string
		d     Dest
		h     Hello
		match string
		want  string
	}{
		{"inspect", Dest{IP: public, Port: 443}, named, "", ""},
		{"port", Dest{IP: public, Port: 80}, named, "", "not_443"},
		{"ipv6", Dest{IP: v6, Port: 443}, named, "", "ipv6"},
		{"private 10", Dest{IP: net.IPv4(10, 1, 2, 3), Port: 443}, named, "", "private"},
		{"private 172", Dest{IP: net.IPv4(172, 16, 0, 1), Port: 443}, named, "", "private"},
		{"private 192", Dest{IP: private, Port: 443}, named, "", "private"},
		{"not tls", Dest{IP: public, Port: 443}, Hello{}, "", "not_tls"},
		{"no name", Dest{IP: public, Port: 443}, Hello{TLS: true}, "", "no_name"},
		{"bypass", Dest{IP: public, Port: 443}, named, "bypass", "bypass"},
		{"auto", Dest{IP: public, Port: 443}, named, "auto_bypass", "auto_bypass"},

		{"port comes before ipv6", Dest{IP: v6, Port: 25}, named, "", "not_443"},
		{"ipv6 comes before private", Dest{IP: net.ParseIP("fd00::1"), Port: 443}, named, "", "ipv6"},
		{"private comes before not tls", Dest{IP: private, Port: 443}, Hello{}, "", "private"},
		{"not tls comes before no name", Dest{IP: public, Port: 443}, Hello{}, "", "not_tls"},
		{"no name comes before match", Dest{IP: public, Port: 443}, Hello{TLS: true}, "bypass", "no_name"},
		{"mapped IPv4 is IPv4", Dest{IP: net.ParseIP("::ffff:198.51.100.7"), Port: 443}, named, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Classify(c.d, c.h, c.match); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestInspectCopiesPlaintext(t *testing.T) {
	srv := tlsServer(t)
	r := newRig(t, srv.Listener.Addr().String())
	r.Roots = poolOf(srv.Certificate())
	raw, done := r.connect(t.Context(), t, testDest)

	c := tls.Client(raw, r.clientConfig())
	if reply := get(t, c, "/x"); !strings.Contains(reply, "reply to /x") {
		t.Fatalf("reply %q", reply)
	}
	leaf := c.ConnectionState().PeerCertificates[0]
	if err := leaf.CheckSignatureFrom(r.CA.Load().cert); err != nil {
		t.Fatalf("leaf not from our CA: %v", err)
	}
	if n := statsInspected(r.Stats); n != 1 {
		t.Fatalf("inspected %d", n)
	}

	raw.Close()
	waitFor(t, done)
	syn, fromClient, fromServer := collect(t, r.sink)
	if !strings.Contains(fromClient, "GET /x") {
		t.Fatalf("client copy %q", fromClient)
	}
	if !strings.Contains(fromServer, "reply to /x") {
		t.Fatalf("server copy %q", fromServer)
	}
	if src := net.IP(syn[fHdr+12 : fHdr+16]); !src.Equal(testDevice) {
		t.Fatalf("source %v", src)
	}
	if dst := net.IP(syn[fHdr+16 : fHdr+20]); !dst.Equal(testDest.IP) {
		t.Fatalf("destination %v", dst)
	}
	port := int(syn[tcpAt])<<8 | int(syn[tcpAt+1])
	if want := raw.LocalAddr().(*net.TCPAddr).Port; port != want {
		t.Fatalf("client port %d, want %d", port, want)
	}
}

func TestOnlyHTTP11Offered(t *testing.T) {
	// This server prefers h2, so any offer of h2 upstream would be taken and
	// the HTTP/1.1 request below would fail.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "over %s", r.Proto)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	r := newRig(t, srv.Listener.Addr().String())
	r.Roots = poolOf(srv.Certificate())
	raw, _ := r.connect(t.Context(), t, testDest)

	cfg := r.clientConfig()
	cfg.NextProtos = []string{"h2", "http/1.1"}
	c := tls.Client(raw, cfg)
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	if got := c.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("negotiated %q", got)
	}
	if reply := get(t, c, "/"); !strings.Contains(reply, "over HTTP/1.1") {
		t.Fatalf("reply %q", reply)
	}
}

func TestBadUpstreamRelaysOriginal(t *testing.T) {
	srv := tlsServer(t)
	cases := []struct {
		name       string
		roots      *x509.CertPool
		serverName string
	}{
		{"unknown issuer", x509.NewCertPool(), testName},
		{"wrong name", poolOf(srv.Certificate()), "other.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, srv.Listener.Addr().String())
			r.Roots = tc.roots
			raw, _ := r.connect(t.Context(), t, testDest)

			// The client accepts anything, to show what it was given.
			c := tls.Client(raw, &tls.Config{ServerName: tc.serverName, InsecureSkipVerify: true})
			if err := c.Handshake(); err != nil {
				t.Fatal(err)
			}
			if n := r.open.Load(); n != 2 {
				t.Fatalf("%d connections open during the relay, want the client and one upstream", n)
			}
			if reply := get(t, c, "/x"); !strings.Contains(reply, "reply to /x") {
				t.Fatalf("reply %q", reply)
			}
			if !c.ConnectionState().PeerCertificates[0].Equal(srv.Certificate()) {
				t.Fatal("client did not see the server's own certificate")
			}
			if n := statsRelayed(r.Stats, "upstream"); n != 1 {
				t.Fatalf("relayed upstream %d", n)
			}
			if n := statsInspected(r.Stats); n != 0 {
				t.Fatalf("inspected %d", n)
			}
			r.sink.none(t)
		})
	}
}

func TestClientCertRequestRelays(t *testing.T) {
	// Leaf certificates are for servers, so these servers do not verify the
	// client's: they only show whether it arrived.
	cases := []struct {
		name    string
		version uint16
		auth    tls.ClientAuthType
	}{
		{"TLS 1.3 required", tls.VersionTLS13, tls.RequireAnyClientCert},
		{"TLS 1.3 optional", tls.VersionTLS13, tls.RequestClientCert},
		{"TLS 1.2 required", tls.VersionTLS12, tls.RequireAnyClientCert},
		{"TLS 1.2 optional", tls.VersionTLS12, tls.RequestClientCert},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan *x509.Certificate, 2)
			addr, roots := tlsEndWith(t, func(cfg *tls.Config) {
				cfg.MaxVersion = tc.version
				cfg.ClientAuth = tc.auth
			}, func(s *tls.Conn) {
				var peer *x509.Certificate
				if certs := s.ConnectionState().PeerCertificates; len(certs) > 0 {
					peer = certs[0]
				}
				seen <- peer
				io.Copy(s, s)
			})
			r := newRig(t, addr)
			r.Roots = roots
			raw, _ := r.connect(t.Context(), t, testDest)

			// An enrolled device: it trusts our CA as well as the server's,
			// so only the relay can bring its certificate to the server.
			own, err := r.CA.Load().Leaf("device.example")
			if err != nil {
				t.Fatal(err)
			}
			trusted := roots.Clone()
			trusted.AddCert(r.CA.Load().cert)
			c := tls.Client(raw, &tls.Config{
				ServerName:   testName,
				RootCAs:      trusted,
				Certificates: []tls.Certificate{*own},
			})
			if _, err := c.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(c, make([]byte, 4)); err != nil {
				t.Errorf("reply: %v", err)
			}

			// serve reports before it echoes, so a reply means it has reported.
			var peer *x509.Certificate
			select {
			case peer = <-seen:
			default:
			}
			if peer == nil || !peer.Equal(own.Leaf) {
				t.Errorf("the client's certificate did not reach the server")
			}
			if n := statsInspected(r.Stats); n != 0 {
				t.Errorf("inspected %d", n)
			}
			if n := statsRelayed(r.Stats, "upstream"); n != 1 {
				t.Errorf("relayed upstream %d", n)
			}
		})
	}
}

func TestBadUpstreamSecondDialFails(t *testing.T) {
	srv := tlsServer(t)
	r := newRig(t, srv.Listener.Addr().String())
	r.Roots = x509.NewCertPool()
	first := r.Dial
	var dials atomic.Int64
	r.Dial = func(ctx context.Context, d Dest) (net.Conn, error) {
		if dials.Add(1) > 1 {
			return nil, errors.New("unreachable")
		}
		return first(ctx, d)
	}
	raw, done := r.connect(t.Context(), t, testDest)

	if _, err := raw.Write(captureHello(t, testName)); err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, raw)
	if n != 0 || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read %d bytes, err %v", n, err)
	}
	waitFor(t, done)
	if !r.waitReady(t) {
		t.Fatal("ready(false) after a good first dial")
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("%d dials", n)
	}
	if n := statsRelayed(r.Stats, "upstream"); n != 0 {
		t.Fatalf("relayed upstream %d", n)
	}
}

func TestRelayReasons(t *testing.T) {
	srv := tlsServer(t)
	cases := []struct {
		reason     string
		d          Dest
		serverName string
		own        []string
	}{
		{"bypass", testDest, testName, []string{testName}},
		{"no_name", testDest, "", nil},
		{"ipv6", Dest{IP: net.ParseIP("2001:db8::1"), Port: 443}, testName, nil},
		{"private", Dest{IP: net.IPv4(192, 168, 1, 1), Port: 443}, testName, nil},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			r := newRig(t, srv.Listener.Addr().String())
			r.Roots = poolOf(srv.Certificate()) // would be inspected if not relayed
			r.Bypass.SetOwn(tc.own)
			raw, _ := r.connect(t.Context(), t, tc.d)

			c := tls.Client(raw, &tls.Config{ServerName: tc.serverName, InsecureSkipVerify: true})
			if reply := get(t, c, "/x"); !strings.Contains(reply, "reply to /x") {
				t.Fatalf("reply %q", reply)
			}
			if !c.ConnectionState().PeerCertificates[0].Equal(srv.Certificate()) {
				t.Fatal("client did not see the server's own certificate")
			}
			if n := statsRelayed(r.Stats, tc.reason); n != 1 {
				t.Fatalf("relayed %s %d", tc.reason, n)
			}
		})
	}
}

func TestClientRejectsOurCert(t *testing.T) {
	srv := tlsServer(t)
	r := newRig(t, srv.Listener.Addr().String())
	r.Roots = poolOf(srv.Certificate())
	r.Now = func() time.Time { return t0 }
	device := testDevice.String()
	raw, done := r.connect(t.Context(), t, testDest)

	// This client trusts the real server and not our CA, like a pinned app.
	pinned := &tls.Config{ServerName: testName, RootCAs: poolOf(srv.Certificate())}
	if err := tls.Client(raw, pinned).Handshake(); err == nil {
		t.Fatal("client accepted our certificate")
	}
	waitFor(t, done)
	if got := r.Bypass.Match(device, testName, t0); got != "auto_bypass" {
		t.Fatalf("match %q", got)
	}
	if got := r.Bypass.Match(device, testName, t0.Add(autoTTL)); got != "" {
		t.Fatalf("entry not dated from Now: match %q", got)
	}
	if n := statsHandshakes(r.Stats); n != 1 {
		t.Fatalf("handshake failures %d", n)
	}

	raw, _ = r.connect(t.Context(), t, testDest)
	c := tls.Client(raw, pinned)
	if reply := get(t, c, "/x"); !strings.Contains(reply, "reply to /x") {
		t.Fatalf("reply %q", reply)
	}
	if n := statsRelayed(r.Stats, "auto_bypass"); n != 1 {
		t.Fatalf("relayed auto_bypass %d", n)
	}
	if n := statsInspected(r.Stats); n != 0 {
		t.Fatalf("inspected %d", n)
	}
}

func TestPlainCloseAddsAuto(t *testing.T) {
	cases := []struct {
		name  string
		close func(c *net.TCPConn) error
	}{
		{"fin", (*net.TCPConn).CloseWrite},
		{"reset", (*net.TCPConn).Close}, // unread bytes turn the close into a reset
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tlsServer(t)
			r := newRig(t, srv.Listener.Addr().String())
			r.Roots = poolOf(srv.Certificate())
			raw, done := r.connect(t.Context(), t, testDest)

			if _, err := raw.Write(captureHello(t, testName)); err != nil {
				t.Fatal(err)
			}
			readN(t, raw, 1) // the proxy answered: the client handshake is running
			if err := tc.close(raw); err != nil {
				t.Fatal(err)
			}
			waitFor(t, done)
			if got := r.Bypass.Match(testDevice.String(), testName, time.Now()); got != "auto_bypass" {
				t.Fatalf("match %q", got)
			}
			if n := statsHandshakes(r.Stats); n != 1 {
				t.Fatalf("handshake failures %d", n)
			}
		})
	}
}

func TestLeafErrorAddsNoAuto(t *testing.T) {
	srv := tlsServer(t)
	r := newRig(t, srv.Listener.Addr().String())
	r.Roots = poolOf(srv.Certificate())
	r.CA.Load().cert.NotAfter = time.Now().Add(-time.Minute)
	raw, done := r.connect(t.Context(), t, testDest)

	if err := tls.Client(raw, r.clientConfig()).Handshake(); err == nil {
		t.Fatal("handshake passed with an expired CA")
	}
	waitFor(t, done)
	if n := statsHandshakes(r.Stats); n != 1 {
		t.Fatalf("handshake failures %d", n)
	}
	if got := r.Bypass.Auto(time.Now()); len(got) != 0 {
		t.Fatalf("automatic entries %v", got)
	}
}

func TestStalledClientHandshake(t *testing.T) {
	t.Parallel()
	srv := tlsServer(t)
	r := newRig(t, srv.Listener.Addr().String())
	r.Roots = poolOf(srv.Certificate())
	raw, done := r.connect(t.Context(), t, testDest)

	start := time.Now()
	raw.SetDeadline(start.Add(15 * time.Second))
	if _, err := raw.Write(captureHello(t, testName)); err != nil {
		t.Fatal(err)
	}
	// The client never finishes, so this reads until the proxy gives up.
	if _, err := io.Copy(io.Discard, raw); errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	waitFor(t, done)
	if d := time.Since(start); d < 9*time.Second || d > 12*time.Second {
		t.Fatalf("gave up after %v", d)
	}
	if n := statsHandshakes(r.Stats); n != 1 {
		t.Fatalf("handshake failures %d", n)
	}
	if got := r.Bypass.Auto(time.Now()); len(got) != 0 {
		t.Fatalf("automatic entries %v", got)
	}
}

func TestStalledUpstreamHandshake(t *testing.T) {
	t.Parallel()
	srv := tlsServer(t)
	silent := tcpServer(t, func(c *net.TCPConn) { io.Copy(io.Discard, c) })
	r := newRig(t, "")
	r.Roots = poolOf(srv.Certificate())
	var dials atomic.Int64
	r.Dial = func(ctx context.Context, _ Dest) (net.Conn, error) {
		if dials.Add(1) == 1 {
			return r.dial(ctx, silent)
		}
		return r.dial(ctx, srv.Listener.Addr().String())
	}
	raw, _ := r.connect(t.Context(), t, testDest)

	start := time.Now()
	raw.SetDeadline(start.Add(15 * time.Second))
	c := tls.Client(raw, &tls.Config{ServerName: testName, InsecureSkipVerify: true})
	if reply := get(t, c, "/x"); !strings.Contains(reply, "reply to /x") {
		t.Fatalf("reply %q", reply)
	}
	if d := time.Since(start); d < 9*time.Second || d > 12*time.Second {
		t.Fatalf("relayed after %v", d)
	}
	if !c.ConnectionState().PeerCertificates[0].Equal(srv.Certificate()) {
		t.Fatal("client did not see the server's own certificate")
	}
	if n := statsRelayed(r.Stats, "upstream"); n != 1 {
		t.Fatalf("relayed upstream %d", n)
	}
}

func TestHalfCloseKeepsResponse(t *testing.T) {
	// Twice the copy cap: relaying goes on after the copies stop.
	reply := bytes.Repeat([]byte("0123456789abcdef"), 1<<17)
	// This server answers only once it has seen the end of the request.
	addr, roots := tlsEnd(t, func(s *tls.Conn) {
		if _, err := io.ReadAll(s); err == nil {
			s.Write(reply)
		}
	})
	r := newRig(t, addr)
	r.Roots = roots
	raw, _ := r.connect(t.Context(), t, testDest)

	c := tls.Client(raw, r.clientConfig())
	if _, err := c.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := raw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("after %d bytes: %v", len(got), err)
	}
	if !bytes.Equal(got, reply) {
		t.Fatalf("reply of %d bytes, want %d", len(got), len(reply))
	}
	if n := statsInspected(r.Stats); n != 1 {
		t.Fatalf("inspected %d", n)
	}
}

func TestHalfCloseRelayed(t *testing.T) {
	t.Run("client first", func(t *testing.T) {
		reply := bytes.Repeat([]byte("0123456789abcdef"), 1<<14)
		r := newRig(t, tcpServer(t, func(c *net.TCPConn) {
			if _, err := io.ReadAll(c); err == nil {
				c.Write(reply)
			}
		}))
		raw, _ := r.connect(t.Context(), t, Dest{IP: testDest.IP, Port: 25})
		if _, err := raw.Write([]byte("request")); err != nil {
			t.Fatal(err)
		}
		if err := raw.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(raw)
		if err != nil {
			t.Fatalf("after %d bytes: %v", len(got), err)
		}
		if !bytes.Equal(got, reply) {
			t.Fatalf("reply of %d bytes, want %d", len(got), len(reply))
		}
	})
	t.Run("server first", func(t *testing.T) {
		seen := make(chan string, 1)
		r := newRig(t, tcpServer(t, func(c *net.TCPConn) {
			io.WriteString(c, "bye")
			c.CloseWrite()
			late, _ := io.ReadAll(c)
			seen <- string(late)
		}))
		raw, _ := r.connect(t.Context(), t, Dest{IP: testDest.IP, Port: 25})
		got, err := io.ReadAll(raw)
		if err != nil || string(got) != "bye" {
			t.Fatalf("got %q, err %v", got, err)
		}
		if _, err := raw.Write([]byte("late")); err != nil {
			t.Fatal(err)
		}
		if err := raw.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		select {
		case late := <-seen:
			if late != "late" {
				t.Fatalf("server read %q", late)
			}
		case <-time.After(ioWait):
			t.Fatal("server saw no end of stream")
		}
	})
}

// heldServer accepts connections and keeps them open and silent until the test
// ends, whatever the peer does. It reads nothing, like the hostile server this
// limit is for.
func heldServer(t *testing.T) string {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	return tcpServer(t, func(*net.TCPConn) { <-release })
}

func TestIdleLimit(t *testing.T) {
	t.Run("relay", func(t *testing.T) {
		r := newRig(t, echoServer(t, ""))
		r.IdleLimit = 100 * time.Millisecond
		raw, done := r.connect(t.Context(), t, Dest{IP: testDest.IP, Port: 25})
		roundTrip(t, raw)
		ended(t, raw)
		waitFor(t, done)
	})
	t.Run("inspected", func(t *testing.T) {
		addr, roots := tlsEnd(t, func(s *tls.Conn) { io.Copy(s, s) })
		r := newRig(t, addr)
		r.Roots = roots
		r.IdleLimit = 100 * time.Millisecond
		raw, done := r.connect(t.Context(), t, testDest)
		c := tls.Client(raw, r.clientConfig())
		roundTrip(t, c)
		ended(t, raw)
		waitFor(t, done)
		if n := statsInspected(r.Stats); n != 1 {
			t.Fatalf("inspected %d", n)
		}
	})
}

func TestDefaultLimits(t *testing.T) {
	if idleLimit != 10*time.Minute || halfCloseLimit != 60*time.Second {
		t.Fatalf("idle %v, half-close %v", idleLimit, halfCloseLimit)
	}
}

// Bytes in either direction count as activity, so a long download with a silent
// client stays open.
func TestTrafficPutsOffIdleLimit(t *testing.T) {
	const limit, tick = 500 * time.Millisecond, 50 * time.Millisecond
	drip := func(c net.Conn) {
		for range 30 {
			if _, err := c.Write([]byte("x")); err != nil {
				return
			}
			time.Sleep(tick)
		}
	}
	for name, tc := range map[string]struct {
		server func(c *net.TCPConn)
		client func(c net.Conn)
	}{
		"from the server": {
			server: func(c *net.TCPConn) { drip(c) },
			client: func(c net.Conn) {},
		},
		"from the client": {
			server: func(c *net.TCPConn) { io.Copy(io.Discard, c) },
			client: drip,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := newRig(t, tcpServer(t, tc.server))
			r.IdleLimit = limit
			raw, done := r.connect(t.Context(), t, Dest{IP: testDest.IP, Port: 25})
			go tc.client(raw)
			select {
			case <-done:
				t.Fatal("closed with traffic flowing")
			case <-time.After(3 * limit):
			}
		})
	}
}

func TestHalfCloseLimit(t *testing.T) {
	const limit = 200 * time.Millisecond
	// closesAfterLimit checks that Handle keeps the connection for the limit,
	// then closes it although nobody else ever ends it.
	closesAfterLimit := func(t *testing.T, done <-chan struct{}) {
		t.Helper()
		select {
		case <-done:
			t.Fatal("closed before the limit")
		case <-time.After(limit / 2):
		}
		waitFor(t, done)
	}

	t.Run("client ends a relay", func(t *testing.T) {
		r := newRig(t, heldServer(t))
		r.HalfCloseLimit = limit
		raw, done := r.connect(t.Context(), t, Dest{IP: testDest.IP, Port: 25})
		if err := raw.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		closesAfterLimit(t, done)
	})

	t.Run("server ends a relay", func(t *testing.T) {
		r := newRig(t, tcpServer(t, func(c *net.TCPConn) {
			c.CloseWrite()
			time.Sleep(ioWait)
		}))
		r.HalfCloseLimit = limit
		raw, done := r.connect(t.Context(), t, Dest{IP: testDest.IP, Port: 25})
		if n, err := raw.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Fatalf("read %d bytes, err %v", n, err)
		}
		closesAfterLimit(t, done)
	})

	t.Run("client ends an inspected connection", func(t *testing.T) {
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		addr, roots := tlsEnd(t, func(s *tls.Conn) { <-release })
		r := newRig(t, addr)
		r.Roots = roots
		r.HalfCloseLimit = limit
		raw, done := r.connect(t.Context(), t, testDest)
		c := tls.Client(raw, r.clientConfig())
		if err := c.Handshake(); err != nil {
			t.Fatal(err)
		}
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		closesAfterLimit(t, done)
		if n := statsInspected(r.Stats); n != 1 {
			t.Fatalf("inspected %d", n)
		}
	})

	t.Run("traffic does not put it off", func(t *testing.T) {
		r := newRig(t, tcpServer(t, func(c *net.TCPConn) {
			for {
				if _, err := c.Write([]byte("x")); err != nil {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}))
		r.HalfCloseLimit = limit
		raw, done := r.connect(t.Context(), t, Dest{IP: testDest.IP, Port: 25})
		if err := raw.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		go io.Copy(io.Discard, raw)
		closesAfterLimit(t, done)
	})
}

// eofConn records that a read hit the end of the TCP stream. A TLS client gets
// there only if no close_notify came first, which its own Read does not show.
type eofConn struct {
	net.Conn
	eof atomic.Bool
}

func (c *eofConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err == io.EOF {
		c.eof.Store(true)
	}
	return n, err
}

func TestCutStreamStaysCut(t *testing.T) {
	// The server drops TCP in the middle of a record: a truncated reply. The
	// client must not get a close_notify that makes it look complete.
	addr, roots := tlsEnd(t, func(s *tls.Conn) {
		if _, err := s.Read(make([]byte, 16)); err == nil {
			s.Write([]byte("partial"))
			s.NetConn().Write([]byte{23, 3, 3, 0, 100, 1, 2})
			s.NetConn().Close()
		}
	})
	r := newRig(t, addr)
	r.Roots = roots
	raw, _ := r.connect(t.Context(), t, testDest)

	spy := &eofConn{Conn: raw}
	c := tls.Client(spy, r.clientConfig())
	if _, err := c.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(c); string(got) != "partial" || err != nil {
		t.Fatalf("got %q, err %v", got, err)
	}
	if !spy.eof.Load() {
		t.Fatal("a close_notify hid the cut")
	}
}

func TestNon443RelaysWithoutWaiting(t *testing.T) {
	banner := "220 ready\r\n"
	r := newRig(t, echoServer(t, banner))
	raw, _ := r.connect(t.Context(), t, Dest{IP: testDest.IP, Port: 25})

	raw.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if got := readN(t, raw, len(banner)); got != banner {
		t.Fatalf("banner %q", got)
	}
	if n := statsRelayed(r.Stats, "not_443"); n != 1 {
		t.Fatalf("relayed not_443 %d", n)
	}
}

func TestSilentClientOn443(t *testing.T) {
	r := newRig(t, echoServer(t, "banner"))
	r.HelloLimit = 50 * time.Millisecond
	raw, _ := r.connect(t.Context(), t, testDest)

	if got := readN(t, raw, 6); got != "banner" {
		t.Fatalf("banner %q", got)
	}
	if n := statsRelayed(r.Stats, "not_tls"); n != 1 {
		t.Fatalf("relayed not_tls %d", n)
	}
	if _, err := raw.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, raw, 4); got != "ping" {
		t.Fatalf("echo %q", got)
	}
}

func TestPlainBytesOn443Replayed(t *testing.T) {
	r := newRig(t, echoServer(t, ""))
	raw, _ := r.connect(t.Context(), t, testDest)

	msg := "GET / HTTP/1.0\r\n\r\n"
	if _, err := raw.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, raw, len(msg)); got != msg {
		t.Fatalf("echo %q", got)
	}
	if n := statsRelayed(r.Stats, "not_tls"); n != 1 {
		t.Fatalf("relayed not_tls %d", n)
	}
}

func TestHelloLimitDefault(t *testing.T) {
	t.Parallel()
	r := newRig(t, echoServer(t, "banner"))
	raw, _ := r.connect(t.Context(), t, testDest)

	start := time.Now()
	raw.SetDeadline(start.Add(8 * time.Second))
	readN(t, raw, 6)
	if d := time.Since(start); d < 4500*time.Millisecond || d > 6*time.Second {
		t.Fatalf("relayed after %v", d)
	}
}

func TestDialFailure(t *testing.T) {
	r := newRig(t, "")
	r.Dial = func(context.Context, Dest) (net.Conn, error) {
		return nil, errors.New("unreachable")
	}
	raw, done := r.connect(t.Context(), t, testDest)

	if r.waitReady(t) {
		t.Fatal("ready(true) after a failed dial")
	}
	if n, err := raw.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("read %d bytes, err %v", n, err)
	}
	waitFor(t, done)
}

func TestReadyWaitsForDial(t *testing.T) {
	addr := echoServer(t, "")
	r := newRig(t, addr)
	release := make(chan struct{})
	r.Dial = func(ctx context.Context, _ Dest) (net.Conn, error) {
		<-release
		return r.dial(ctx, addr)
	}
	r.connect(t.Context(), t, Dest{IP: testDest.IP, Port: 25})

	select {
	case <-r.ready:
		t.Fatal("ready called before the dial finished")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if !r.waitReady(t) {
		t.Fatal("ready(false) after a good dial")
	}
}

func TestCancelClosesBothSides(t *testing.T) {
	// finish cancels and checks that Handle ends at once, nothing stays open
	// and the client sees the connection go.
	finish := func(t *testing.T, r *rig, raw *net.TCPConn, done <-chan struct{}, cancel context.CancelFunc) {
		t.Helper()
		start := time.Now()
		cancel()
		waitFor(t, done)
		if d := time.Since(start); d > time.Second {
			t.Fatalf("took %v", d)
		}
		if n := r.open.Load(); n != 0 {
			t.Fatalf("%d connections left open", n)
		}
		raw.SetDeadline(time.Now().Add(time.Second))
		if _, err := io.Copy(io.Discard, raw); errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("client side still open")
		}
	}

	t.Run("relay", func(t *testing.T) {
		r := newRig(t, echoServer(t, ""))
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		raw, done := r.connect(ctx, t, Dest{IP: testDest.IP, Port: 25})
		if _, err := raw.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		readN(t, raw, 4)
		finish(t, r, raw, done, cancel)
	})

	t.Run("inspect", func(t *testing.T) {
		addr, roots := tlsEnd(t, func(s *tls.Conn) { io.Copy(s, s) })
		r := newRig(t, addr)
		r.Roots = roots
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		raw, done := r.connect(ctx, t, testDest)
		c := tls.Client(raw, r.clientConfig())
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		readN(t, c, 4)
		finish(t, r, raw, done, cancel)
		_, fromClient, fromServer := collect(t, r.sink)
		if fromClient != "ping" || fromServer != "ping" {
			t.Fatalf("copies %q and %q", fromClient, fromServer)
		}
	})

	t.Run("waiting for hello", func(t *testing.T) {
		r := newRig(t, echoServer(t, ""))
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		raw, done := r.connect(ctx, t, testDest)
		r.waitReady(t)
		finish(t, r, raw, done, cancel)
		if n := statsRelayed(r.Stats, "not_tls"); n != 0 {
			t.Fatalf("relayed not_tls %d", n)
		}
	})

	t.Run("upstream handshake", func(t *testing.T) {
		reached := make(chan struct{}, 1)
		addr := tcpServer(t, func(c *net.TCPConn) {
			c.Read(make([]byte, 1))
			reached <- struct{}{}
			io.Copy(io.Discard, c)
		})
		r := newRig(t, addr)
		var dials atomic.Int64
		r.Dial = func(ctx context.Context, _ Dest) (net.Conn, error) {
			dials.Add(1)
			return r.dial(ctx, addr)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		raw, done := r.connect(ctx, t, testDest)
		if _, err := raw.Write(captureHello(t, testName)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-reached:
		case <-time.After(ioWait):
			t.Fatal("no upstream handshake")
		}
		finish(t, r, raw, done, cancel)
		if n := dials.Load(); n != 1 {
			t.Fatalf("%d dials", n)
		}
		if n := statsRelayed(r.Stats, "upstream"); n != 0 {
			t.Fatalf("relayed upstream %d", n)
		}
	})

	t.Run("client handshake", func(t *testing.T) {
		srv := tlsServer(t)
		r := newRig(t, srv.Listener.Addr().String())
		r.Roots = poolOf(srv.Certificate())
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		raw, done := r.connect(ctx, t, testDest)
		if _, err := raw.Write(captureHello(t, testName)); err != nil {
			t.Fatal(err)
		}
		readN(t, raw, 1) // the proxy answered: the client handshake is running
		finish(t, r, raw, done, cancel)
		if got := r.Bypass.Auto(time.Now()); len(got) != 0 {
			t.Fatalf("automatic entries %v", got)
		}
	})
}
