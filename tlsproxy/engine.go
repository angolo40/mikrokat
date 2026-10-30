package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	helloLimit     = 5 * time.Second
	handshakeLimit = 10 * time.Second
	idleLimit      = 10 * time.Minute
	halfCloseLimit = 60 * time.Second
)

// Classify returns why a connection is relayed untouched, or "" to inspect it.
// match is what Bypass.Match said about the name.
func Classify(d Dest, h Hello, match string) string {
	switch {
	case d.Port != 443:
		return "not_443"
	case d.IP.To4() == nil:
		return "ipv6"
	case d.IP.IsPrivate():
		return "private"
	case !h.TLS:
		return "not_tls"
	case h.Name == "":
		return "no_name"
	}
	return match
}

// Engine decides for each connection whether to relay it untouched or to
// inspect it. It never hides an upstream certificate that fails its checks of
// chain, name and dates, and it never changes the bytes it passes on.
type Engine struct {
	CA         *atomic.Pointer[CA]
	Bypass     *Bypass
	Emitter    *Emitter
	Stats      *Stats
	Dial       func(ctx context.Context, d Dest) (net.Conn, error)
	Roots      *x509.CertPool   // nil means the system pool
	HelloLimit time.Duration    // zero means 5 seconds
	Now        func() time.Time // nil means time.Now

	IdleLimit      time.Duration // zero means 10 minutes
	HalfCloseLimit time.Duration // zero means 60 seconds
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Handle serves client until both directions have ended or ctx is cancelled.
// It closes client and every upstream connection before it returns. ready is
// called exactly once, when the first upstream dial has finished.
func (e *Engine) Handle(ctx context.Context, client net.Conn, device net.IP, d Dest, ready func(ok bool)) {
	conns := &connSet{}
	conns.add(client)
	defer conns.close()
	stop := context.AfterFunc(ctx, conns.close)
	defer stop()

	upstream, err := e.Dial(ctx, d)
	if err != nil {
		ready(false)
		return
	}
	conns.add(upstream)
	ready(true)

	br := bufio.NewReaderSize(client, 16*1024+5)
	passThrough := func(reason string, up net.Conn) {
		e.Stats.Relayed(reason)
		e.relay(conns, client, up, br, up)
	}
	if d.Port != 443 {
		passThrough("not_443", upstream)
		return
	}

	limit := e.HelloLimit
	if limit == 0 {
		limit = helloLimit
	}
	h := ReadHello(br, client, limit)
	if ctx.Err() != nil {
		return
	}
	reason := Classify(d, h, e.Bypass.Match(device.String(), h.Name, e.now()))
	if reason == "" && device.To4() == nil {
		reason = "ipv6" // the emitter rebuilds IPv4 only, so no copy could be made
	}
	if reason != "" {
		passThrough(reason, upstream)
		return
	}
	// Before the upstream handshake, while the first connection is still clean:
	// devices keep working through a CA that has run out, uninspected. No
	// client has rejected anything, so this adds no automatic entry.
	leaf, err := e.CA.Load().Leaf(h.Name)
	if err != nil {
		passThrough("ca_expired", upstream)
		return
	}

	toServer := tls.Client(upstream, &tls.Config{
		ServerName: h.Name,
		NextProtos: []string{"http/1.1"},
		RootCAs:    e.Roots,
		MinVersion: tls.VersionTLS12,
		// Only the client can answer this, so it fails the handshake and the
		// original connection is relayed. An empty answer would make the
		// client anonymous, or break the site after inspection has begun.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return nil, errors.New("server asked for a client certificate")
		},
	})
	if err := handshake(ctx, toServer); err != nil {
		upstream.Close()
		if ctx.Err() != nil {
			return
		}
		// The hello was only peeked, so a fresh connection can still get it
		// and the client sees the real server, certificate and all.
		again, err := e.Dial(ctx, d)
		if err != nil {
			return
		}
		conns.add(again)
		passThrough("upstream", again)
		return
	}

	offered := false
	toClient := tls.Server(&bufferedConn{Conn: client, r: br}, &tls.Config{
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: true, // a resumed session would skip the leaf of the current CA
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			offered = true
			return leaf, nil
		},
	})
	if err := handshake(ctx, toClient); err != nil {
		e.Stats.HandshakeFailed()
		var ne net.Error
		timedOut := errors.As(err, &ne) && ne.Timeout()
		// A TLS version or ALPN the proxy refuses ends the handshake before any
		// certificate is chosen, so that client has not rejected ours.
		if offered && !timedOut && ctx.Err() == nil {
			e.Bypass.Failed(device.String(), h.Name, e.now())
		}
		return
	}
	e.Bypass.Completed(device.String(), h.Name, e.now())

	e.Stats.Inspected()
	s := e.Emitter.Open(device, d.IP, remotePort(client))
	defer s.Close()
	e.relay(conns, toClient, toServer,
		io.TeeReader(toClient, copyTo(s.Client)),
		io.TeeReader(toServer, copyTo(s.Server)))
}

// handshake runs the TLS handshake of c, for at most handshakeLimit.
func handshake(ctx context.Context, c *tls.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, handshakeLimit)
	defer cancel()
	return c.HandshakeContext(ctx)
}

func remotePort(c net.Conn) uint16 {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return uint16(a.Port)
	}
	return 0
}

// connSet closes the raw connections of one Handle call together. That also
// stops any TLS handshake running on them.
type connSet struct {
	mu     sync.Mutex
	conns  []net.Conn
	closed bool
}

// add keeps c for close, or closes it at once if the set is already closed.
func (s *connSet) add(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		c.Close()
		return
	}
	s.conns = append(s.conns, c)
}

func (s *connSet) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, c := range s.conns {
		c.Close()
	}
	s.conns = nil
}

// bufferedConn reads through the bufio.Reader that holds the peeked hello.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// copyTo turns a Stream method into the writer of a TeeReader. Copying never
// fails, so it never stops the relay.
type copyTo func(p []byte)

func (f copyTo) Write(p []byte) (int, error) {
	f(p)
	return len(p), nil
}

// closeWriter is the half-close of both *net.TCPConn and *tls.Conn.
type closeWriter interface {
	CloseWrite() error
}

// relay copies both ways, one goroutine per direction, until both have ended.
// Bytes are read from fromClient and fromUpstream and written to the other
// side, which is what gets half-closed. A hostile peer can hold a connection
// open for ever, so a relay with no bytes either way for IdleLimit is closed,
// and so is one still running HalfCloseLimit after the first half-close.
func (e *Engine) relay(conns *connSet, client, upstream net.Conn, fromClient, fromUpstream io.Reader) {
	idle := e.IdleLimit
	if idle == 0 {
		idle = idleLimit
	}
	half := e.HalfCloseLimit
	if half == 0 {
		half = halfCloseLimit
	}
	quiet := time.AfterFunc(idle, conns.close)
	defer quiet.Stop()

	var once sync.Once
	var cut *time.Timer // set once, and read after both pipes have ended
	halfClosed := func() {
		once.Do(func() { cut = time.AfterFunc(half, conns.close) })
	}
	var wg sync.WaitGroup
	wg.Go(func() { pipe(conns, upstream, activeReader{fromClient, quiet, idle}, halfClosed) })
	wg.Go(func() { pipe(conns, client, activeReader{fromUpstream, quiet, idle}, halfClosed) })
	wg.Wait()
	if cut != nil {
		cut.Stop()
	}
}

// activeReader puts off the idle limit each time bytes arrive.
type activeReader struct {
	r     io.Reader
	quiet *time.Timer
	idle  time.Duration
}

func (a activeReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if n > 0 {
		a.quiet.Reset(a.idle)
	}
	return n, err
}

// pipe copies one direction. A clean end is passed on as a half-close, so the
// other direction keeps running. Any other end closes everything: a reset, or
// a TLS stream cut without close_notify, which must not reach the other side
// as a clean end.
func pipe(conns *connSet, dst net.Conn, src io.Reader, halfClosed func()) {
	if _, err := io.Copy(dst, src); err == nil {
		if cw, ok := dst.(closeWriter); ok && cw.CloseWrite() == nil {
			halfClosed()
			return
		}
	}
	conns.close()
}
