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
// inspect it. It never hides a bad upstream certificate and never changes the
// bytes it passes on.
type Engine struct {
	CA         *atomic.Pointer[CA]
	Bypass     *Bypass
	Emitter    *Emitter
	Stats      *Stats
	Dial       func(ctx context.Context, d Dest) (net.Conn, error)
	Roots      *x509.CertPool   // nil means the system pool
	HelloLimit time.Duration    // zero means 5 seconds
	Now        func() time.Time // nil means time.Now
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
		relay(conns, client, up, br, up)
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
	if reason := Classify(d, h, e.Bypass.Match(device.String(), h.Name, e.now())); reason != "" {
		passThrough(reason, upstream)
		return
	}

	toServer := tls.Client(upstream, &tls.Config{
		ServerName: h.Name,
		NextProtos: []string{"http/1.1"},
		RootCAs:    e.Roots,
		MinVersion: tls.VersionTLS12,
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

	var leafErr error
	toClient := tls.Server(&bufferedConn{Conn: client, r: br}, &tls.Config{
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			var cert *tls.Certificate
			cert, leafErr = e.CA.Load().Leaf(h.Name)
			return cert, leafErr
		},
	})
	if err := handshake(ctx, toClient); err != nil {
		e.Stats.HandshakeFailed()
		var ne net.Error
		timedOut := errors.As(err, &ne) && ne.Timeout()
		if leafErr == nil && !timedOut && ctx.Err() == nil {
			e.Bypass.AddAuto(device.String(), h.Name, e.now())
		}
		return
	}

	e.Stats.Inspected()
	s := e.Emitter.Open(device, d.IP, remotePort(client))
	defer s.Close()
	relay(conns, toClient, toServer,
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
// side, which is what gets half-closed.
func relay(conns *connSet, client, upstream net.Conn, fromClient, fromUpstream io.Reader) {
	var wg sync.WaitGroup
	wg.Go(func() { pipe(conns, upstream, fromClient) })
	wg.Go(func() { pipe(conns, client, fromUpstream) })
	wg.Wait()
}

// pipe copies one direction. A clean end is passed on as a half-close, so the
// other direction keeps running. Any other end closes everything: a reset, or
// a TLS stream cut without close_notify, which must not reach the other side
// as a clean end.
func pipe(conns *connSet, dst net.Conn, src io.Reader) {
	if _, err := io.Copy(dst, src); err == nil {
		if cw, ok := dst.(closeWriter); ok && cw.CloseWrite() == nil {
			return
		}
	}
	conns.close()
}
