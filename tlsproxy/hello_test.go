package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

// captureHello returns the first flight a real tls.Client sends.
func captureHello(t testing.TB, serverName string) []byte {
	t.Helper()
	cc, sc := net.Pipe()
	defer sc.Close()
	go func() {
		c := tls.Client(cc, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		_ = c.Handshake()
		cc.Close()
	}()
	buf := make([]byte, 16*1024+5)
	sc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := sc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func TestParseRealHello(t *testing.T) {
	h, err := ParseClientHello(captureHello(t, "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if !h.TLS || h.Name != "example.com" {
		t.Fatalf("got %+v", h)
	}
}

func TestParseNoSNI(t *testing.T) {
	// An IP address as server name makes tls.Client omit the extension.
	h, err := ParseClientHello(captureHello(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if !h.TLS || h.Name != "" {
		t.Fatalf("got %+v", h)
	}
}

func TestParseNotTLS(t *testing.T) {
	h, err := ParseClientHello([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if err != nil || h.TLS || h.Name != "" {
		t.Fatalf("got %+v, %v", h, err)
	}
}

func TestParseNormalisesName(t *testing.T) {
	h, err := ParseClientHello(captureHello(t, "Example.COM."))
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != "example.com" {
		t.Fatalf("got %q", h.Name)
	}
}

func TestParseTruncated(t *testing.T) {
	data := captureHello(t, "example.com")
	for i := 0; i < len(data); i++ {
		h, err := ParseClientHello(data[:i])
		if err != nil && !errors.Is(err, ErrNeedMore) {
			t.Fatalf("prefix %d: unexpected error %v", i, err)
		}
		if err == nil && i > 0 && h.Name != "" {
			t.Fatalf("prefix %d: name from incomplete record", i)
		}
	}
	if _, err := ParseClientHello(data[:len(data)-1]); !errors.Is(err, ErrNeedMore) {
		t.Fatalf("want ErrNeedMore, got %v", err)
	}
}

func TestParseOtherRecords(t *testing.T) {
	// Handshake record that is not a ClientHello, and a hello spanning records.
	h, err := ParseClientHello([]byte{22, 3, 1, 0, 4, 2, 0, 0, 0})
	if err != nil || !h.TLS || h.Name != "" {
		t.Fatalf("got %+v, %v", h, err)
	}
	h, err = ParseClientHello([]byte{22, 3, 1, 0, 4, 1, 0, 1, 0})
	if err != nil || !h.TLS || h.Name != "" {
		t.Fatalf("got %+v, %v", h, err)
	}
	h, err = ParseClientHello([]byte{22, 3, 1, 0xff, 0xff})
	if err != nil || !h.TLS {
		t.Fatalf("oversized record: %+v, %v", h, err)
	}
}

func TestReadHelloConsumesNothing(t *testing.T) {
	data := captureHello(t, "example.com")
	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()
	go func() {
		// Deliver in small pieces to exercise the growing Peek.
		for i := 0; i < len(data); i += 7 {
			end := min(i+7, len(data))
			cc.Write(data[i:end])
		}
	}()
	r := bufio.NewReaderSize(sc, 16*1024+5)
	h := ReadHello(r, sc, 5*time.Second)
	if !h.TLS || h.Name != "example.com" {
		t.Fatalf("got %+v", h)
	}
	got := make([]byte, len(data))
	if _, err := readFull(r, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("reader lost bytes")
	}
}

func readFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func TestReadHelloTimeout(t *testing.T) {
	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()
	r := bufio.NewReaderSize(sc, 16*1024+5)
	if h := ReadHello(r, sc, 100*time.Millisecond); h != (Hello{}) {
		t.Fatalf("silent peer: got %+v", h)
	}
	go cc.Write([]byte{22, 3, 1, 0, 200, 1})
	if h := ReadHello(r, sc, 100*time.Millisecond); h != (Hello{TLS: true}) {
		t.Fatalf("stalled hello: got %+v", h)
	}
}

func FuzzParseClientHello(f *testing.F) {
	f.Add(captureHello(f, "example.com"))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseClientHello(data)
	})
}
