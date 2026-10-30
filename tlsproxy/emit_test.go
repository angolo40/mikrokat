package main

import (
	"bytes"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

const (
	fHdr   = 18 // Ethernet + 802.1Q tag + ethertype
	tcpAt  = fHdr + 20
	dataAt = tcpAt + 20
)

func ip4(s string) net.IP { return net.ParseIP(s).To4() }

func statsDropped(s *Stats) int64 { s.mu.Lock(); defer s.mu.Unlock(); return s.dropped }
func statsCopied(s *Stats) int64  { s.mu.Lock(); defer s.mu.Unlock(); return s.copied }

// sink is a local UDP socket that stands in for the tzsp container.
type sink struct{ c *net.UDPConn }

func newSink(t *testing.T) *sink {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &sink{c}
}

func (s *sink) addr() string { return s.c.LocalAddr().String() }

// frame returns the next captured Ethernet frame with the TZSP header removed.
func (s *sink) frame(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 65535)
	s.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := s.c.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no frame: %v", err)
	}
	if !bytes.HasPrefix(buf[:n], []byte{1, 0, 0, 1, 1}) {
		t.Fatalf("bad TZSP header % x", buf[:5])
	}
	return append([]byte(nil), buf[5:n]...)
}

func (s *sink) none(t *testing.T) {
	t.Helper()
	buf := make([]byte, 65535)
	s.c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _, err := s.c.ReadFromUDP(buf); err == nil {
		t.Fatalf("unexpected frame of %d bytes", n)
	}
}

func flagsOf(f []byte) byte { return f[tcpAt+13] }
func seqOf(f []byte) uint32 {
	return uint32(f[tcpAt+4])<<24 | uint32(f[tcpAt+5])<<16 | uint32(f[tcpAt+6])<<8 | uint32(f[tcpAt+7])
}
func ackOf(f []byte) uint32 {
	return uint32(f[tcpAt+8])<<24 | uint32(f[tcpAt+9])<<16 | uint32(f[tcpAt+10])<<8 | uint32(f[tcpAt+11])
}
func dstPort(f []byte) int { return int(f[tcpAt+2])<<8 | int(f[tcpAt+3]) }

func startEmitter(t *testing.T, queue int) (*Emitter, *sink, *Stats) {
	t.Helper()
	sk := newSink(t)
	st := NewStats()
	e, err := NewEmitter(sk.addr(), queue, st)
	if err != nil {
		t.Fatal(err)
	}
	go e.Run()
	return e, sk, st
}

func TestFrameLayout(t *testing.T) {
	f := BuildFrame(ip4("10.0.0.1"), ip4("10.0.0.2"), 1234, 80, 7, 9, 0x18, []byte("hello"))
	if f[12] != 0x81 || f[13] != 0x00 {
		t.Fatalf("no 802.1Q tag: % x", f[12:14])
	}
	if got := int(f[14])<<8 | int(f[15]); got != DecryptedVLAN || DecryptedVLAN != 3900 {
		t.Fatalf("vlan %d", got)
	}
	if f[16] != 0x08 || f[17] != 0x00 {
		t.Fatalf("ethertype % x", f[16:18])
	}
	ip := f[fHdr : fHdr+20]
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(ip[i])<<8 | uint32(ip[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	if sum != 0xffff {
		t.Fatalf("IPv4 checksum invalid: %#x", sum)
	}
	if tl := int(ip[2])<<8 | int(ip[3]); tl != 20+20+5 {
		t.Fatalf("total length %d", tl)
	}
	if ip[8] != 64 || ip[9] != 6 || ip[6]&0x40 == 0 {
		t.Fatalf("ttl/proto/DF wrong: % x", ip)
	}
	if dstPort(f) != 80 || seqOf(f) != 7 || ackOf(f) != 9 || flagsOf(f) != 0x18 {
		t.Fatal("tcp fields wrong")
	}
	if string(f[dataAt:]) != "hello" {
		t.Fatal("payload wrong")
	}
}

func TestTZSPHeader(t *testing.T) {
	f := []byte{1, 2, 3, 4}
	w := WrapTZSP(f)
	if !bytes.Equal(w, []byte{1, 0, 0, 1, 1, 1, 2, 3, 4}) {
		t.Fatalf("% x", w)
	}
}

func TestConversation(t *testing.T) {
	e, sk, _ := startEmitter(t, 1<<20)
	s := e.Open(ip4("10.0.0.1"), ip4("93.184.216.34"), 40000)

	syn, synack, ack := sk.frame(t), sk.frame(t), sk.frame(t)
	if flagsOf(syn) != 0x02 || flagsOf(synack) != 0x12 || flagsOf(ack) != 0x10 {
		t.Fatalf("handshake flags %#x %#x %#x", flagsOf(syn), flagsOf(synack), flagsOf(ack))
	}
	cISN, sISN := seqOf(syn), seqOf(synack)
	if ackOf(synack) != cISN+1 || seqOf(ack) != cISN+1 || ackOf(ack) != sISN+1 {
		t.Fatal("handshake numbers wrong")
	}
	if dstPort(syn) != 80 {
		t.Fatal("destination port not 80")
	}

	s.Client([]byte("GET"))
	d, a := sk.frame(t), sk.frame(t)
	if flagsOf(d) != 0x18 || seqOf(d) != cISN+1 || ackOf(d) != sISN+1 || string(d[dataAt:]) != "GET" {
		t.Fatalf("client data wrong: flags %#x", flagsOf(d))
	}
	if flagsOf(a) != 0x10 || seqOf(a) != sISN+1 || ackOf(a) != cISN+4 {
		t.Fatal("server ack wrong")
	}

	s.Server([]byte("OK"))
	d, a = sk.frame(t), sk.frame(t)
	if flagsOf(d) != 0x18 || seqOf(d) != sISN+1 || ackOf(d) != cISN+4 || string(d[dataAt:]) != "OK" {
		t.Fatal("server data wrong")
	}
	if flagsOf(a) != 0x10 || seqOf(a) != cISN+4 || ackOf(a) != sISN+3 {
		t.Fatal("client ack wrong")
	}

	s.Close()
	f1, f2, f3 := sk.frame(t), sk.frame(t), sk.frame(t)
	if flagsOf(f1)&1 == 0 || flagsOf(f2)&1 == 0 || flagsOf(f3) != 0x10 {
		t.Fatalf("close flags %#x %#x %#x", flagsOf(f1), flagsOf(f2), flagsOf(f3))
	}
	if !bytes.Equal(f1[0:6], f3[0:6]) || bytes.Equal(f1[0:6], f2[0:6]) {
		t.Fatal("FIN directions wrong")
	}
	s.Close()
	sk.none(t)
}

func TestSegments(t *testing.T) {
	e, sk, _ := startEmitter(t, 1<<20)
	s := e.Open(ip4("10.0.0.1"), ip4("10.0.0.2"), 40000)
	for i := 0; i < 3; i++ {
		sk.frame(t)
	}
	s.Client(make([]byte, 4000))
	var sizes []int
	for i := 0; i < 6; i++ {
		f := sk.frame(t)
		if len(f) > dataAt {
			sizes = append(sizes, len(f)-dataAt)
		}
	}
	if len(sizes) != 3 || sizes[0] != 1460 || sizes[1] != 1460 || sizes[2] != 1080 {
		t.Fatalf("segments %v", sizes)
	}
}

func TestCopyCap(t *testing.T) {
	e, sk, st := startEmitter(t, 64<<20)
	var fins atomic.Int32
	go func() { // drain while the data flows, the socket buffer is small
		buf := make([]byte, 65535)
		for {
			n, _, err := sk.c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n > 5+tcpAt+13 && buf[5+tcpAt+13]&1 != 0 {
				fins.Add(1)
			}
		}
	}()
	s := e.Open(ip4("10.0.0.1"), ip4("10.0.0.2"), 40000)
	chunk := make([]byte, 64<<10)
	for i := 0; i < 32; i++ { // 2 MiB
		s.Client(chunk)
	}
	if c := statsCopied(st); c > 1<<20 || c == 0 {
		t.Fatalf("copied %d", c)
	}
	s.Close()
	deadline := time.Now().Add(10 * time.Second)
	for fins.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if fins.Load() != 2 {
		t.Fatalf("saw %d FINs", fins.Load())
	}
}

func TestQueueFullDrops(t *testing.T) {
	sk := newSink(t)
	st := NewStats()
	e, err := NewEmitter(sk.addr(), 100, st) // no Run
	if err != nil {
		t.Fatal(err)
	}
	s := e.Open(ip4("10.0.0.1"), ip4("10.0.0.2"), 40000)
	start := time.Now()
	s.Client(make([]byte, 5000))
	s.Server([]byte("x"))
	s.Close()
	if time.Since(start) > time.Second {
		t.Fatal("blocked")
	}
	if statsDropped(st) == 0 {
		t.Fatal("no drops counted")
	}
}

func TestSendErrorsDoNotStop(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := c.LocalAddr().String()
	c.Close() // nothing listens any more
	st := NewStats()
	e, err := NewEmitter(addr, 1<<20, st)
	if err != nil {
		t.Fatal(err)
	}
	go e.Run()
	s := e.Open(ip4("10.0.0.1"), ip4("10.0.0.2"), 40000)
	deadline := time.Now().Add(3 * time.Second)
	for statsDropped(st) == 0 && time.Now().Before(deadline) {
		s.Client([]byte("x"))
		time.Sleep(10 * time.Millisecond)
	}
	if statsDropped(st) == 0 {
		t.Fatal("send errors not counted")
	}
	before := statsDropped(st)
	for i := 0; i < 20 && statsDropped(st) == before; i++ {
		s.Client([]byte("y"))
		time.Sleep(20 * time.Millisecond)
	}
	if statsDropped(st) == before {
		t.Fatal("Run stopped after an error")
	}
}
