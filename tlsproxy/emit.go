package main

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// DecryptedVLAN tags rebuilt traffic so Suricata rules can tell it apart
// from the real traffic. The tag goes in the frame; the destination port
// stays 80.
const DecryptedVLAN = 3900

const (
	maxSegment = 1460
	copyCap    = 1 << 20 // bytes copied per direction per connection

	// Run sends this much, then pauses. UDP has no backpressure: what tzsp
	// cannot read in time is dropped by the kernel, nothing counts it, and
	// Suricata cannot use a stream with a gap. On the 4-core test host 64 KiB
	// lost frames with every core busy, and 32 KiB sometimes did with the
	// queue full as well. It works out at about 10 MB/s.
	paceBytes = 16 << 10
	pacePause = time.Millisecond

	flagFIN = 0x01
	flagSYN = 0x02
	flagPSH = 0x08
	flagACK = 0x10
)

var (
	clientMAC = []byte{0x02, 0x4d, 0x4b, 0x00, 0x00, 0x01}
	serverMAC = []byte{0x02, 0x4d, 0x4b, 0x00, 0x00, 0x02}
)

// BuildFrame returns an Ethernet frame with an 802.1Q tag, IPv4 and TCP
// headers and the payload. TCP checksums stay zero: Suricata runs with
// checksum validation off.
func BuildFrame(src, dst net.IP, sport, dport uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	f := make([]byte, 18+20+20+len(payload))
	// Traffic to port 80 comes from the client, the rest from the server.
	if dport == 80 {
		copy(f[0:6], serverMAC)
		copy(f[6:12], clientMAC)
	} else {
		copy(f[0:6], clientMAC)
		copy(f[6:12], serverMAC)
	}
	binary.BigEndian.PutUint16(f[12:], 0x8100)
	binary.BigEndian.PutUint16(f[14:], DecryptedVLAN)
	binary.BigEndian.PutUint16(f[16:], 0x0800)

	ip := f[18:38]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(40+len(payload)))
	binary.BigEndian.PutUint16(ip[4:], uint16(seq)^uint16(sport))
	ip[6] = 0x40 // DF
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(ip[10:], ^uint16(sum))

	tcp := f[38:58]
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	copy(f[58:], payload)
	return f
}

// WrapTZSP prepends the TZSP header: version 1, type 0, protocol 0x0001,
// then the end tag.
func WrapTZSP(frame []byte) []byte {
	return append([]byte{1, 0, 0, 1, 1}, frame...)
}

// Emitter queues rebuilt frames and sends them as TZSP over UDP. One Run
// goroutine owns the socket, so frames keep their order.
type Emitter struct {
	conn  *net.UDPConn
	stats *Stats
	max   int

	mu    sync.Mutex
	queue [][]byte
	bytes int
	wake  chan struct{}
}

func NewEmitter(addr string, queueBytes int, stats *Stats) (*Emitter, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		return nil, err
	}
	return &Emitter{conn: c, stats: stats, max: queueBytes, wake: make(chan struct{}, 1)}, nil
}

// enqueue never blocks on the network. It reports false when the frame did
// not fit and was dropped.
func (e *Emitter) enqueue(frame []byte) bool {
	pkt := WrapTZSP(frame)
	e.mu.Lock()
	if e.bytes+len(pkt) > e.max {
		e.mu.Unlock()
		e.stats.CopyDropped()
		return false
	}
	e.queue = append(e.queue, pkt)
	e.bytes += len(pkt)
	e.mu.Unlock()
	select {
	case e.wake <- struct{}{}:
	default:
	}
	return true
}

// Run sends queued frames until the process exits, at a pace tzsp can follow.
// A send error counts as a drop and the loop goes on.
func (e *Emitter) Run() {
	sent := 0
	for {
		e.mu.Lock()
		if len(e.queue) == 0 {
			e.mu.Unlock()
			<-e.wake
			continue
		}
		pkt := e.queue[0]
		e.queue[0] = nil
		e.queue = e.queue[1:]
		e.bytes -= len(pkt)
		e.mu.Unlock()
		if _, err := e.conn.Write(pkt); err != nil {
			e.stats.CopyDropped()
		}
		if sent += len(pkt); sent >= paceBytes {
			sent = 0
			time.Sleep(pacePause)
		}
	}
}

// Stream is one rebuilt TCP conversation. Safe to call from two goroutines.
type Stream struct {
	e          *Emitter
	client     net.IP
	server     net.IP
	cport      uint16
	mu         sync.Mutex
	cseq, sseq uint32
	cn, sn     int // payload bytes copied per direction
	broken     bool
	closed     bool
	noop       bool
}

// Open emits the three-way handshake. A non-IPv4 address gives a stream that
// does nothing.
func (e *Emitter) Open(client, server net.IP, clientPort uint16) *Stream {
	s := &Stream{e: e, client: client.To4(), server: server.To4(), cport: clientPort}
	if s.client == nil || s.server == nil {
		s.noop = true
		return s
	}
	var b [8]byte
	rand.Read(b[:])
	s.cseq = binary.BigEndian.Uint32(b[:4])
	s.sseq = binary.BigEndian.Uint32(b[4:])
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fromClient(s.cseq, 0, flagSYN, nil)
	s.cseq++
	s.fromServer(s.sseq, s.cseq, flagSYN|flagACK, nil)
	s.sseq++
	s.fromClient(s.cseq, s.sseq, flagACK, nil)
	return s
}

// send enqueues one frame and marks the stream broken if it was dropped.
// The caller holds s.mu.
func (s *Stream) send(f []byte) {
	if s.broken {
		return
	}
	if !s.e.enqueue(f) {
		s.broken = true
	}
}

func (s *Stream) fromClient(seq, ack uint32, flags byte, p []byte) {
	s.send(BuildFrame(s.client, s.server, s.cport, 80, seq, ack, flags, p))
}

func (s *Stream) fromServer(seq, ack uint32, flags byte, p []byte) {
	s.send(BuildFrame(s.server, s.client, 80, s.cport, seq, ack, flags, p))
}

// Client emits bytes sent by the client, each segment followed by the
// server's ACK. Suricata only inspects acknowledged data.
func (s *Stream) Client(p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.noop || s.closed || s.broken {
		return
	}
	for len(p) > 0 && s.cn < copyCap && !s.broken {
		n := min(len(p), maxSegment, copyCap-s.cn)
		s.fromClient(s.cseq, s.sseq, flagPSH|flagACK, p[:n])
		if s.broken {
			return
		}
		s.cseq += uint32(n)
		s.cn += n
		s.e.stats.Copied(n)
		s.fromServer(s.sseq, s.cseq, flagACK, nil)
		p = p[n:]
	}
}

// Server emits bytes sent by the server, each segment followed by the
// client's ACK.
func (s *Stream) Server(p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.noop || s.closed || s.broken {
		return
	}
	for len(p) > 0 && s.sn < copyCap && !s.broken {
		n := min(len(p), maxSegment, copyCap-s.sn)
		s.fromServer(s.sseq, s.cseq, flagPSH|flagACK, p[:n])
		if s.broken {
			return
		}
		s.sseq += uint32(n)
		s.sn += n
		s.e.stats.Copied(n)
		s.fromClient(s.cseq, s.sseq, flagACK, nil)
		p = p[n:]
	}
}

// Close emits FIN both ways and the last ACK. Calling it twice is safe.
func (s *Stream) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.noop || s.closed {
		return
	}
	s.closed = true
	s.fromClient(s.cseq, s.sseq, flagFIN|flagACK, nil)
	s.cseq++
	s.fromServer(s.sseq, s.cseq, flagFIN|flagACK, nil)
	s.sseq++
	s.fromClient(s.cseq, s.sseq, flagACK, nil)
}
