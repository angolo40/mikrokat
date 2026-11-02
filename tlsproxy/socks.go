package main

import (
	"errors"
	"fmt"
	"io"
	"net"
)

// SOCKS5 reply codes (RFC 1928).
const (
	ReplyOK                      = 0
	ReplyNotAllowed              = 2
	ReplyUnreachable             = 4
	ReplyCommandNotSupported     = 7
	ReplyAddressTypeNotSupported = 8
)

// Dest is where the client asked to connect. Exactly one of Host and IP is set.
// Host is stored as sent; the caller resolves it, and keeps the name in Name
// for the connection log.
type Dest struct {
	Host string
	IP   net.IP
	Port int
	Name string
}

// Greet runs the SOCKS5 handshake up to the request. It offers only "no
// authentication" and accepts only CONNECT. It sends the method selection
// and, for an unsupported command or address type, the refusal. It sends no
// success reply: the caller does that once the upstream connection is open.
func Greet(rw io.ReadWriter) (Dest, error) {
	var head [4]byte
	if _, err := io.ReadFull(rw, head[:2]); err != nil {
		return Dest{}, err
	}
	if head[0] != 5 {
		return Dest{}, fmt.Errorf("socks version %d", head[0])
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(rw, methods); err != nil {
		return Dest{}, err
	}
	noAuth := false
	for _, m := range methods {
		if m == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		rw.Write([]byte{5, 0xFF})
		return Dest{}, errors.New("client offers no unauthenticated method")
	}
	if _, err := rw.Write([]byte{5, 0}); err != nil {
		return Dest{}, err
	}

	if _, err := io.ReadFull(rw, head[:]); err != nil {
		return Dest{}, err
	}
	if head[0] != 5 {
		return Dest{}, fmt.Errorf("socks request version %d", head[0])
	}
	if head[1] != 1 {
		Reply(rw, ReplyCommandNotSupported)
		return Dest{}, fmt.Errorf("socks command %d not supported", head[1])
	}

	var d Dest
	switch head[3] {
	case 1, 4:
		ip := make(net.IP, 4)
		if head[3] == 4 {
			ip = make(net.IP, 16)
		}
		if _, err := io.ReadFull(rw, ip); err != nil {
			return Dest{}, err
		}
		d.IP = ip
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(rw, n[:]); err != nil {
			return Dest{}, err
		}
		if n[0] == 0 {
			return Dest{}, errors.New("empty domain name")
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(rw, name); err != nil {
			return Dest{}, err
		}
		d.Host = string(name)
	default:
		Reply(rw, ReplyAddressTypeNotSupported)
		return Dest{}, fmt.Errorf("socks address type %d not supported", head[3])
	}

	var port [2]byte
	if _, err := io.ReadFull(rw, port[:]); err != nil {
		return Dest{}, err
	}
	d.Port = int(port[0])<<8 | int(port[1])
	if d.Port == 0 {
		return Dest{}, errors.New("port 0")
	}
	return d, nil
}

// Reply sends a SOCKS5 reply with the given code and a zero bound address.
func Reply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}
