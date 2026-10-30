package main

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"time"
)

// Hello is what the proxy learns from the first bytes of a connection.
type Hello struct {
	TLS  bool   // the bytes look like a TLS handshake record
	Name string // lower-case server name, without trailing dot; empty if absent
}

// ErrNeedMore means the record is not complete yet.
var ErrNeedMore = errors.New("incomplete TLS record")

const maxRecord = 16 * 1024

// ParseClientHello reads the server name from the first TLS record in data.
// It never panics on any input. Malformed or unsupported TLS yields
// Hello{TLS: true} with no name; a hello spanning several records is not
// reassembled.
func ParseClientHello(data []byte) (Hello, error) {
	if len(data) == 0 {
		return Hello{}, ErrNeedMore
	}
	if data[0] != 22 {
		return Hello{}, nil
	}
	if len(data) >= 2 && data[1] != 3 {
		return Hello{}, nil
	}
	if len(data) < 5 {
		return Hello{}, ErrNeedMore
	}
	rl := int(data[3])<<8 | int(data[4])
	if rl > maxRecord {
		return Hello{TLS: true}, nil
	}
	if len(data) < 5+rl {
		return Hello{}, ErrNeedMore
	}
	tlsHello := Hello{TLS: true}
	body := data[5 : 5+rl]
	if len(body) < 4 || body[0] != 1 {
		return tlsHello, nil
	}
	hl := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if hl > len(body)-4 {
		return tlsHello, nil // continues in another record
	}
	b := body[4 : 4+hl]

	// version (2), random (32), then three length-prefixed fields.
	if len(b) < 34 {
		return tlsHello, nil
	}
	b = b[34:]
	var ok bool
	if b, ok = skip(b, 1); !ok { // session id
		return tlsHello, nil
	}
	if b, ok = skip(b, 2); !ok { // cipher suites
		return tlsHello, nil
	}
	if b, ok = skip(b, 1); !ok { // compression methods
		return tlsHello, nil
	}
	if len(b) < 2 {
		return tlsHello, nil
	}
	el := int(b[0])<<8 | int(b[1])
	if el > len(b)-2 {
		return tlsHello, nil
	}
	exts := b[2 : 2+el]
	for len(exts) >= 4 {
		typ := int(exts[0])<<8 | int(exts[1])
		l := int(exts[2])<<8 | int(exts[3])
		if l > len(exts)-4 {
			return tlsHello, nil
		}
		if typ == 0 {
			tlsHello.Name = serverName(exts[4 : 4+l])
			return tlsHello, nil
		}
		exts = exts[4+l:]
	}
	return tlsHello, nil
}

// skip drops a field with a length prefix of n bytes (1 or 2).
func skip(b []byte, n int) ([]byte, bool) {
	if len(b) < n {
		return nil, false
	}
	l := int(b[0])
	if n == 2 {
		l = l<<8 | int(b[1])
	}
	if l > len(b)-n {
		return nil, false
	}
	return b[n+l:], true
}

// serverName extracts the host_name entry of a server_name extension.
func serverName(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	ll := int(b[0])<<8 | int(b[1])
	if ll > len(b)-2 {
		return ""
	}
	list := b[2 : 2+ll]
	for len(list) >= 3 {
		typ := list[0]
		l := int(list[1])<<8 | int(list[2])
		if l > len(list)-3 {
			return ""
		}
		if typ == 0 {
			return cleanName(string(list[3 : 3+l]))
		}
		list = list[3+l:]
	}
	return ""
}

// cleanName lower-cases the name and drops one trailing dot. Names that are
// empty, too long or hold anything but printable ASCII are rejected.
func cleanName(s string) string {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return ""
		}
	}
	return strings.ToLower(s)
}

// ReadHello peeks at the first TLS record of a connection for up to limit and
// consumes nothing: the bytes stay in r. r must wrap c and its buffer must
// hold a full record, so create it with bufio.NewReaderSize(c, 16*1024+5).
// It returns Hello{} on timeout or read error when no TLS record header was
// seen, and Hello{TLS: true} when the record began as TLS but did not
// complete. The read deadline is cleared before it returns.
func ReadHello(r *bufio.Reader, c net.Conn, limit time.Duration) Hello {
	c.SetReadDeadline(time.Now().Add(limit))
	defer c.SetReadDeadline(time.Time{})
	n := 1
	for {
		if n > r.Size() {
			return Hello{TLS: true}
		}
		b, err := r.Peek(n)
		if err != nil {
			// Peek returns what it could read; judge by that.
			h, perr := ParseClientHello(b)
			if perr != nil {
				h = Hello{TLS: len(b) > 0 && b[0] == 22 && (len(b) < 2 || b[1] == 3)}
			}
			return h
		}
		h, perr := ParseClientHello(b)
		if perr == nil {
			return h
		}
		n = 5
		if len(b) >= 5 {
			n = 5 + (int(b[3])<<8 | int(b[4]))
		}
		if n <= len(b) {
			n = len(b) + 1
		}
	}
}
