package main

import (
	"bytes"
	"net"
	"testing"
)

// rwBuf feeds canned client bytes and records what the server writes.
type rwBuf struct {
	in  *bytes.Reader
	out bytes.Buffer
}

func newRW(client []byte) *rwBuf { return &rwBuf{in: bytes.NewReader(client)} }

func (b *rwBuf) Read(p []byte) (int, error)  { return b.in.Read(p) }
func (b *rwBuf) Write(p []byte) (int, error) { return b.out.Write(p) }

func request(atyp byte, addr []byte, port uint16) []byte {
	b := []byte{5, 1, 0, atyp}
	b = append(b, addr...)
	return append(b, byte(port>>8), byte(port))
}

func TestGreetIPv4(t *testing.T) {
	client := append([]byte{5, 1, 0}, request(1, []byte{198, 51, 100, 7}, 443)...)
	rw := newRW(client)
	d, err := Greet(rw)
	if err != nil {
		t.Fatal(err)
	}
	if !d.IP.Equal(net.ParseIP("198.51.100.7")) || d.Port != 443 || d.Host != "" {
		t.Fatalf("got %+v", d)
	}
	if !bytes.Equal(rw.out.Bytes(), []byte{5, 0}) {
		t.Fatalf("method selection: %v", rw.out.Bytes())
	}
}

func TestGreetDomain(t *testing.T) {
	name := "example.com"
	client := append([]byte{5, 1, 0}, request(3, append([]byte{byte(len(name))}, name...), 443)...)
	d, err := Greet(newRW(client))
	if err != nil {
		t.Fatal(err)
	}
	if d.Host != name || d.IP != nil || d.Port != 443 {
		t.Fatalf("got %+v", d)
	}
}

func TestGreetIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	client := append([]byte{5, 1, 0}, request(4, ip.To16(), 8443)...)
	d, err := Greet(newRW(client))
	if err != nil {
		t.Fatal(err)
	}
	if !d.IP.Equal(ip) || d.Port != 8443 {
		t.Fatalf("got %+v", d)
	}
}

func TestGreetNoAuthOnly(t *testing.T) {
	rw := newRW([]byte{5, 1, 2})
	if _, err := Greet(rw); err == nil {
		t.Fatal("expected error")
	}
	if !bytes.Equal(rw.out.Bytes(), []byte{5, 0xFF}) {
		t.Fatalf("reply: %v", rw.out.Bytes())
	}
}

func TestGreetUDPRefused(t *testing.T) {
	req := request(1, []byte{198, 51, 100, 7}, 53)
	req[1] = 3 // UDP ASSOCIATE
	rw := newRW(append([]byte{5, 1, 0}, req...))
	if _, err := Greet(rw); err == nil {
		t.Fatal("expected error")
	}
	out := rw.out.Bytes()
	if len(out) != 12 || out[2] != 5 || out[3] != ReplyCommandNotSupported {
		t.Fatalf("reply: %v", out)
	}
}

func TestGreetBadInput(t *testing.T) {
	cases := map[string][]byte{
		"empty":           {},
		"wrong version":   {4, 1, 0},
		"zero methods":    {5, 0},
		"empty domain":    append([]byte{5, 1, 0}, request(3, []byte{0}, 80)...),
		"port zero":       append([]byte{5, 1, 0}, request(1, []byte{1, 2, 3, 4}, 0)...),
		"truncated":       append([]byte{5, 1, 0}, 5, 1, 0, 3, 10, 'a'),
		"bad request ver": append([]byte{5, 1, 0}, 4, 1, 0, 1, 1, 2, 3, 4, 0, 80),
	}
	for name, in := range cases {
		if _, err := Greet(newRW(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestGreetBadAddressType(t *testing.T) {
	rw := newRW(append([]byte{5, 1, 0}, 5, 1, 0, 9, 0, 0))
	if _, err := Greet(rw); err == nil {
		t.Fatal("expected error")
	}
	out := rw.out.Bytes()
	if len(out) != 12 || out[3] != ReplyAddressTypeNotSupported {
		t.Fatalf("reply: %v", out)
	}
}

func TestReply(t *testing.T) {
	var b bytes.Buffer
	if err := Reply(&b, ReplyUnreachable); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.Bytes(), []byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("got %v", b.Bytes())
	}
}

func FuzzGreet(f *testing.F) {
	f.Add([]byte{5, 1, 0, 5, 1, 0, 1, 1, 2, 3, 4, 0, 80})
	f.Add([]byte{5, 1, 0, 5, 1, 0, 3, 3, 'a', 'b', 'c', 1, 187})
	f.Add([]byte{5, 2, 2, 0, 5, 3, 0, 4})
	f.Fuzz(func(t *testing.T, in []byte) {
		d, err := Greet(newRW(in))
		if err == nil && (d.Port < 1 || d.Port > 65535 || (d.Host == "") == (d.IP == nil)) {
			t.Fatalf("bad Dest %+v", d)
		}
	})
}
