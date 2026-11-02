package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

type rawRSA struct {
	Version            int
	N                  *big.Int
	E                  int
	D                  *big.Int
	P, Q, Dp, Dq, Qinv *big.Int
}

// fakeRSA makes a key that is arithmetically consistent but built from odd
// numbers, not primes, so a huge one costs nothing to produce.
func fakeRSA(t *testing.T, bits int) []byte {
	t.Helper()
	e, one := big.NewInt(65537), big.NewInt(1)
	pick := func() *big.Int {
		for {
			b := make([]byte, bits/16)
			rand.Read(b)
			b[0] |= 0xC0
			b[len(b)-1] |= 1
			x := new(big.Int).SetBytes(b)
			if new(big.Int).GCD(nil, nil, e, new(big.Int).Sub(x, one)).Cmp(one) == 0 {
				return x
			}
		}
	}
	for {
		p, q := pick(), pick()
		if new(big.Int).GCD(nil, nil, p, q).Cmp(one) != 0 {
			continue
		}
		pm, qm := new(big.Int).Sub(p, one), new(big.Int).Sub(q, one)
		g := new(big.Int).GCD(nil, nil, pm, qm)
		l := new(big.Int).Div(new(big.Int).Mul(pm, qm), g)
		d := new(big.Int).ModInverse(e, l)
		if d == nil {
			continue
		}
		key := rawRSA{0, new(big.Int).Mul(p, q), 65537, d, p, q,
			new(big.Int).ModInverse(e, pm), new(big.Int).ModInverse(e, qm), new(big.Int).ModInverse(q, p)}
		der, err := asn1.Marshal(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	}
}

func TestOversizedRSAKeyRefused(t *testing.T) {
	start := time.Now()
	_, err := parseOwnKey(fakeRSA(t, 8192+64))
	if err == nil || !strings.Contains(err.Error(), "8192") {
		t.Fatalf("an RSA key over 8192 bits must be refused with the limit in the message, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("refusing took %v", time.Since(start))
	}
}

// exchange swaps two paths in one step, as a process in the app container
// could do between the check and the open.
func exchange(t *testing.T, a, b string) error {
	var nr uintptr
	switch runtime.GOARCH {
	case "amd64":
		nr = 316
	case "arm64":
		nr = 276
	default:
		t.Skip("renameat2 number unknown here")
	}
	pa, _ := syscall.BytePtrFromString(a)
	pb, _ := syscall.BytePtrFromString(b)
	const atFDCWD = ^uintptr(99)
	_, _, e := syscall.Syscall6(nr, atFDCWD, uintptr(unsafe.Pointer(pa)), atFDCWD, uintptr(unsafe.Pointer(pb)), 2, 0)
	if e != 0 {
		return e
	}
	return nil
}

func TestReadOwnFileSwappedForFifo(t *testing.T) {
	dir := t.TempDir()
	file, fifo := filepath.Join(dir, "own-ca.pem"), filepath.Join(dir, "swap")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	swapped := make(chan struct{})
	go func() {
		defer close(swapped)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if exchange(t, fifo, file) != nil {
				return
			}
		}
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20000; i++ {
			readOwnFile(file)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		// release whatever is blocked on a FIFO, so the test can end
		for _, p := range []string{file, fifo} {
			if f, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				f.Close()
			}
		}
		t.Error("readOwnFile hung on a file swapped for a FIFO")
	}
	close(stop)
	<-swapped
}

func TestReadOwnFileRefusesLinkAndHugeFile(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	os.WriteFile(real, []byte("x"), 0o600)
	link := filepath.Join(dir, "link")
	os.Symlink(real, link)
	if _, err := readOwnFile(link); err == nil {
		t.Error("a symbolic link was read")
	}
	huge := filepath.Join(dir, "huge")
	os.WriteFile(huge, make([]byte, ownFileLimit+1), 0o600)
	if _, err := readOwnFile(huge); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("a huge file was read: %v", err)
	}
	if data, err := readOwnFile(real); err != nil || string(data) != "x" {
		t.Errorf("a regular file was not read: %q %v", data, err)
	}
}

// What a device accepted from one CA says nothing about the next: a pinned app
// outside the name constraints of a new CA must still be found.
func TestChangingTheCAForgetsGoodHandshakes(t *testing.T) {
	r := newOwnRig(t)
	r.Apply(r.cfg)
	now := r.Engine.now()
	r.Engine.Bypass.Completed("dev", "site.example", now)
	ca := makeCA(t, "Own CA", ecKey(t, elliptic.P256()), nil)
	r.upload(t, ca.pem, pkcs8(t, ca.key))
	r.Apply(r.cfg)
	r.Engine.Bypass.Failed("dev", "site.example", now)
	r.Engine.Bypass.Failed("dev", "site.example", now.Add(time.Second))
	if got := r.Engine.Bypass.Match("dev", "site.example", now.Add(time.Second)); got != "auto_bypass" {
		t.Fatalf("a handshake with the old CA still counts: %q", got)
	}
}
