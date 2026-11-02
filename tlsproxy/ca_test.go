package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sameKey(a, b *CA) bool {
	return a.key.Public().(*ecdsa.PublicKey).Equal(b.key.Public())
}

func TestCreateThenReload(t *testing.T) {
	priv, state := t.TempDir(), t.TempDir()
	a, err := LoadCA(priv, state, 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadCA(priv, state, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !sameKey(a, b) {
		t.Fatal("reload changed the key")
	}
	st, err := os.Stat(filepath.Join(priv, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("ca.key mode %v", st.Mode().Perm())
	}
	st, err = os.Stat(filepath.Join(state, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("ca.pem mode %v", st.Mode().Perm())
	}
}

func TestGenerationReplaces(t *testing.T) {
	priv, state := t.TempDir(), t.TempDir()
	a, err := LoadCA(priv, state, 1)
	if err != nil {
		t.Fatal(err)
	}
	pem1, _ := os.ReadFile(filepath.Join(state, "ca.pem"))
	b, err := LoadCA(priv, state, 2)
	if err != nil {
		t.Fatal(err)
	}
	pem2, _ := os.ReadFile(filepath.Join(state, "ca.pem"))
	if sameKey(a, b) {
		t.Fatal("generation 2 kept the key")
	}
	if string(pem1) == string(pem2) {
		t.Fatal("ca.pem not replaced")
	}
}

func TestCorruptKeyRecreated(t *testing.T) {
	priv, state := t.TempDir(), t.TempDir()
	if _, err := LoadCA(priv, state, 1); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(priv, "ca.key"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(priv, state, 1); err != nil {
		t.Fatal(err)
	}
}

func TestLeafVerifies(t *testing.T) {
	priv, state := t.TempDir(), t.TempDir()
	ca, err := LoadCA(priv, state, 1)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(state, "ca.pem"))
	block, _ := pem.Decode(data)
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := c.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: pool}); err != nil {
		t.Fatal(err)
	}
	pk, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || pk.Curve != elliptic.P256() {
		t.Fatal("leaf is not ECDSA P-256")
	}
	if d := time.Until(c.NotAfter); d > 30*24*time.Hour || d < 29*24*time.Hour {
		t.Fatalf("NotAfter in %v", d)
	}
}

func TestLeafIP(t *testing.T) {
	ca, err := LoadCA(t.TempDir(), t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(leaf.Certificate[0])
	if len(c.IPAddresses) != 1 || len(c.DNSNames) != 0 {
		t.Fatalf("ips %v dns %v", c.IPAddresses, c.DNSNames)
	}
}

func TestLeafCached(t *testing.T) {
	ca, err := LoadCA(t.TempDir(), t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := ca.Leaf("example.com")
	b, _ := ca.Leaf("example.com")
	if a != b {
		t.Fatal("not cached")
	}
}

func TestLeafEmptyName(t *testing.T) {
	ca, err := LoadCA(t.TempDir(), t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Leaf(""); err == nil {
		t.Fatal("empty name accepted")
	}
}

func TestLeafLongName(t *testing.T) {
	ca, err := LoadCA(t.TempDir(), t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Leaf(strings.Repeat("a", 300)); err == nil {
		t.Fatal("long name accepted")
	}
}

func TestLeafConcurrent(t *testing.T) {
	ca, err := LoadCA(t.TempDir(), t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 5; j++ {
				if _, err := ca.Leaf("example.com"); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

// captureLog returns what the log package wrote until the test ends.
func captureLog(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// writeTestCA stores a CA valid until notAfter, as a previous run would have.
func writeTestCA(t *testing.T, priv, state string, generation int, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Mikrokat local CA"},
		NotBefore:             notAfter.Add(-2 * 365 * 24 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{filepath.Join(priv, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600},
		{filepath.Join(priv, "generation"), []byte(strconv.Itoa(generation) + "\n"), 0o600},
		{filepath.Join(state, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644},
	} {
		if err := os.WriteFile(f.path, f.data, f.mode); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWideKeyModeTightened(t *testing.T) {
	priv, state := t.TempDir(), t.TempDir()
	a, err := LoadCA(priv, state, 1)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(priv, "ca.key")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	buf := captureLog(t)
	b, err := LoadCA(priv, state, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !sameKey(a, b) {
		t.Fatal("pair was replaced")
	}
	st, _ := os.Stat(keyPath)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	if !strings.Contains(buf.String(), "ca.key mode was 0644, tightened to 600") {
		t.Fatalf("log %q", buf.String())
	}
}

func TestLeafClampedToCA(t *testing.T) {
	priv, state := t.TempDir(), t.TempDir()
	end := time.Now().Add(10 * 24 * time.Hour)
	writeTestCA(t, priv, state, 1, end)
	ca, err := LoadCA(priv, state, 1)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Leaf.NotAfter.After(ca.cert.NotAfter) {
		t.Fatalf("leaf %v outlives CA %v", leaf.Leaf.NotAfter, ca.cert.NotAfter)
	}
}

func TestLeafAfterCAExpiry(t *testing.T) {
	ca, err := LoadCA(t.TempDir(), t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Leaf("example.com"); err != nil {
		t.Fatal(err)
	}
	ca.cert.NotAfter = time.Now().Add(-time.Minute)
	if _, err := ca.Leaf("example.com"); err == nil {
		t.Fatal("cached leaf served after CA expiry")
	}
	if _, err := ca.Leaf("other.example"); err == nil {
		t.Fatal("new leaf signed after CA expiry")
	}
}

func TestExpiredCAReplaced(t *testing.T) {
	priv, state := t.TempDir(), t.TempDir()
	writeTestCA(t, priv, state, 1, time.Now().Add(-time.Hour))
	buf := captureLog(t)
	ca, err := LoadCA(priv, state, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.cert.NotAfter.After(time.Now()) {
		t.Fatal("expired CA kept")
	}
	if !strings.Contains(buf.String(), "replacing CA: CA certificate has expired") {
		t.Fatalf("log %q", buf.String())
	}
}

func TestReplacementLogged(t *testing.T) {
	priv, state := t.TempDir(), t.TempDir()
	buf := captureLog(t)
	if _, err := LoadCA(priv, state, 1); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("first run logged %q", buf.String())
	}
	if _, err := LoadCA(priv, state, 2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "replacing CA: generation changed from 1 to 2") {
		t.Fatalf("log %q", buf.String())
	}
}

func TestPrivateDirTightened(t *testing.T) {
	priv := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(priv, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(priv, 0o755); err != nil { // whatever the umask left
		t.Fatal(err)
	}
	if _, err := LoadCA(priv, t.TempDir(), 1); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(priv)
	if err != nil {
		t.Fatal(err)
	}
	if m := st.Mode().Perm(); m != 0o700 {
		t.Fatalf("mode %04o", m)
	}
}
