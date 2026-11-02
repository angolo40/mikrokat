package main

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testCA is a certificate authority made for one test.
type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
	pem  []byte
}

var rsaOnce = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

func ecKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func edKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// makeCA signs a CA with parent, or with itself when parent is nil. Each change
// edits the template, so a test can spoil exactly one thing.
func makeCA(t *testing.T, name string, key crypto.Signer, parent *testCA, change ...func(*x509.Certificate)) *testCA {
	t.Helper()
	serial, err := randomSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, c := range change {
		c(tmpl)
	}
	issuer, signer := tmpl, key
	if parent != nil {
		issuer, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func pkcs8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func pkcs1(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func sec1(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// newOwnRig is a proxy with a real HTTPS server behind it and an incoming folder.
func newOwnRig(t *testing.T) *socksRig {
	t.Helper()
	srv := tlsServer(t)
	r := newSocksRig(t, srv.Listener.Addr().String())
	r.Engine.Roots = poolOf(srv.Certificate())
	r.IncomingDir = t.TempDir()
	return r
}

func (r *socksRig) upload(t *testing.T, cert, key []byte) {
	t.Helper()
	for name, data := range map[string][]byte{"own-ca.key": key, "own-ca.pem": cert} {
		if err := os.WriteFile(filepath.Join(r.IncomingDir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// requestRemoval is what the Stop using my CA button leaves for the proxy.
func (r *socksRig) requestRemoval(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(r.IncomingDir, "remove-own-ca"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// visit opens a TLS connection through the proxy, trusting only roots, fetches a
// page and returns what the client saw.
func (r *socksRig) visit(t *testing.T, roots *x509.CertPool) tls.ConnectionState {
	t.Helper()
	c := r.open(t, "127.0.0.1")
	if code := socksConnect(t, c, 1, []byte{198, 51, 100, 7}, 443); code != ReplyOK {
		t.Fatalf("reply code %d", code)
	}
	client := tls.Client(c, &tls.Config{ServerName: testName, RootCAs: roots})
	if reply := get(t, client, "/x"); !strings.Contains(reply, "reply to /x") {
		t.Fatalf("reply %q", reply)
	}
	return client.ConnectionState()
}

// stat returns what the proxy reports, read back from a real stats.json.
func (r *socksRig) stat(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stats.json")
	if err := r.Engine.Stats.WriteFile(path, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// snapshot reads every file below the private and state folders, stats aside.
func (r *socksRig) snapshot(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, dir := range []string{r.PrivateDir, r.StateDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			out[e.Name()] = string(raw)
		}
	}
	return out
}

func sameFiles(t *testing.T, want, got map[string]string) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("files changed: had %d, now %d", len(want), len(got))
	}
	for name, content := range want {
		if got[name] != content {
			t.Fatalf("%s changed", name)
		}
	}
}

func incomingEmpty(t *testing.T, r *socksRig) {
	t.Helper()
	entries, err := os.ReadDir(r.IncomingDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("incoming still holds %s", entries[0].Name())
	}
}

func onDisk(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	return err == nil
}

func TestOwnCATable(t *testing.T) {
	ec := ecKey(t, elliptic.P256())
	p384 := ecKey(t, elliptic.P384())
	ed := edKey(t)
	params := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}})
	for _, c := range []struct {
		name string
		key  crypto.Signer
		pem  []byte
	}{
		{"rsa pkcs8", rsaOnce(), pkcs8(t, rsaOnce())},
		{"rsa pkcs1", rsaOnce(), pkcs1(rsaOnce())},
		{"ecdsa pkcs8", ec, pkcs8(t, ec)},
		{"ecdsa sec1", ec, sec1(t, ec)},
		{"ecdsa p384 sec1", p384, sec1(t, p384)},
		// What openssl ecparam -genkey writes: the parameters come first.
		{"ecdsa sec1 after parameters", ec, append(append([]byte{}, params...), sec1(t, ec)...)},
		{"ed25519 pkcs8", ed, pkcs8(t, ed)},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newOwnRig(t)
			ca := makeCA(t, "Own test CA", c.key, nil)
			r.upload(t, ca.pem, c.pem)
			r.Apply(r.cfg)
			if reason := r.stat(t)["ca_import_error"]; reason != "" {
				t.Fatalf("refused: %v", reason)
			}
			st := r.visit(t, poolOf(ca.cert))
			if !st.PeerCertificates[1].Equal(ca.cert) {
				t.Fatal("the chain was not served after the leaf")
			}
			pub, ok := st.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
			if !ok || pub.Curve != elliptic.P256() {
				t.Fatalf("leaf key %T", st.PeerCertificates[0].PublicKey)
			}
			if n := statsInspected(r.Engine.Stats); n != 1 {
				t.Fatalf("inspected %d", n)
			}
			m := r.stat(t)
			if m["ca_own"] != true || m["ca_subject"] != "CN=Own test CA" || m["ca_chain"] != float64(1) {
				t.Fatalf("stats %v", m)
			}
			if m["ca_expires"] != float64(ca.cert.NotAfter.Unix()) {
				t.Fatalf("ca_expires %v, want %d", m["ca_expires"], ca.cert.NotAfter.Unix())
			}
			incomingEmpty(t, r)
		})
	}
}

func TestOwnCAIntermediate(t *testing.T) {
	r := newOwnRig(t)
	root := makeCA(t, "Own root", ecKey(t, elliptic.P256()), nil)
	middle := makeCA(t, "Own middle", ecKey(t, elliptic.P256()), root)
	signing := makeCA(t, "Own signing", ecKey(t, elliptic.P256()), middle)
	chain := bytes.Join([][]byte{signing.pem, middle.pem, root.pem}, nil)
	r.upload(t, chain, pkcs8(t, signing.key))
	r.Apply(r.cfg)

	st := r.visit(t, poolOf(root.cert))
	if n := len(st.PeerCertificates); n != 4 {
		t.Fatalf("%d certificates served, want the leaf and the three of the chain", n)
	}
	if len(st.VerifiedChains) == 0 || len(st.VerifiedChains[0]) != 4 {
		t.Fatalf("verified chains %v", st.VerifiedChains)
	}
	if got := readPEM(t, r); got != string(chain) {
		t.Fatalf("state/ca.pem does not hold the chain: %q", got)
	}
	if n := r.stat(t)["ca_chain"]; n != float64(3) {
		t.Fatalf("ca_chain %v", n)
	}
}

// A client that trusts the first certificate alone needs nothing else served.
func TestOwnCAIntermediateWithoutRoot(t *testing.T) {
	r := newOwnRig(t)
	root := makeCA(t, "Own root", ecKey(t, elliptic.P256()), nil)
	signing := makeCA(t, "Own signing", ecKey(t, elliptic.P256()), root)
	r.upload(t, signing.pem, pkcs8(t, signing.key))
	r.Apply(r.cfg)
	r.visit(t, poolOf(root.cert))
}

// pfx is the start of a PKCS#12 file: a SEQUENCE with version 3.
func pfx(t *testing.T) []byte {
	t.Helper()
	der, err := asn1.Marshal(struct {
		Version int
		Data    []byte
	}{3, []byte("not really a store of certificates")})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestImportRefused(t *testing.T) {
	good := ecKey(t, elliptic.P256())
	goodCA := makeCA(t, "Good CA", good, nil)
	goodKey := pkcs8(t, good)
	spoiled := func(change func(*x509.Certificate)) []byte {
		return makeCA(t, "Spoiled CA", good, nil, change).pem
	}
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expiredRoot := makeCA(t, "Old root", ecKey(t, elliptic.P256()), nil, func(c *x509.Certificate) {
		c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)
	})
	underOld := makeCA(t, "Under old root", good, expiredRoot)
	root0 := makeCA(t, "Root without room", ecKey(t, elliptic.P256()), nil, func(c *x509.Certificate) {
		c.MaxPathLen, c.MaxPathLenZero = 0, true
	})
	underRoot0 := makeCA(t, "Under root without room", good, root0)
	stranger := makeCA(t, "Stranger", ecKey(t, elliptic.P256()), nil)
	clientOnly := makeCA(t, "Client only", good, nil, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	})
	// Go reads an RSA key this small but will not sign with it, so only a real
	// signature finds out. It takes a setting to make one, for this subtest only.
	var weak *testCA
	t.Run("make a weak key", func(t *testing.T) {
		t.Setenv("GODEBUG", "rsa1024min=0")
		key, err := rsa.GenerateKey(rand.Reader, 512)
		if err != nil {
			t.Fatal(err)
		}
		weak = makeCA(t, "Weak CA", key, goodCA)
	})

	cases := []struct {
		name, reason string
		cert, key    []byte
	}{
		{"no certificate", "no certificate", goodKey, goodKey},
		{"mismatch", "does not match the first certificate", goodCA.pem, pkcs8(t, ecKey(t, elliptic.P256()))},
		{"not a CA", "not a CA", spoiled(func(c *x509.Certificate) { c.IsCA = false }), goodKey},
		{"no basic constraints", "not a CA", spoiled(func(c *x509.Certificate) { c.BasicConstraintsValid, c.IsCA = false, false }), goodKey},
		{"no CertSign", "CertSign", spoiled(func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature }), goodKey},
		{"expired", "has expired", spoiled(func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)
		}), goodKey},
		{"not yet valid", "not valid yet", spoiled(func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Now().Add(time.Hour), time.Now().Add(48*time.Hour)
		}), goodKey},
		{"expired later in the chain", "certificate 2", append(append([]byte{}, underOld.pem...), expiredRoot.pem...), goodKey},
		{"encrypted pkcs8", "remove the passphrase, for example with openssl pkey", goodCA.pem,
			pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{48, 3, 2, 1, 0}})},
		{"encrypted legacy", "remove the passphrase, for example with openssl pkey", goodCA.pem,
			pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3},
				Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00112233445566778899AABBCCDDEEFF"}})},
		{"pkcs12 in both", "PKCS#12", pfx(t), pfx(t)},
		{"pkcs12 as the key", "PKCS#12", goodCA.pem, pfx(t)},
		{"unknown certificate format", "unknown format", []byte("hello\n"), goodKey},
		{"unknown key format", "unknown format", goodCA.pem, []byte("hello\n")},
		{"empty key", "unknown format", goodCA.pem, nil},
		{"certificate as the key", "no private key", goodCA.pem, goodCA.pem},
		{"unknown key type x25519", "unknown key type", goodCA.pem, pkcs8(t, x25519)},
		{"unknown key type dsa", "unknown key type", goodCA.pem,
			pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte{1, 2, 3}})},
		{"unknown key type openssh", "unknown key type", goodCA.pem,
			pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte{1, 2, 3}})},
		{"damaged key", "unknown key type", goodCA.pem,
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})},
		{"too many certificates", "more than 8", bytes.Repeat(goodCA.pem, 9), goodKey},
		{"unrelated second certificate", "certificate 1 of the chain is not signed by certificate 2",
			append(append([]byte{}, goodCA.pem...), stranger.pem...), goodKey},
		{"root without room for a CA below", "path length", append(append([]byte{}, underRoot0.pem...), root0.pem...), goodKey},
		{"client authentication only", "server authentication", clientOnly.pem, goodKey},
		{"key that cannot sign", "at least 1024 bits", weak.pem, pkcs1(weak.key.(*rsa.PrivateKey))},
	}
	// Whatever is in use stays in use: the CA the proxy made, or an earlier upload.
	for _, current := range []string{"generated", "own"} {
		for _, c := range cases {
			t.Run(current+"/"+c.name, func(t *testing.T) {
				r := newOwnRig(t)
				r.Apply(r.cfg)
				if current == "own" {
					first := makeCA(t, "First own CA", ecKey(t, elliptic.P256()), nil)
					r.upload(t, first.pem, pkcs8(t, first.key))
					r.Apply(r.cfg)
				}
				before, files := r.Engine.CA.Load(), r.snapshot(t)
				trust := poolOf(before.cert)
				r.visit(t, trust)

				r.upload(t, c.cert, c.key)
				r.Apply(r.cfg)

				if reason, _ := r.stat(t)["ca_import_error"].(string); !strings.Contains(reason, c.reason) {
					t.Fatalf("reason %q, want %q", reason, c.reason)
				}
				if r.Engine.CA.Load() != before {
					t.Fatal("the CA in use changed")
				}
				sameFiles(t, files, r.snapshot(t))
				r.visit(t, trust)
				incomingEmpty(t, r)
				if m := r.stat(t); m["listening"] != true {
					t.Fatalf("a refused upload touched the port: %v", m)
				}
			})
		}
	}
}

// A file that is not what the app writes must not hang or exhaust the proxy.
func TestImportRefusesOddFiles(t *testing.T) {
	ca := makeCA(t, "Good CA", ecKey(t, elliptic.P256()), nil)
	key := pkcs8(t, ca.key)
	for _, c := range []struct {
		name, reason string
		plant        func(t *testing.T, path string)
	}{
		{"symbolic link", "not a regular file", func(t *testing.T, path string) {
			if err := os.Symlink("/dev/zero", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"too large", "too large", func(t *testing.T, path string) {
			if err := os.WriteFile(path, make([]byte, 2<<20), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newOwnRig(t)
			r.Apply(r.cfg)
			before := r.Engine.CA.Load()
			c.plant(t, filepath.Join(r.IncomingDir, "own-ca.pem"))
			if err := os.WriteFile(filepath.Join(r.IncomingDir, "own-ca.key"), key, 0o600); err != nil {
				t.Fatal(err)
			}
			r.Apply(r.cfg)
			if r.Engine.CA.Load() != before {
				t.Fatal("the CA in use changed")
			}
			if reason, _ := r.stat(t)["ca_import_error"].(string); !strings.Contains(reason, c.reason) {
				t.Fatalf("reason %q, want %q", reason, c.reason)
			}
			incomingEmpty(t, r)
		})
	}
}

// The chain goes to a folder the app can read and serve, so a key pasted into
// the certificate file must not travel with it.
func TestChainCopyHoldsNoKey(t *testing.T) {
	r := newOwnRig(t)
	ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), nil)
	key := pkcs8(t, ca.key)
	r.upload(t, append(append([]byte("Bag Attributes\n"), key...), ca.pem...), key)
	r.Apply(r.cfg)
	r.visit(t, poolOf(ca.cert))
	if got := readPEM(t, r); got != string(ca.pem) {
		t.Fatalf("state/ca.pem holds %q", got)
	}
	installed, err := os.ReadFile(filepath.Join(r.PrivateDir, "own-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(installed, []byte("PRIVATE KEY")) {
		t.Fatal("own-ca.pem holds the key")
	}
}

func TestImportAtomic(t *testing.T) {
	for _, c := range []struct {
		lone, reason string
	}{
		{"own-ca.key", "only the key"},
		{"own-ca.pem", "only the certificate"},
	} {
		t.Run(c.lone, func(t *testing.T) {
			r := newOwnRig(t)
			now := time.Now()
			r.Engine.Now = func() time.Time { return now }
			r.Apply(r.cfg)
			before := r.Engine.CA.Load()
			ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), nil)
			path := filepath.Join(r.IncomingDir, c.lone)
			data := ca.pem
			if c.lone == "own-ca.key" {
				data = pkcs8(t, ca.key)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}

			r.Apply(r.cfg)
			now = now.Add(59 * time.Second)
			r.Apply(r.cfg)
			if !onDisk(t, path) {
				t.Fatal("deleted while the other file may still come")
			}
			if r.Engine.CA.Load() != before {
				t.Fatal("half an upload was used")
			}
			if reason := r.stat(t)["ca_import_error"]; reason != "" {
				t.Fatalf("reported too early: %v", reason)
			}

			now = now.Add(3 * time.Second)
			if !r.Apply(r.cfg) {
				t.Fatal("the error waits for the next stats write")
			}
			if onDisk(t, path) {
				t.Fatal("a lone file stayed after 60 seconds")
			}
			if reason, _ := r.stat(t)["ca_import_error"].(string); !strings.Contains(reason, c.reason) {
				t.Fatalf("reason %q", reason)
			}
			if r.Engine.CA.Load() != before {
				t.Fatal("the CA in use changed")
			}
		})
	}
}

func TestSecondFileCompletesTheUpload(t *testing.T) {
	r := newOwnRig(t)
	r.Apply(r.cfg)
	ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), nil)
	if err := os.WriteFile(filepath.Join(r.IncomingDir, "own-ca.key"), pkcs8(t, ca.key), 0o600); err != nil {
		t.Fatal(err)
	}
	r.Apply(r.cfg)
	r.upload(t, ca.pem, pkcs8(t, ca.key))
	r.Apply(r.cfg)
	r.visit(t, poolOf(ca.cert))
}

// The app writes under a temporary name. One left by a crash holds a key.
func TestTemporaryFiles(t *testing.T) {
	r := newOwnRig(t)
	now := time.Now()
	r.Engine.Now = func() time.Time { return now }
	r.Apply(r.cfg)
	before := r.Engine.CA.Load()
	path := filepath.Join(r.IncomingDir, "own-ca.key.tmp")
	if err := os.WriteFile(path, []byte("half a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.Apply(r.cfg)
	if !onDisk(t, path) {
		t.Fatal("deleted while the app may still write it")
	}
	now = now.Add(61 * time.Second)
	r.Apply(r.cfg)
	if onDisk(t, path) {
		t.Fatal("a left-over key stayed")
	}
	if r.Engine.CA.Load() != before {
		t.Fatal("the CA in use changed")
	}
	if reason := r.stat(t)["ca_import_error"]; reason != "" {
		t.Fatalf("reported: %v", reason)
	}
}

func TestOwnCAInvalidNoFallback(t *testing.T) {
	ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), nil)
	other := makeCA(t, "Other CA", ecKey(t, elliptic.P256()), nil)
	expired := makeCA(t, "Old CA", ca.key, nil, func(c *x509.Certificate) {
		c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)
	})
	for _, c := range []struct {
		name, file, reason string
		data               []byte
	}{
		{"key is junk", "own-ca.key", "unknown format", []byte("junk")},
		{"certificate is junk", "own-ca.pem", "unknown format", []byte("junk")},
		{"key of another CA", "own-ca.key", "does not match", pkcs8(t, other.key)},
		{"expired", "own-ca.pem", "has expired", expired.pem},
		{"key is gone", "own-ca.key", "own-ca.key", nil},
		{"certificate is gone", "own-ca.pem", "own-ca.pem", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newOwnRig(t)
			r.Apply(r.cfg) // a valid generated CA is on disk
			generated := r.Engine.CA.Load()
			r.upload(t, ca.pem, pkcs8(t, ca.key))
			r.Apply(r.cfg)
			held := r.open(t, "127.0.0.1")
			if code := socksConnect(t, held, 1, []byte{198, 51, 100, 7}, 80); code != ReplyOK {
				t.Fatalf("reply code %d", code)
			}

			path := filepath.Join(r.PrivateDir, c.file)
			var err error
			if c.data == nil {
				err = os.Remove(path)
			} else {
				err = os.WriteFile(path, c.data, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			files := r.snapshot(t)

			check := func(s *Server) {
				t.Helper()
				portClosed(t, r.addr())
				if s.Engine.CA.Load() != nil {
					t.Fatal("a CA stayed loaded")
				}
				if m := r.statOf(t, s); m["listening"] != false || !strings.Contains(m["error"].(string), c.reason) {
					t.Fatalf("stats %v, want %q", m, c.reason)
				}
				sameFiles(t, files, r.snapshot(t))
				if strings.Contains(r.logs.String(), "replacing CA") {
					t.Fatal("the code that replaces the generated CA ran")
				}
				if s.Engine.CA.Load() == generated {
					t.Fatal("fell back to the generated CA")
				}
			}

			// While running: the port closes, and so do its connections.
			r.Apply(r.cfg)
			check(r.Server)
			ended(t, held)
			// After a restart, with nothing in memory.
			restarted := r.restart()
			restarted.Apply(r.cfg)
			check(restarted)

			// The owner decides: a valid upload opens the port again.
			fresh := makeCA(t, "Fresh CA", ecKey(t, elliptic.P256()), nil)
			r.upload(t, fresh.pem, pkcs8(t, fresh.key))
			r.Apply(r.cfg)
			r.visit(t, poolOf(fresh.cert))
		})
	}
}

// restart is a new process on the same folders, with nothing in memory.
func (r *socksRig) restart() *Server {
	s := NewServer(&Engine{
		CA:      new(atomic.Pointer[CA]),
		Bypass:  NewBypass(nil),
		Emitter: r.Engine.Emitter,
		Stats:   NewStats(),
		Dial:    r.Engine.Dial,
		Roots:   r.Engine.Roots,
	}, r.PrivateDir, r.StateDir)
	s.Interfaces = r.Interfaces
	s.IncomingDir = r.IncomingDir
	return s
}

func (r *socksRig) statOf(t *testing.T, s *Server) map[string]any {
	t.Helper()
	other := socksRig{Server: s}
	return other.stat(t)
}

// An own CA that runs out in service behaves like the generated one.
func TestOwnCAExpiresWhileRunning(t *testing.T) {
	r := newOwnRig(t)
	ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), nil)
	r.upload(t, ca.pem, pkcs8(t, ca.key))
	r.Apply(r.cfg)
	r.Engine.CA.Load().cert.NotAfter = time.Now().Add(-time.Minute)
	r.Apply(r.cfg)

	c := r.open(t, "127.0.0.1")
	if code := socksConnect(t, c, 1, []byte{198, 51, 100, 7}, 443); code != ReplyOK {
		t.Fatalf("reply code %d", code)
	}
	client := tls.Client(c, &tls.Config{ServerName: testName, InsecureSkipVerify: true})
	if reply := get(t, client, "/x"); !strings.Contains(reply, "reply to /x") {
		t.Fatalf("reply %q", reply)
	}
	if n := statsRelayed(r.Engine.Stats, "ca_expired"); n != 1 {
		t.Fatalf("relayed ca_expired %d", n)
	}
	if m := r.stat(t); m["listening"] != true {
		t.Fatalf("stats %v", m)
	}
}

func TestOwnCARemoved(t *testing.T) {
	r := newOwnRig(t)
	r.Apply(r.cfg)
	generated := r.Engine.CA.Load()
	files := r.snapshot(t)
	root := makeCA(t, "Own root", ecKey(t, elliptic.P256()), nil)
	ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), root)
	r.upload(t, append(append([]byte{}, ca.pem...), root.pem...), pkcs8(t, ca.key))
	r.Apply(r.cfg)
	r.visit(t, poolOf(root.cert))

	r.requestRemoval(t)
	if !r.Apply(r.cfg) {
		t.Fatal("the change waits for the next stats write")
	}
	if onDisk(t, filepath.Join(r.PrivateDir, "own-ca.pem")) || onDisk(t, filepath.Join(r.PrivateDir, "own-ca.key")) {
		t.Fatal("own files stayed")
	}
	incomingEmpty(t, r)
	// The same CA, not a new one: devices that trusted it must keep working.
	sameFiles(t, files, r.snapshot(t))
	if !r.Engine.CA.Load().cert.Equal(generated.cert) {
		t.Fatal("not the generated CA that was there before")
	}
	r.visit(t, poolOf(generated.cert))
	m := r.stat(t)
	if m["ca_own"] != false || m["ca_subject"] != "CN=Mikrokat local CA" {
		t.Fatalf("stats %v", m)
	}
	if strings.Contains(r.logs.String(), "replacing CA") {
		t.Fatal("the generated CA was replaced")
	}
}

func TestOwnCARemovedWhileOff(t *testing.T) {
	r := newOwnRig(t)
	r.Apply(r.cfg)
	files := r.snapshot(t)
	ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), nil)
	r.upload(t, ca.pem, pkcs8(t, ca.key))
	r.Apply(Config{})
	r.requestRemoval(t)
	r.Apply(Config{})
	sameFiles(t, files, r.snapshot(t))
	if m := r.stat(t); m["ca_own"] != false {
		t.Fatalf("stats %v", m)
	}
	if r.Engine.CA.Load() != nil && r.Engine.CA.Load().cert.Equal(ca.cert) {
		t.Fatal("the removed key stayed in memory")
	}
	r.Apply(r.cfg)
	if r.Engine.CA.Load().cert.Equal(ca.cert) {
		t.Fatal("the removed CA is signing")
	}
}

// With no generated CA yet, nothing may stay behind that names the removed one.
func TestOwnCARemovedWithoutGenerated(t *testing.T) {
	r := newOwnRig(t)
	ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), nil)
	r.upload(t, ca.pem, pkcs8(t, ca.key))
	r.Apply(Config{})
	r.requestRemoval(t)
	r.Apply(Config{})
	if onDisk(t, filepath.Join(r.StateDir, "ca.pem")) {
		t.Fatal("ca.pem still offers the removed CA")
	}
	r.Apply(r.cfg)
	r.visit(t, poolOf(r.Engine.CA.Load().cert))
	if r.Engine.CA.Load().cert.Equal(ca.cert) {
		t.Fatal("the removed CA is signing")
	}
}

// A request with nothing to remove must leave the generated CA and its
// certificate alone, and a request must not outlive its poll.
func TestRemovalIsOneShot(t *testing.T) {
	r := newOwnRig(t)
	r.Apply(r.cfg)
	files := r.snapshot(t)
	r.requestRemoval(t)
	r.Apply(r.cfg)
	sameFiles(t, files, r.snapshot(t))
	incomingEmpty(t, r)

	ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), nil)
	r.upload(t, ca.pem, pkcs8(t, ca.key))
	r.Apply(r.cfg)
	r.Apply(r.cfg)
	r.visit(t, poolOf(ca.cert))
}

// Remove, then upload, before the next poll: the upload is what stays.
func TestRemovalThenUploadInOnePoll(t *testing.T) {
	r := newOwnRig(t)
	first := makeCA(t, "First CA", ecKey(t, elliptic.P256()), nil)
	r.upload(t, first.pem, pkcs8(t, first.key))
	r.Apply(r.cfg)
	second := makeCA(t, "Second CA", ecKey(t, elliptic.P256()), nil)
	r.requestRemoval(t)
	r.upload(t, second.pem, pkcs8(t, second.key))
	r.Apply(r.cfg)
	r.visit(t, poolOf(second.cert))
	incomingEmpty(t, r)
}

func TestReplacingOwnCAKeepsGenerated(t *testing.T) {
	r := newOwnRig(t)
	r.Apply(r.cfg)
	files := r.snapshot(t)
	for _, name := range []string{"First CA", "Second CA"} {
		ca := makeCA(t, name, ecKey(t, elliptic.P256()), nil)
		r.upload(t, ca.pem, pkcs8(t, ca.key))
		r.Apply(r.cfg)
		r.visit(t, poolOf(ca.cert))
		if got := r.stat(t)["ca_subject"]; got != "CN="+name {
			t.Fatalf("subject %v", got)
		}
	}
	r.requestRemoval(t)
	r.Apply(r.cfg)
	sameFiles(t, files, r.snapshot(t))
}

func TestRegenerateIgnoredWithOwnCA(t *testing.T) {
	for _, on := range []bool{true, false} {
		r := newOwnRig(t)
		r.Apply(r.cfg)
		ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), nil)
		r.upload(t, ca.pem, pkcs8(t, ca.key))
		r.Apply(r.cfg)
		before, files := r.Engine.CA.Load(), r.snapshot(t)

		cfg := r.cfg
		cfg.Enabled = on
		cfg.CAGeneration++
		r.Apply(cfg)
		if r.Engine.CA.Load() != before {
			t.Fatal("the own CA was reloaded")
		}
		sameFiles(t, files, r.snapshot(t))
		if strings.Contains(r.logs.String(), "replacing CA") {
			t.Fatal("the code that replaces the generated CA ran")
		}
	}
}

func TestOwnKeyMode(t *testing.T) {
	r := newOwnRig(t)
	if err := os.Chmod(r.PrivateDir, 0o755); err != nil { // what Docker makes
		t.Fatal(err)
	}
	ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), nil)
	r.upload(t, ca.pem, pkcs8(t, ca.key))
	if err := os.Chmod(filepath.Join(r.IncomingDir, "own-ca.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.Apply(Config{}) // no generated CA, and the feature is off
	mode := func(path string) os.FileMode {
		t.Helper()
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return st.Mode().Perm()
	}
	for _, name := range []string{"own-ca.key", "own-ca.pem"} {
		if m := mode(filepath.Join(r.PrivateDir, name)); m != 0o600 {
			t.Fatalf("%s mode %04o", name, m)
		}
	}
	if m := mode(r.PrivateDir); m != 0o700 {
		t.Fatalf("private folder mode %04o", m)
	}
	if m := mode(filepath.Join(r.StateDir, "ca.pem")); m != 0o644 {
		t.Fatalf("ca.pem mode %04o", m)
	}

	// A restored file may be wider. That is no reason to touch its content.
	keyPath := filepath.Join(r.PrivateDir, "own-ca.key")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	restarted := r.restart()
	restarted.Apply(Config{})
	if m := mode(keyPath); m != 0o600 {
		t.Fatalf("own-ca.key mode %04o after a restart", m)
	}
}

func TestOwnCASurvivesRestart(t *testing.T) {
	r := newOwnRig(t)
	r.Apply(r.cfg)
	ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), nil)
	r.upload(t, ca.pem, pkcs8(t, ca.key))
	r.Apply(r.cfg)
	files := r.snapshot(t)

	restarted := r.restart()
	restarted.Apply(Config{})
	if got := restarted.Engine.CA.Load(); got == nil || !got.cert.Equal(ca.cert) {
		t.Fatal("own CA not loaded while off")
	}
	if m := r.statOf(t, restarted); m["ca_own"] != true || m["ca_subject"] != "CN=Own test CA" {
		t.Fatalf("stats %v", m)
	}
	sameFiles(t, files, r.snapshot(t))
}

// A crash can leave ca.pem behind the install. The next start puts it right.
func TestChainCopyRepairedAtStart(t *testing.T) {
	r := newOwnRig(t)
	r.Apply(r.cfg)
	generated := readPEM(t, r)
	ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), nil)
	r.upload(t, ca.pem, pkcs8(t, ca.key))
	r.Apply(r.cfg)
	if err := os.WriteFile(filepath.Join(r.StateDir, "ca.pem"), []byte(generated), 0o644); err != nil {
		t.Fatal(err)
	}
	r.restart().Apply(r.cfg)
	if got := readPEM(t, r); got != string(ca.pem) {
		t.Fatalf("ca.pem %q", got)
	}
}

func TestUploadWhileOff(t *testing.T) {
	r := newOwnRig(t)
	ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), nil)
	r.upload(t, ca.pem, pkcs8(t, ca.key))
	if !r.Apply(Config{}) {
		t.Fatal("the result waits for the next stats write")
	}
	incomingEmpty(t, r)
	if m := r.stat(t); m["ca_own"] != true || m["ca_subject"] != "CN=Own test CA" {
		t.Fatalf("stats %v", m)
	}
	if onDisk(t, filepath.Join(r.PrivateDir, "ca.key")) {
		t.Fatal("a generated CA was made while off")
	}
	r.Apply(r.cfg)
	r.visit(t, poolOf(ca.cert))
}

func TestImportErrorIsClearedByAGoodUpload(t *testing.T) {
	r := newOwnRig(t)
	r.Apply(r.cfg)
	ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), nil)
	r.upload(t, ca.pem, []byte("junk"))
	if !r.Apply(r.cfg) {
		t.Fatal("the error waits for the next stats write")
	}
	if reason := r.stat(t)["ca_import_error"]; reason == "" {
		t.Fatal("no reason")
	}
	r.Apply(r.cfg) // nothing in incoming: the reason stays for the owner to read
	if reason := r.stat(t)["ca_import_error"]; reason == "" {
		t.Fatal("reason lost")
	}
	r.upload(t, ca.pem, pkcs8(t, ca.key))
	r.Apply(r.cfg)
	if reason := r.stat(t)["ca_import_error"]; reason != "" {
		t.Fatalf("reason stayed: %v", reason)
	}
}

// Two renames are not one step. Whatever a crash leaves, a pair stays whole.
func TestInstallInterrupted(t *testing.T) {
	first := makeCA(t, "First CA", ecKey(t, elliptic.P256()), nil)
	second := makeCA(t, "Second CA", ecKey(t, elliptic.P256()), nil)
	for _, c := range []struct {
		name  string
		leave map[string][]byte // in the private folder, after the first CA was installed
		want  *testCA
	}{
		{"before the certificate was ready", map[string][]byte{"own-ca.key.new": pkcs8(t, second.key)}, first},
		{"both ready", map[string][]byte{"own-ca.key.new": pkcs8(t, second.key), "own-ca.pem.new": second.pem}, second},
		{"after the key moved", map[string][]byte{"own-ca.key": pkcs8(t, second.key), "own-ca.pem.new": second.pem}, second},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newOwnRig(t)
			r.upload(t, first.pem, pkcs8(t, first.key))
			r.Apply(r.cfg)
			for name, data := range c.leave {
				if err := os.WriteFile(filepath.Join(r.PrivateDir, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			restarted := r.restart()
			restarted.Apply(r.cfg)
			if got := restarted.Engine.CA.Load(); got == nil || !got.cert.Equal(c.want.cert) {
				t.Fatalf("CA %v", got)
			}
			for name := range map[string]bool{"own-ca.key.new": true, "own-ca.pem.new": true} {
				if onDisk(t, filepath.Join(r.PrivateDir, name)) {
					t.Fatalf("%s stayed", name)
				}
			}
		})
	}
}

// A connection can be past its check when the CA goes away.
func TestNoCAIsNotAPanic(t *testing.T) {
	var ca *CA
	if _, err := ca.Leaf(testName); err == nil {
		t.Fatal("no error")
	}
}

// A private path that is no folder holds no own files. The page must not claim
// an own CA that was never uploaded.
func TestBrokenPrivateFolderIsNoOwnCA(t *testing.T) {
	r := newOwnRig(t)
	r.PrivateDir = filepath.Join(t.TempDir(), "not-a-folder")
	if err := os.WriteFile(r.PrivateDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r.Apply(r.cfg)
	portClosed(t, r.addr())
	if m := r.stat(t); m["ca_own"] != false || !strings.Contains(m["error"].(string), "not-a-folder") {
		t.Fatalf("stats %v", m)
	}
}

// Nothing the proxy logs may carry the key.
func TestImportLogsNoKey(t *testing.T) {
	r := newOwnRig(t)
	ca := makeCA(t, "Own test CA", ecKey(t, elliptic.P256()), nil)
	key := pkcs8(t, ca.key)
	r.upload(t, ca.pem, key)
	r.Apply(r.cfg)
	r.upload(t, ca.pem, append([]byte("junk"), key[:40]...))
	r.Apply(r.cfg)
	block, _ := pem.Decode(key)
	if strings.Contains(r.logs.String(), "PRIVATE KEY") || bytes.Contains(r.logs.Bytes(), block.Bytes) {
		t.Fatalf("log %q", r.logs)
	}
}

// A name-constrained CA works for its names only, and must still load.
func TestOwnCANameConstrainedLoads(t *testing.T) {
	r := newOwnRig(t)
	ca := makeCA(t, "Constrained CA", ecKey(t, elliptic.P256()), nil, func(c *x509.Certificate) {
		c.PermittedDNSDomainsCritical = true
		c.PermittedDNSDomains = []string{"example.test"}
	})
	r.upload(t, ca.pem, pkcs8(t, ca.key))
	r.Apply(r.cfg)
	if reason := r.stat(t)["ca_import_error"]; reason != "" {
		t.Fatalf("a name-constrained CA was refused: %v", reason)
	}
	if r.stat(t)["ca_own"] != true {
		t.Fatal("the name-constrained CA is not in use")
	}
}

// The CA is only as long-lived as the shortest certificate above it.
func TestOwnCAExpiresWithTheEarliestCertificate(t *testing.T) {
	r := newOwnRig(t)
	root := makeCA(t, "Short root", ecKey(t, elliptic.P256()), nil, func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(10 * 24 * time.Hour)
	})
	signing := makeCA(t, "Long signing", ecKey(t, elliptic.P256()), root)
	r.upload(t, append(append([]byte{}, signing.pem...), root.pem...), pkcs8(t, signing.key))
	r.Apply(r.cfg)
	if got := r.stat(t)["ca_expires"]; got != float64(root.cert.NotAfter.Unix()) {
		t.Fatalf("ca_expires %v, want the root's %d", got, root.cert.NotAfter.Unix())
	}
}
