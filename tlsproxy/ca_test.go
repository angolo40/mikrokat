package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
	if !a.key.PublicKey.Equal(&b.key.PublicKey) {
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
	if a.key.PublicKey.Equal(&b.key.PublicKey) {
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

func TestLeafBadName(t *testing.T) {
	ca, err := LoadCA(t.TempDir(), t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Leaf(""); err == nil {
		t.Fatal("empty name accepted")
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
