package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	leafCacheMax  = 10000
	leafValidity  = 30 * 24 * time.Hour
	leafMinLeft   = 24 * time.Hour
	caValidity    = 2 * 365 * 24 * time.Hour
	maxNameLength = 253
)

// CA is the private certificate authority that signs the leaf certificates
// shown to devices. Its key can impersonate any site, so it lives only in the
// private directory.
type CA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// LoadCA reads the CA from privateDir (ca.key, generation) and stateDir
// (ca.pem), creating it when missing. A different generation, or any file
// that is unreadable or does not match the others, replaces the whole pair.
func LoadCA(privateDir, stateDir string, generation int) (*CA, error) {
	if err := os.MkdirAll(privateDir, 0o700); err != nil {
		return nil, err
	}
	// MkdirAll leaves a folder that already exists as it is.
	if err := os.Chmod(privateDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(privateDir, "ca.key")
	genPath := filepath.Join(privateDir, "generation")
	pemPath := filepath.Join(stateDir, "ca.pem")

	key, cert, why := readCA(keyPath, genPath, pemPath, generation)
	if why == nil {
		// A restored or copied key may be wider than 600; tighten it rather
		// than replace a CA that devices already trust.
		st, err := os.Stat(keyPath)
		if err != nil {
			return nil, err
		}
		if m := st.Mode().Perm(); m != 0o600 {
			if err := os.Chmod(keyPath, 0o600); err != nil {
				return nil, err
			}
			log.Printf("ca.key mode was %04o, tightened to 600", m)
		}
		return newCA(key, cert), nil
	}
	for _, p := range []string{keyPath, genPath, pemPath} {
		if _, err := os.Lstat(p); err == nil {
			log.Printf("replacing CA: %v", why)
			break
		}
	}

	for _, p := range []string{keyPath, genPath, pemPath} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Mikrokat local CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	// The key goes first and the certificate last: a crash in between leaves
	// a pair that readCA rejects, and the next start creates a fresh one.
	if err := writeFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(genPath, []byte(strconv.Itoa(generation)+"\n"), 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(pemPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	return newCA(key, cert), nil
}

func newCA(key *ecdsa.PrivateKey, cert *x509.Certificate) *CA {
	return &CA{key: key, cert: cert, cache: map[string]*tls.Certificate{}}
}

// readCA returns the stored pair when all three files are readable, agree
// with each other and with generation, and the certificate is still valid.
// Otherwise the error says why the pair cannot be used.
func readCA(keyPath, genPath, pemPath string, generation int) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	gen, err := os.ReadFile(genPath)
	if err != nil {
		return nil, nil, fmt.Errorf("generation file: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(gen)))
	if err != nil {
		return nil, nil, fmt.Errorf("generation file is not a number: %w", err)
	}
	if n != generation {
		return nil, nil, fmt.Errorf("generation changed from %d to %d", n, generation)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ca.key: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, errors.New("ca.key has no PEM block")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ca.key: %w", err)
	}
	certPEM, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ca.pem: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, errors.New("ca.pem has no PEM block")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ca.pem: %w", err)
	}
	if !cert.IsCA {
		return nil, nil, errors.New("ca.pem is not a CA certificate")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, nil, errors.New("ca.pem does not match ca.key")
	}
	if time.Now().After(cert.NotAfter) {
		return nil, nil, errors.New("CA certificate has expired")
	}
	return key, cert, nil
}

// Leaf returns a certificate for name signed by the CA, from memory when one
// with at least a day left is cached. Safe for concurrent use.
func (c *CA) Leaf(name string) (*tls.Certificate, error) {
	if name == "" || len(name) > maxNameLength {
		return nil, fmt.Errorf("invalid server name length %d", len(name))
	}
	if time.Now().After(c.cert.NotAfter) {
		return nil, errors.New("CA certificate has expired")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.cache[name]; ok && time.Until(l.Leaf.NotAfter) >= leafMinLeft {
		return l, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	notAfter := now.Add(leafValidity)
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter // never outlive the CA
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour), // allow for clock skew
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	l := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}
	if len(c.cache) >= leafCacheMax {
		c.cache = map[string]*tls.Certificate{}
	}
	c.cache[name] = l
	return l, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// writeFileAtomic writes to a temporary file in the same directory, created
// with mode 600 so it is never wider than needed, then sets mode and renames.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
