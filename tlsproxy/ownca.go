package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	ownCertFile = "own-ca.pem"
	ownKeyFile  = "own-ca.key"
	// The app asks for the removal with this file in the incoming folder. A
	// request in the control file would stay there and take the next upload too.
	removeRequest = "remove-own-ca"
	// What state/ca.pem held before an own chain replaced it, empty if nothing.
	savedGenerated = "generated-ca.pem"

	// A request for the owner's root to sign. The key stays in private, the
	// request is the only part of it that is served. The counters the proxy has
	// handled are kept beside the key, so a restart does not ask again.
	requestKeyFile  = "own-ca-request.key"
	requestCSRFile  = "own-ca.csr"
	requestSeenFile = "own-ca-request.seen"
	requestNameMax  = 64
	requestDefault  = "Mikrokat Inspection CA"

	ownFileLimit  = 1 << 20 // the app takes 256 KiB, this is against anything else
	ownLoneLimit  = 60 * time.Second
	ownCheckName  = "own-ca-check.invalid"
	ownRSAMaxBits = 8192 // signing with more freezes the proxy for minutes
	ownChainMax   = 8
)

var (
	errKeyMismatch   = errors.New("the key does not match the first certificate")
	errNotForRequest = errors.New("This certificate was not signed for the pending request.")
	errNoRequest     = errors.New("No request is pending. Create a request, or upload the key too.")
)

// parseOwnCA checks a certificate file and a key file and returns the CA they
// make. Its errors are read by the owner, and they carry nothing from the files.
func parseOwnCA(certPEM, keyPEM []byte, now time.Time) (*CA, error) {
	chain, err := parseChain(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseOwnKey(keyPEM)
	if err != nil {
		return nil, err
	}
	first := chain[0]
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(first.PublicKey) {
		return nil, errKeyMismatch
	}
	if !first.IsCA {
		return nil, errors.New("the first certificate is not a CA")
	}
	if first.KeyUsage != 0 && first.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("the first certificate has a KeyUsage without CertSign, so it may not sign certificates")
	}
	for i, c := range chain {
		if now.After(c.NotAfter) {
			return nil, fmt.Errorf("certificate %d of the chain has expired", i+1)
		}
		if now.Before(c.NotBefore) {
			return nil, fmt.Errorf("certificate %d of the chain is not valid yet", i+1)
		}
	}
	if err := checkChain(chain); err != nil {
		return nil, err
	}
	ca := newCA(key, first)
	ca.expires = chain[0].NotAfter
	for _, c := range chain {
		ca.chain = append(ca.chain, c.Raw)
		if c.NotAfter.Before(ca.expires) {
			ca.expires = c.NotAfter
		}
	}
	// The engine takes any failure to sign for an expired CA, so it must show
	// here, where the reason can reach the owner.
	leaf, err := ca.Leaf(ownCheckName)
	if err == nil {
		err = leaf.Leaf.CheckSignatureFrom(first)
	}
	if err != nil {
		return nil, errors.New("this key could not sign a test certificate, RSA keys need at least 1024 bits")
	}
	if err := checkLeaf(chain, leaf.Leaf, now); err != nil {
		return nil, err
	}
	return ca, nil
}

// checkChain refuses a chain that is too long, or whose certificates do not
// each sign the one before: a stranger in it would stop every device.
func checkChain(chain []*x509.Certificate) error {
	if len(chain) > ownChainMax {
		return fmt.Errorf("the chain has more than %d certificates", ownChainMax)
	}
	for i := 0; i+1 < len(chain); i++ {
		if chain[i].CheckSignatureFrom(chain[i+1]) != nil {
			return fmt.Errorf("certificate %d of the chain is not signed by certificate %d", i+1, i+2)
		}
	}
	return nil
}

// checkLeaf verifies a certificate the CA made, the way a device would, with
// the last certificate of the chain as its trust anchor. A CA no device would
// accept must not show as in use. A name constraint only limits the CA to its
// names, so that one failure is let through.
func checkLeaf(chain []*x509.Certificate, leaf *x509.Certificate, now time.Time) error {
	intermediates, roots := x509.NewCertPool(), x509.NewCertPool()
	for _, c := range chain[:len(chain)-1] {
		intermediates.AddCert(c)
	}
	roots.AddCert(chain[len(chain)-1])
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	var bad x509.CertificateInvalidError
	switch {
	case err == nil:
		return nil
	case !errors.As(err, &bad):
		return fmt.Errorf("devices would not accept certificates from this chain: %w", err)
	case bad.Reason == x509.CANotAuthorizedForThisName:
		return nil
	case bad.Reason == x509.IncompatibleUsage:
		return errors.New("a certificate of the chain does not allow server authentication (its extended key usage), so no device would accept it for a website")
	case bad.Reason == x509.TooManyIntermediates || bad.Reason == x509.NotAuthorizedToSign:
		return errors.New("a path length limit in the chain stops this CA from signing: no device would accept its certificates")
	}
	return fmt.Errorf("devices would not accept certificates from this chain: %w", err)
}

// parseChain returns the certificates of a PEM file, and skips anything else,
// so that a key pasted into it goes no further.
func parseChain(data []byte) ([]*x509.Certificate, error) {
	if !bytes.Contains(data, []byte("-----BEGIN ")) {
		return nil, notPEM("certificate", data)
	}
	var chain []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d of the chain cannot be read", len(chain)+1)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, errors.New("the certificate file holds no certificate")
	}
	return chain, nil
}

// parseOwnKey returns the first private key of a PEM file, in PKCS#8, PKCS#1 or
// SEC1. Other blocks are skipped: openssl writes EC PARAMETERS before an EC key.
func parseOwnKey(data []byte) (crypto.Signer, error) {
	if !bytes.Contains(data, []byte("-----BEGIN ")) {
		return nil, notPEM("key", data)
	}
	unknown := errors.New("unknown key type, or a damaged key: RSA, ECDSA and Ed25519 work")
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("the key file holds no private key")
		}
		_, legacy := block.Headers["DEK-Info"]
		if legacy || block.Type == "ENCRYPTED PRIVATE KEY" {
			return nil, errors.New("the key is encrypted: remove the passphrase, for example with openssl pkey")
		}
		var key any
		var err error
		switch block.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		default:
			if strings.HasSuffix(block.Type, "PRIVATE KEY") {
				return nil, unknown
			}
			continue
		}
		if err != nil {
			return nil, unknown
		}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			if k.N.BitLen() > ownRSAMaxBits {
				return nil, fmt.Errorf("the RSA key is too large: %d bits, the limit is %d", k.N.BitLen(), ownRSAMaxBits)
			}
			return k, nil
		case *ecdsa.PrivateKey:
			return k, nil
		case ed25519.PrivateKey:
			return k, nil
		}
		return nil, unknown
	}
}

// notPEM says what a file without any PEM block seems to be.
func notPEM(what string, data []byte) error {
	if len(data) > 0 && data[0] == 0x30 { // a DER SEQUENCE, which PKCS#12 is
		return fmt.Errorf("the %s file looks like PKCS#12 or DER: export it as PEM, for example with openssl pkcs12 -nodes", what)
	}
	return fmt.Errorf("the %s file is in an unknown format: it must be PEM", what)
}

// chainPEM writes the chain again, from what parseChain kept.
func chainPEM(ca *CA) []byte {
	var out bytes.Buffer
	for _, der := range ca.chain {
		pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return out.Bytes()
}

// readOwnFile reads a file that may come from the app, which is exposed to the
// network while this process holds the keys. A link to a device or a pipe must
// not hang it, and a huge file must not exhaust it.
func readOwnFile(path string) ([]byte, error) {
	// O_NONBLOCK so that a pipe swapped in after any earlier look cannot hang
	// the open, and O_NOFOLLOW so that a link is refused. What is checked is the
	// open file, not the name.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
		}
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	if st.Size() > ownFileLimit {
		return nil, fmt.Errorf("%s is too large", filepath.Base(path))
	}
	data, err := io.ReadAll(io.LimitReader(f, ownFileLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > ownFileLimit {
		return nil, fmt.Errorf("%s is too large", filepath.Base(path))
	}
	return data, nil
}

// isNotDir reports a path through something that is not a folder. os.ErrNotExist
// does not cover it, though the file is just as absent.
func isNotDir(err error) bool { return errors.Is(err, syscall.ENOTDIR) }

func (s *Server) private(name string) string { return filepath.Join(s.PrivateDir, name) }

func (s *Server) statePEM() string { return filepath.Join(s.StateDir, "ca.pem") }

// ownStored reports whether own files are installed, whole or not. A folder
// that cannot be read counts: only their real absence may lead to the generated
// CA, because the files of the generated CA would then be rewritten.
func (s *Server) ownStored() bool {
	for _, name := range []string{ownCertFile, ownKeyFile} {
		if _, err := os.Lstat(s.private(name)); !errors.Is(err, os.ErrNotExist) && !isNotDir(err) {
			return true
		}
	}
	return false
}

// pollOwn carries out what the incoming folder asks for. Each step leaves the
// folders so that the next poll can finish it, wherever a crash stops it.
func (s *Server) pollOwn() {
	if err := s.finishInstall(); err != nil {
		s.importResult(fmt.Errorf("the upload could not be installed: %w", err))
	}
	s.pollRequest()
	s.removeOwn()
	if !s.ownStored() {
		s.restoreGenerated() // a failure is tried again, and loadCA reports it
		if s.caOwn {
			s.caOwn, s.ownSeen, s.ownNews = false, "", true
			s.Engine.CA.Store(nil)
			s.Engine.Bypass.ForgetGood()
			s.Engine.Stats.SetCA(false, "", 0, 0)
		}
	}
	s.importOwn()
	s.reportRequest()
}

// removeOwn acts on a request to stop using the own CA. The request goes last,
// so a removal cut in half is finished by the next poll.
func (s *Server) removeOwn() {
	if s.IncomingDir == "" {
		return
	}
	request := filepath.Join(s.IncomingDir, removeRequest)
	if _, err := os.Lstat(request); err != nil {
		return
	}
	for _, name := range []string{ownKeyFile, ownCertFile} {
		if err := os.Remove(s.private(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			s.importResult(fmt.Errorf("the CA could not be removed: %w", err))
			return
		}
	}
	if err := os.Remove(request); err != nil {
		s.importResult(fmt.Errorf("the removal request could not be deleted: %w", err))
		return
	}
	s.ownNews = true
	s.Engine.Stats.SetImportError("")
	log.Printf("own CA removed")
}

// removeUploaded deletes a file from the incoming folder. A variable so that a
// test can make it fail, which a test running as root cannot do otherwise.
var removeUploaded = os.Remove

// importOwn takes an upload when both files are there, and deletes what stays
// behind alone. Valid or not, a key never stays in the folder.
func (s *Server) importOwn() {
	if s.IncomingDir == "" {
		return
	}
	cert, key := filepath.Join(s.IncomingDir, ownCertFile), filepath.Join(s.IncomingDir, ownKeyFile)
	_, certErr := os.Lstat(cert)
	_, keyErr := os.Lstat(key)
	if certErr == nil && keyErr != nil && errors.Is(keyErr, os.ErrNotExist) {
		// A signed certificate for the pending key. The app writes the key of a
		// pair first, so a certificate with no key beside it is not half a pair.
		s.importSigned(cert)
	}
	if certErr == nil && keyErr == nil {
		err := s.takeUpload(cert, key)
		for _, path := range []string{key, cert} {
			if rerr := removeUploaded(path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				// After a good install the page must not say the CA is unchanged.
				log.Printf("the uploaded %s could not be deleted from the incoming folder: %v", filepath.Base(path), rerr)
			}
		}
		s.importResult(err)
	}
	entries, err := os.ReadDir(s.IncomingDir)
	if err != nil {
		return
	}
	now := s.Engine.now()
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || e.Name() == removeRequest {
			continue
		}
		// Either way round: a clock that moved back must not keep a key here.
		if age := now.Sub(info.ModTime()); age <= ownLoneLimit && age >= -ownLoneLimit {
			continue
		}
		rerr := os.Remove(filepath.Join(s.IncomingDir, e.Name()))
		switch {
		case rerr != nil:
			s.importResult(fmt.Errorf("%s could not be deleted: %w", e.Name(), rerr))
		case e.Name() == ownKeyFile:
			s.importResult(errors.New("only the key arrived, and it was deleted: upload both files again"))
		case e.Name() == ownCertFile:
			s.importResult(errors.New("only the certificate arrived, and it was deleted: upload both files again"))
		}
	}
}

// takeUpload checks a pair and installs it. What is in use changes only once
// the pair has passed, so a refused upload leaves it untouched.
func (s *Server) takeUpload(cert, key string) error {
	certPEM, err := readOwnFile(cert)
	if err != nil {
		return err
	}
	keyPEM, err := readOwnFile(key)
	if err != nil {
		return err
	}
	ca, err := parseOwnCA(certPEM, keyPEM, s.Engine.now())
	if err != nil {
		return err
	}
	return s.installOwn(chainPEM(ca), keyPEM)
}

// importResult records how an upload ended, for the page, at once.
func (s *Server) importResult(err error) {
	s.ownNews = true
	if err == nil {
		s.Engine.Stats.SetImportError("")
		log.Printf("own CA upload accepted")
		return
	}
	s.Engine.Stats.SetImportError(err.Error())
	log.Printf("own CA upload refused: %v", err)
}

// installOwn stores a checked pair. Two renames cannot be one step, so both
// files first get a .new name, the certificate last: from then on the upload is
// committed, and finishInstall completes it, also after a crash.
func (s *Server) installOwn(chain, key []byte) error {
	if err := prepareDirs(s.PrivateDir, s.StateDir); err != nil {
		return err
	}
	if !s.ownStored() {
		if err := s.saveGenerated(); err != nil {
			return err
		}
	}
	if err := writeFileAtomic(s.private(ownKeyFile+".new"), key, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(s.private(ownCertFile+".new"), chain, 0o600); err != nil {
		return err
	}
	return s.finishInstall()
}

// finishInstall moves a committed pair into place, and drops one that never was.
func (s *Server) finishInstall() error {
	certNew, keyNew := s.private(ownCertFile+".new"), s.private(ownKeyFile+".new")
	if _, err := os.Lstat(certNew); err != nil {
		if err := os.Remove(keyNew); err != nil && !os.IsNotExist(err) && !isNotDir(err) {
			return err
		}
		return nil
	}
	if err := os.Rename(keyNew, s.private(ownKeyFile)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(certNew, s.private(ownCertFile))
}

// saveGenerated keeps what ca.pem holds while the own chain takes its place.
// LoadCA would otherwise find it does not match ca.key, and make a new CA that
// no device trusts when the owner goes back to the generated one.
func (s *Server) saveGenerated() error {
	data, err := os.ReadFile(s.statePEM())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeFileAtomic(s.private(savedGenerated), data, 0o600)
}

// restoreGenerated puts ca.pem back once the own files are gone.
func (s *Server) restoreGenerated() error {
	data, err := os.ReadFile(s.private(savedGenerated))
	if errors.Is(err, os.ErrNotExist) || isNotDir(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(data) > 0 {
		err = writeFileAtomic(s.statePEM(), data, 0o644)
	} else if err = os.Remove(s.statePEM()); errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		return err
	}
	return os.Remove(s.private(savedGenerated))
}

// ownStamp changes when either own file does.
func (s *Server) ownStamp() string {
	var stamp strings.Builder
	for _, name := range []string{ownCertFile, ownKeyFile} {
		if st, err := os.Stat(s.private(name)); err == nil {
			fmt.Fprintf(&stamp, "%d %d;", st.Size(), st.ModTime().UnixNano())
		}
		stamp.WriteString("/")
	}
	return stamp.String()
}

// loadOwn stores the own CA, unless the same files are already loaded. So an
// own CA that expires in service stays loaded and relays as ca_expired, while
// one that fails here leaves no CA at all and the caller keeps the port closed.
func (s *Server) loadOwn() error {
	stamp := s.ownStamp()
	if s.caOwn && stamp == s.ownSeen && s.Engine.CA.Load() != nil {
		return nil
	}
	s.caOwn = true
	ca, err := s.readOwn()
	if err != nil {
		s.ownSeen = ""
		s.Engine.CA.Store(nil)
		s.Engine.Bypass.ForgetGood()
		s.Engine.Stats.SetCA(true, "", 0, 0)
		return fmt.Errorf("own CA: %w", err)
	}
	s.ownSeen, s.ownNews = stamp, true
	s.Engine.CA.Store(ca)
	s.Engine.Bypass.ForgetGood()
	s.Engine.Stats.SetCA(true, ca.cert.Subject.String(), len(ca.chain), ca.expires.Unix())
	log.Printf("own CA loaded: %q, %d in the chain", ca.cert.Subject.String(), len(ca.chain))
	return nil
}

// readOwn reads and checks the installed files, and only ever tightens their
// mode. The chain is copied beside the generated CA's place for the download.
func (s *Server) readOwn() (*CA, error) {
	if err := prepareDirs(s.PrivateDir, s.StateDir); err != nil {
		return nil, err
	}
	certPEM, err := readOwnFile(s.private(ownCertFile))
	if err != nil {
		return nil, err
	}
	keyPEM, err := readOwnFile(s.private(ownKeyFile))
	if err != nil {
		return nil, err
	}
	ca, err := parseOwnCA(certPEM, keyPEM, s.Engine.now())
	if err != nil {
		return nil, err
	}
	for _, name := range []string{ownCertFile, ownKeyFile} {
		st, err := os.Stat(s.private(name))
		if err != nil {
			return nil, err
		}
		if m := st.Mode().Perm(); m != 0o600 {
			if err := os.Chmod(s.private(name), 0o600); err != nil {
				return nil, err
			}
			log.Printf("%s mode was %04o, tightened to 600", name, m)
		}
	}
	chain := chainPEM(ca)
	if current, err := os.ReadFile(s.statePEM()); err != nil || !bytes.Equal(current, chain) {
		if err := writeFileAtomic(s.statePEM(), chain, 0o644); err != nil {
			return nil, err
		}
	}
	return ca, nil
}

// pollRequest carries out the app's counters: a new request replaces the
// pending one, a cancel drops it. Cancel goes last, so a key never outlives it.
func (s *Server) pollRequest() {
	if !s.reqLoaded {
		s.reqMade, s.reqCancelled = readRequestSeen(s.private(requestSeenFile))
		s.reqLoaded = true
	}
	cfg := s.cfg
	if cfg.CARequest != s.reqMade && cfg.CARequest != 0 {
		s.reqMade = cfg.CARequest
		err := s.makeRequest(cfg.CARequestName)
		s.saveRequestSeen()
		s.ownNews = true
		if err != nil {
			s.Engine.Stats.SetImportError(fmt.Sprintf("the request could not be made: %v", err))
			log.Printf("own CA request failed: %v", err)
		} else {
			s.Engine.Stats.SetImportError("")
			log.Printf("own CA request made")
		}
	}
	if cfg.CARequestCancel != s.reqCancelled && cfg.CARequestCancel != 0 {
		s.reqCancelled = cfg.CARequestCancel
		if err := s.dropRequest(); err != nil {
			s.importResult(fmt.Errorf("the request could not be cancelled: %w", err))
		} else {
			log.Printf("own CA request cancelled")
		}
		s.saveRequestSeen()
		s.ownNews = true
	}
}

// reportRequest tells the stats whether a request is pending, and its name.
func (s *Server) reportRequest() {
	if _, err := os.Lstat(s.private(requestKeyFile)); err != nil {
		s.reqName = ""
		s.Engine.Stats.SetRequest(false, "")
		return
	}
	if s.reqName == "" {
		s.reqName = requestDefault
		if raw, err := os.ReadFile(filepath.Join(s.StateDir, requestCSRFile)); err == nil {
			if block, _ := pem.Decode(raw); block != nil {
				if csr, err := x509.ParseCertificateRequest(block.Bytes); err == nil && csr.Subject.CommonName != "" {
					s.reqName = csr.Subject.CommonName
				}
			}
		}
	}
	s.Engine.Stats.SetRequest(true, s.reqName)
}

func readRequestSeen(path string) (made, cancelled int) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0
	}
	f := strings.Fields(string(raw))
	if len(f) != 2 {
		return 0, 0
	}
	made, _ = strconv.Atoi(f[0])
	cancelled, _ = strconv.Atoi(f[1])
	return made, cancelled
}

func (s *Server) saveRequestSeen() {
	data := []byte(fmt.Sprintf("%d %d\n", s.reqMade, s.reqCancelled))
	if err := prepareDirs(s.PrivateDir, s.StateDir); err == nil {
		err = writeFileAtomic(s.private(requestSeenFile), data, 0o600)
		if err != nil {
			log.Printf("own CA request counters could not be saved: %v", err)
		}
	}
}

// requestName caps the name the app sent. The app checks it too.
func requestName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return requestDefault
	}
	for utf8.RuneCountInString(name) > requestNameMax {
		_, n := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-n]
	}
	return name
}

// makeRequest writes a new key and the request for it. The key goes first and
// the request last, each through a rename, so a request on offer always has
// its key. An older pending pair is replaced.
func (s *Server) makeRequest(name string) error {
	if err := prepareDirs(s.PrivateDir, s.StateDir); err != nil {
		return err
	}
	name = requestName(name)
	key, err := ecdsaNew()
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: name},
	}, key)
	if err != nil {
		return err
	}
	// The old request goes first: while the key is replaced it would not match.
	if err := os.Remove(filepath.Join(s.StateDir, requestCSRFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeFileAtomic(s.private(requestKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(s.StateDir, requestCSRFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), 0o644); err != nil {
		return err
	}
	s.reqName = name
	return nil
}

func ecdsaNew() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// dropRequest deletes the pending key and request. The key goes first.
func (s *Server) dropRequest() error {
	s.reqName = ""
	for _, path := range []string{s.private(requestKeyFile), filepath.Join(s.StateDir, requestCSRFile)} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) && !isNotDir(err) {
			return err
		}
	}
	return nil
}

// importSigned takes a certificate that came without a key. It is checked as an
// upload is, with the pending key. A refusal leaves the pending key and the CA
// in use, and the certificate never stays in the incoming folder.
func (s *Server) importSigned(cert string) {
	err := s.takeSigned(cert)
	if rerr := removeUploaded(cert); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		log.Printf("the uploaded %s could not be deleted from the incoming folder: %v", filepath.Base(cert), rerr)
	}
	s.importResult(err)
}

func (s *Server) takeSigned(cert string) error {
	keyPEM, err := readOwnFile(s.private(requestKeyFile))
	if errors.Is(err, os.ErrNotExist) || isNotDir(err) {
		return errNoRequest
	}
	if err != nil {
		return err
	}
	certPEM, err := readOwnFile(cert)
	if err != nil {
		return err
	}
	ca, err := parseOwnCA(certPEM, keyPEM, s.Engine.now())
	if errors.Is(err, errKeyMismatch) {
		return errNotForRequest
	}
	if err != nil {
		return err
	}
	if err := s.installOwn(chainPEM(ca), keyPEM); err != nil {
		return err
	}
	if err := s.dropRequest(); err != nil {
		log.Printf("the request could not be removed after the install: %v", err)
	}
	return nil
}
