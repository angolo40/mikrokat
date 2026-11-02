package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// bankListURL is the bank list of the Université Toulouse Capitole, a
	// public list of bank domains. The proxy downloads it, it is not in the repository.
	bankListURL = "https://dsi.ut-capitole.fr/blacklists/download/bank.tar.gz"

	bankFile        = "bank-list.txt"
	bankEntry       = "bank/domains"
	bankEvery       = 30 * 24 * time.Hour
	bankRetry       = 6 * time.Hour
	bankLimit       = 60 * time.Second
	bankMinNames    = 1000
	maxBankDownload = 5 << 20
	maxBankEntry    = 2 << 20
	maxBankExpanded = 32 << 20 // all of the unpacked archive, so a hostile one cannot cost much time
	maxBankEntries  = 100
	bankAgent       = "mikrokat-tlsproxy (bank list updater)"
)

// BankList is a set of domain suffixes. Match walks the name label by label, so
// the cost does not grow with the size of the list. It is safe for concurrent
// use, and a nil *BankList matches nothing.
type BankList struct {
	set atomic.Pointer[map[string]struct{}]
}

func NewBankList() *BankList { return &BankList{} }

// Set replaces the list.
func (l *BankList) Set(names []string) {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[n] = struct{}{}
	}
	l.set.Store(&m)
}

func (l *BankList) Len() int {
	if l == nil {
		return 0
	}
	if m := l.set.Load(); m != nil {
		return len(*m)
	}
	return 0
}

// Match reports whether name, or a parent domain of it, is in the list.
func (l *BankList) Match(name string) bool {
	if l == nil {
		return false
	}
	m := l.set.Load()
	if m == nil {
		return false
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for name != "" {
		if _, ok := (*m)[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
	return false
}

// suffixLabels are first labels that make a name like co.uk a public suffix.
// Such a name in the list would switch off a whole country.
var suffixLabels = map[string]bool{"co": true, "com": true, "org": true, "net": true, "gov": true, "ac": true, "edu": true}

// validBankName reports whether line is a lower-case host name of at least two
// labels, with no wildcard, of at most 253 characters, and not a public suffix
// of two labels such as co.uk.
func validBankName(line string) bool {
	if len(line) > 253 || strings.Count(line, ".") < 1 {
		return false
	}
	if first, _, two := strings.Cut(line, "."); two && suffixLabels[first] && strings.Count(line, ".") == 1 {
		return false
	}
	for _, label := range strings.Split(line, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// parseBankNames returns the valid names of text, without repeats and sorted.
func parseBankNames(text string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if _, dup := seen[line]; dup || !validBankName(line) {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}

// BankLoader keeps the BankList up to date: it reads the stored copy at start,
// and downloads a new one at once if there is none, then every 30 days, and
// 6 hours after a failure. A failure never touches the list in use.
type BankLoader struct {
	List   *BankList
	Stats  *Stats
	Dir    string
	URL    string
	Client *http.Client     // nil means one that verifies TLS with the system roots
	Now    func() time.Time // nil means time.Now

	mu    sync.Mutex
	next  time.Time // no download before this
	busy  bool
	names int   // the list in use, for the status
	at    int64 // when it was downloaded, Unix seconds
	wg    sync.WaitGroup
}

func NewBankLoader(list *BankList, stats *Stats, dir, url string) *BankLoader {
	return &BankLoader{List: list, Stats: stats, Dir: dir, URL: url}
}

func (l *BankLoader) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// Start loads the stored copy, if it is good, and counts it from the time it was stored.
func (l *BankLoader) Start() {
	p := filepath.Join(l.Dir, bankFile)
	raw, err := os.ReadFile(p)
	if err != nil {
		return
	}
	names := parseBankNames(string(raw))
	if len(names) < bankMinNames {
		return
	}
	fi, err := os.Stat(p)
	if err != nil {
		return
	}
	l.mu.Lock()
	l.List.Set(names)
	l.names, l.at = len(names), fi.ModTime().Unix()
	l.next = fi.ModTime().Add(bankEvery)
	l.mu.Unlock()
	l.Stats.SetBankList(l.names, l.at, "")
}

// Tick starts a download in the background if the switch is on and one is due.
func (l *BankLoader) Tick(on bool) {
	if !on {
		return
	}
	now := l.now()
	l.mu.Lock()
	if l.busy || now.Before(l.next) {
		l.mu.Unlock()
		return
	}
	l.busy = true
	l.wg.Add(1)
	l.mu.Unlock()
	go func() {
		defer l.wg.Done()
		names, err := l.fetch()
		done := l.now()
		l.mu.Lock()
		defer l.mu.Unlock()
		l.busy = false
		if err != nil {
			l.next = done.Add(bankRetry)
			l.Stats.SetBankList(l.names, l.at, err.Error())
			return
		}
		l.next = done.Add(bankEvery)
		l.List.Set(names)
		l.names, l.at = len(names), done.Unix()
		l.Stats.SetBankList(l.names, l.at, "")
	}()
}

// Wait returns when no download is running.
func (l *BankLoader) Wait() { l.wg.Wait() }

// fetch downloads the archive, checks it and stores the names. It changes
// nothing else.
func (l *BankLoader) fetch() ([]string, error) {
	if err := checkBankURL(l.URL); err != nil {
		return nil, err
	}
	client := l.Client
	if client == nil {
		client = &http.Client{}
	}
	// A redirect must not lead the download to plain http. The client is copied,
	// so one the caller shares is not changed.
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("redirected to a page that is not https")
		}
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return nil
	}
	client = &c
	ctx, cancel := context.WithTimeout(context.Background(), bankLimit)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", bankAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the server answered %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBankDownload+1))
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	if len(data) > maxBankDownload {
		return nil, errors.New("the download is too large")
	}
	text, err := bankEntryText(data)
	if err != nil {
		return nil, err
	}
	names := parseBankNames(text)
	if len(names) < bankMinNames {
		return nil, fmt.Errorf("only %d valid names, at least %d are needed", len(names), bankMinNames)
	}
	p := filepath.Join(l.Dir, bankFile)
	if err := os.MkdirAll(l.Dir, 0o755); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(p, []byte(strings.Join(names, "\n")+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("cannot store the list: %w", err)
	}
	now := l.now()
	os.Chtimes(p, now, now) // the time the copy counts from
	return names, nil
}

// checkBankURL accepts an https address, or an http one that points at this
// machine, which the tests use.
func checkBankURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); u.Scheme == "http" && (host == "localhost" || ip != nil && ip.IsLoopback()) {
		return nil
	}
	return errors.New("the address must be https")
}

// bankEntryText returns the bank/domains entry of a .tar.gz, reading at most
// maxBankEntry bytes of it.
func bankEntryText(data []byte) (string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("not a valid archive: %v", err)
	}
	tr := tar.NewReader(io.LimitReader(gz, maxBankExpanded))
	for range maxBankEntries {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("not a valid archive: %v", err)
		}
		if h.Typeflag != tar.TypeReg || path.Clean(h.Name) != bankEntry {
			continue
		}
		if h.Size > maxBankEntry {
			return "", errors.New("the " + bankEntry + " entry is too large")
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxBankEntry+1))
		if err != nil {
			return "", fmt.Errorf("not a valid archive: %v", err)
		}
		if len(body) > maxBankEntry {
			return "", errors.New("the " + bankEntry + " entry is too large")
		}
		return string(body), nil
	}
	return "", errors.New("the archive has no " + bankEntry + " entry")
}
