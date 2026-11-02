package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func bankNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("bank%04d.example", i)
	}
	return out
}

// archive builds a .tar.gz with the given entries, in order.
func archive(t *testing.T, entries ...[2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e[0], Mode: 0o644, Size: int64(len(e[1]))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e[1])); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func goodArchive(t *testing.T, n int) []byte {
	return archive(t, [2]string{"bank/domains", strings.Join(bankNames(n), "\n") + "\n"})
}

// bankRig is a loader whose server answers with whatever body and status are set.
type bankRig struct {
	*BankLoader
	dir    string
	srv    *httptest.Server
	mu     sync.Mutex
	body   []byte
	status int
	hits   int
	agent  string
	now    time.Time
}

func newBankRig(t *testing.T) *bankRig {
	t.Helper()
	r := &bankRig{dir: t.TempDir(), status: 200, now: time.Unix(1_800_000_000, 0)}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.mu.Lock()
		r.hits++
		r.agent = q.UserAgent()
		body, status := r.body, r.status
		r.mu.Unlock()
		w.WriteHeader(status)
		w.Write(body)
	}))
	t.Cleanup(r.srv.Close)
	r.BankLoader = NewBankLoader(NewBankList(), NewStats(), r.dir, r.srv.URL)
	r.Client = r.srv.Client()
	r.Now = func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }
	return r
}

func (r *bankRig) serve(body []byte, status int) {
	r.mu.Lock()
	r.body, r.status = body, status
	r.mu.Unlock()
}

func (r *bankRig) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func (r *bankRig) requests() int { r.mu.Lock(); defer r.mu.Unlock(); return r.hits }

// tick runs one check of the loader and waits for any download it started.
func (r *bankRig) tick(on bool) {
	r.Tick(on)
	r.Wait()
}

func (r *bankRig) status_() (names int, at int64, errText string) {
	r.Stats.mu.Lock()
	defer r.Stats.mu.Unlock()
	return r.Stats.bankNames, r.Stats.bankAt, r.Stats.bankError
}

func (r *bankRig) stored(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.dir, "bank-list.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBankGoodDownload(t *testing.T) {
	r := newBankRig(t)
	r.serve(goodArchive(t, 1500), 200)
	r.tick(true)
	names, at, errText := r.status_()
	if names != 1500 || errText != "" || at != r.now.Unix() {
		t.Fatalf("names %d at %d error %q", names, at, errText)
	}
	if !r.List.Match("bank0007.example") || r.List.Match("bank9999.example") {
		t.Fatal("the list does not hold what was sent")
	}
	if got := len(strings.Fields(string(r.stored(t)))); got != 1500 {
		t.Fatalf("stored %d names", got)
	}
	fi, _ := os.Stat(filepath.Join(r.dir, "bank-list.txt"))
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if !strings.Contains(strings.ToLower(r.agent), "mikrokat") {
		t.Fatalf("User-Agent %q", r.agent)
	}
	ents, _ := os.ReadDir(r.dir)
	if len(ents) != 1 {
		t.Fatalf("files left behind: %v", ents)
	}
}

func TestBankKeepsTheOldCopyOnFailure(t *testing.T) {
	cases := map[string]struct {
		body   []byte
		status int
		want   string
	}{
		"not gzip": {[]byte("this is not an archive"), 200, "archive"},
		"not tar": {func() []byte {
			var b bytes.Buffer
			g := gzip.NewWriter(&b)
			g.Write([]byte("plain text, no tar"))
			g.Close()
			return b.Bytes()
		}(), 200, "archive"},
		"no entry":      {nil, 200, "bank/domains"},
		"too few":       {nil, 200, "1000"},
		"server error":  {[]byte("oops"), 503, "503"},
		"entry too big": {nil, 200, "large"},
		"download big":  {nil, 200, "large"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := newBankRig(t)
			r.serve(goodArchive(t, 1200), 200)
			r.tick(true)
			before := r.stored(t)
			body := tc.body
			switch name {
			case "no entry":
				body = archive(t, [2]string{"bank/urls", "x.example\n"})
			case "too few":
				body = goodArchive(t, 999)
			case "entry too big":
				body = archive(t, [2]string{"bank/domains", strings.Repeat("a.example\n", 250_000)}) // 2.5 MB
			case "download big":
				body = make([]byte, 5<<20+1000)
			}
			r.serve(body, tc.status)
			r.advance(bankEvery + time.Hour)
			r.tick(true)
			names, _, errText := r.status_()
			if !strings.Contains(errText, tc.want) {
				t.Fatalf("error %q, want it to mention %q", errText, tc.want)
			}
			if names != 1200 || !r.List.Match("bank0005.example") || !bytes.Equal(r.stored(t), before) {
				t.Fatalf("the old copy was not kept: %d names", names)
			}
		})
	}
}

func TestBankInvalidLinesAreSkipped(t *testing.T) {
	var lines []string
	lines = append(lines, bankNames(1000)...)
	lines = append(lines, "UPPER.example", "*.wild.example", "single", "has space.example", "-bad.example", "bad-.example", "a..b.example",
		".lead.example", "trail.example.", strings.Repeat("a", 60)+"."+strings.Repeat("b", 60)+"."+strings.Repeat("c", 60)+"."+strings.Repeat("d", 60)+"."+strings.Repeat("e", 60)+".example",
		"under_score.example", "http://url.example/path", "", "# comment", "bank0001.example")
	r := newBankRig(t)
	r.serve(archive(t, [2]string{"bank/domains", strings.Join(lines, "\n")}), 200)
	r.tick(true)
	names, _, errText := r.status_()
	if names != 1000 || errText != "" {
		t.Fatalf("names %d error %q", names, errText)
	}
	for _, bad := range []string{"upper.example", "wild.example", "single", "lead.example", "trail.example", "url.example"} {
		if r.List.Match(bad) {
			t.Errorf("%s was taken", bad)
		}
	}
}

func TestBankEntryAtTheLimitIsTaken(t *testing.T) {
	var b strings.Builder
	for i := 0; b.Len() < 2<<20-100; i++ {
		fmt.Fprintf(&b, "n%06d.example\n", i)
	}
	r := newBankRig(t)
	r.serve(archive(t, [2]string{"bank/domains", b.String()}), 200)
	r.tick(true)
	if _, _, errText := r.status_(); errText != "" {
		t.Fatalf("error %q", errText)
	}
}

func TestBankTiming(t *testing.T) {
	r := newBankRig(t)
	r.serve(goodArchive(t, 1100), 200)
	r.tick(true)
	if r.requests() != 1 {
		t.Fatalf("%d requests, want one at once with no copy", r.requests())
	}
	r.advance(bankEvery - time.Minute)
	r.tick(true)
	if r.requests() != 1 {
		t.Fatalf("%d requests before 30 days", r.requests())
	}
	r.advance(2 * time.Minute)
	r.serve([]byte("broken"), 200)
	r.tick(true)
	if r.requests() != 2 {
		t.Fatalf("%d requests after 30 days", r.requests())
	}
	r.advance(bankRetry - time.Minute)
	r.tick(true)
	if r.requests() != 2 {
		t.Fatalf("%d requests before the 6 hours of a retry", r.requests())
	}
	r.advance(2 * time.Minute)
	r.serve(goodArchive(t, 1200), 200)
	r.tick(true)
	if r.requests() != 3 {
		t.Fatalf("%d requests after 6 hours", r.requests())
	}
	if names, _, errText := r.status_(); names != 1200 || errText != "" {
		t.Fatalf("names %d error %q", names, errText)
	}
	r.advance(bankRetry + time.Hour)
	r.tick(true)
	if r.requests() != 3 {
		t.Fatalf("a good copy was fetched again after %d requests", r.requests())
	}
}

func TestBankOffDownloadsNothing(t *testing.T) {
	r := newBankRig(t)
	r.serve(goodArchive(t, 1100), 200)
	r.tick(false)
	r.advance(100 * 24 * time.Hour)
	r.tick(false)
	if r.requests() != 0 {
		t.Fatalf("%d requests while off", r.requests())
	}
	if _, err := os.Stat(filepath.Join(r.dir, "bank-list.txt")); err == nil {
		t.Fatal("a copy was stored while off")
	}
	r.tick(true) // switched on: at once
	if r.requests() != 1 {
		t.Fatalf("%d requests after switching on", r.requests())
	}
}

func TestBankStartLoadsTheStoredCopy(t *testing.T) {
	r := newBankRig(t)
	r.serve(goodArchive(t, 1100), 200)
	r.tick(true)
	stored := time.Unix(r.now.Unix(), 0)

	again := NewBankLoader(NewBankList(), NewStats(), r.dir, r.srv.URL)
	again.Client = r.srv.Client()
	again.Now = func() time.Time { return stored.Add(24 * time.Hour) }
	again.Start()
	if !again.List.Match("bank0003.example") || again.List.Len() != 1100 {
		t.Fatal("the stored copy was not loaded at start")
	}
	if again.Stats.bankNames != 1100 || again.Stats.bankAt != stored.Unix() {
		t.Fatalf("status %d %d", again.Stats.bankNames, again.Stats.bankAt)
	}
	again.Tick(true)
	again.Wait()
	if r.requests() != 1 {
		t.Fatalf("%d requests, a copy of a day ago is enough", r.requests())
	}
}

func TestBankStartIgnoresADamagedCopy(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bank-list.txt"), []byte("only.example\n"), 0o644)
	l := NewBankLoader(NewBankList(), NewStats(), dir, "https://127.0.0.1:1/")
	l.Start()
	if l.List.Len() != 0 {
		t.Fatal("a copy under the minimum was loaded")
	}
}

func TestBankChecksTheCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { t.Error("served to a client that did not trust it") }))
	defer srv.Close()
	l := NewBankLoader(NewBankList(), NewStats(), t.TempDir(), srv.URL) // the default client: the system roots
	l.Tick(true)
	l.Wait()
	l.Stats.mu.Lock()
	defer l.Stats.mu.Unlock()
	if l.Stats.bankError == "" || l.Stats.bankNames != 0 {
		t.Fatalf("error %q names %d", l.Stats.bankError, l.Stats.bankNames)
	}
}

func TestBankMatching(t *testing.T) {
	l := NewBankList()
	l.Set([]string{"bank.example", "credit.example.ch"})
	for name, want := range map[string]bool{
		"bank.example": true, "www.bank.example": true, "a.b.bank.example": true, "BANK.example.": true,
		"notbank.example": false, "bank.example.evil.com": false, "example": false, "ch": false,
		"credit.example.ch": true, "login.credit.example.ch": true, "example.ch": false, "": false,
	} {
		if got := l.Match(name); got != want {
			t.Errorf("%q: got %v", name, got)
		}
	}
	var empty *BankList
	if empty.Match("bank.example") {
		t.Error("a nil list matched")
	}
}

func TestBypassUsesTheBankList(t *testing.T) {
	list := NewBankList()
	list.Set(bankNames(1500))
	b := NewBypass(nil)
	b.SetBankList(list)
	for _, custom := range []bool{false, true} {
		b.SetCustom(custom)
		b.SetBank(true)
		if got := b.Match("d", "www.bank0042.example", t0); got != "bank_list" {
			t.Errorf("custom %v: %q", custom, got)
		}
		if got := b.Match("d", "notbank0042.example", t0); got != "" {
			t.Errorf("custom %v: a lookalike matched: %q", custom, got)
		}
		b.SetBank(false)
		if got := b.Match("d", "www.bank0042.example", t0); got != "" {
			t.Errorf("custom %v: matched while off: %q", custom, got)
		}
	}
	b.SetOwn([]string{"bank0042.example"})
	b.SetBank(true)
	if got := b.Match("d", "bank0042.example", t0); got != "bypass" {
		t.Errorf("the owner's list comes first: %q", got)
	}
}

func TestBankMatchIsFastWithSevenThousandNames(t *testing.T) {
	l := NewBankList()
	l.Set(bankNames(7000))
	start := time.Now()
	for range 100000 {
		l.Match("deep.sub.domain.of.nothing.example.org")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("100000 matches took %v", d)
	}
}

func TestBankStatsInFile(t *testing.T) {
	s := NewStats()
	s.SetBankList(1234, 99, "it broke")
	p := filepath.Join(t.TempDir(), "stats.json")
	if err := s.WriteFile(p, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	var m map[string]any
	json.Unmarshal(raw, &m)
	if m["bank_list_names"] != float64(1234) || m["bank_list_at"] != float64(99) || m["bank_list_error"] != "it broke" {
		t.Fatalf("stats %s", raw)
	}
}

func TestConfigBankList(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(p, []byte(`{"enabled": true, "bank_list": true}`), 0o644)
	c, err := LoadConfig(p, Config{})
	if err != nil || !c.BankList {
		t.Fatalf("%+v, %v", c, err)
	}
}

func TestServerAppliesTheBankSwitch(t *testing.T) {
	r := newOwnRig(t)
	list := NewBankList()
	list.Set(bankNames(1500))
	r.Engine.Bypass.SetBankList(list)
	r.cfg.BankList = true
	r.Apply(r.cfg)
	if got := r.Engine.Bypass.Match("d", "bank0001.example", t0); got != "bank_list" {
		t.Fatalf("on: %q", got)
	}
	r.cfg.BankList = false
	r.Apply(r.cfg)
	if got := r.Engine.Bypass.Match("d", "bank0001.example", t0); got != "" {
		t.Fatalf("off: %q", got)
	}
}

func TestBuiltinHasAppleMicrosoftAndMoreBanks(t *testing.T) {
	b := NewBypass(BuiltinBypass)
	for _, name := range []string{
		"www.apple.com", "p25-content.icloud.com", "a.icloud-content.com", "x.cdn-apple.com", "is1.mzstatic.com", "x.apple-cloudkit.com", "x.apple-dns.net",
		"x.apzones.com", "x.itunes.com", "x.apple-livephotoskit.com", "x.apple-mapkit.com",
		"login.microsoftonline.com", "login.live.com", "www.office.com", "x.office.net", "x.office365.com", "x.sharepoint.com", "teams.microsoft.com", "outlook.com",
		"www.postfinance.ch", "www.finecobank.com",
	} {
		if got := b.Match("d", name, t0); got != "bypass" {
			t.Errorf("%s: %q", name, got)
		}
	}
	if got := b.Match("d", "notapple.com", t0); got != "" {
		t.Errorf("a lookalike matched: %q", got)
	}
	if len(BuiltinBypass) >= 500 {
		t.Errorf("%d names, the field holds 500", len(BuiltinBypass))
	}
}
