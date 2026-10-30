package main

import (
	_ "embed"
	"strings"
	"sync"
	"time"
)

const (
	autoTTL = 24 * time.Hour
	maxAuto = 1000

	failWindow = 10 * time.Minute // a second failure within this adds an entry
	goodTTL    = 24 * time.Hour   // a completed handshake counts for this long
	maxMemory  = 10000            // failures and completed handshakes, each
)

//go:embed bypass.txt
var builtinText string

// BuiltinBypass is the built-in list of names the proxy never decrypts.
var BuiltinBypass = parseList(builtinText)

// parseList reads one suffix per line, ignoring blanks and # comments.
func parseList(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// normalise turns an own-list entry into a plain suffix: no trailing dot, no
// leading "*.". It returns "" for an entry that is empty.
func normalise(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".")
	name = strings.TrimPrefix(name, "*.")
	return name
}

type autoKey struct{ device, name string }

func newAutoKey(device, name string) autoKey {
	return autoKey{device, strings.TrimSuffix(strings.ToLower(name), ".")}
}

// Bypass decides which names are relayed without decryption. It is safe for
// concurrent use.
type Bypass struct {
	mu       sync.Mutex
	builtin  []string
	own      []string
	auto     map[autoKey]int64 // expiry, Unix seconds
	removals map[autoKey]int64 // latest removal time, Unix seconds
	fails    map[autoKey]int64 // when the last failure stops counting, Unix seconds
	good     map[autoKey]int64 // when the last good handshake stops counting, Unix seconds
}

// NewBypass returns a Bypass with the given built-in suffixes.
func NewBypass(builtin []string) *Bypass {
	b := &Bypass{
		auto:     make(map[autoKey]int64),
		removals: make(map[autoKey]int64),
		fails:    make(map[autoKey]int64),
		good:     make(map[autoKey]int64),
	}
	for _, n := range builtin {
		if n = normalise(n); n != "" {
			b.builtin = append(b.builtin, n)
		}
	}
	return b
}

// SetOwn replaces the own list.
func (b *Bypass) SetOwn(names []string) {
	own := make([]string, 0, len(names))
	for _, n := range names {
		if n = normalise(n); n != "" {
			own = append(own, n)
		}
	}
	b.mu.Lock()
	b.own = own
	b.mu.Unlock()
}

func suffixMatch(list []string, name string) bool {
	for _, s := range list {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// Match returns "bypass" for a built-in or own name, "auto_bypass" for a live
// automatic entry of this device for exactly this name, and "" otherwise.
func (b *Bypass) Match(device, name string, now time.Time) string {
	k := newAutoKey(device, name)
	b.mu.Lock()
	defer b.mu.Unlock()
	if suffixMatch(b.builtin, k.name) || suffixMatch(b.own, k.name) {
		return "bypass"
	}
	if b.auto[k] > now.Unix() {
		return "auto_bypass"
	}
	return ""
}

// addAuto adds or renews an automatic bypass for 24 hours. When the list is
// full, the entry that expires first is evicted. A name removed after now is
// not added. The caller holds b.mu.
func (b *Bypass) addAuto(k autoKey, now time.Time) {
	if at, ok := b.removals[k]; ok && now.Unix() < at {
		return
	}
	remember(b.auto, k, now.Add(autoTTL).Unix(), maxAuto, now)
}

// Failed records that device gave up on the certificate of name. A second
// failure within failWindow adds an automatic entry, because one abort can be
// a closed tab, and a pinned app simply tries again. A device that completed a
// handshake for this name lately is not pinned, so it adds nothing.
func (b *Bypass) Failed(device, name string, now time.Time) {
	k := newAutoKey(device, name)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.good[k] > now.Unix() {
		return
	}
	if b.fails[k] > now.Unix() {
		delete(b.fails, k)
		b.addAuto(k, now)
		return
	}
	remember(b.fails, k, now.Add(failWindow).Unix(), maxMemory, now)
}

// Completed records that device finished a handshake with our certificate for
// name.
func (b *Bypass) Completed(device, name string, now time.Time) {
	k := newAutoKey(device, name)
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.fails, k)
	remember(b.good, k, now.Add(goodTTL).Unix(), maxMemory, now)
}

// remember stores until for k in m, which holds at most limit keys.
func remember(m map[autoKey]int64, k autoKey, until int64, limit int, now time.Time) {
	if _, exists := m[k]; !exists && len(m) >= limit {
		evict(m, limit, now)
	}
	m[k] = until
}

// evict drops expired entries, or the one expiring first when none has.
func evict(m map[autoKey]int64, limit int, now time.Time) {
	var first autoKey
	var firstUntil int64
	found := false
	for k, until := range m {
		if until <= now.Unix() {
			delete(m, k)
			continue
		}
		if !found || until < firstUntil {
			first, firstUntil, found = k, until, true
		}
	}
	if len(m) >= limit && found {
		delete(m, first)
	}
}

// Apply removes the automatic entries named by removals that were added before
// the removal time. It is idempotent: a removal never touches a later entry.
func (b *Bypass) Apply(removals []AutoRemoval) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, r := range removals {
		k := newAutoKey(r.Device, r.Name)
		if r.At > b.removals[k] {
			b.removals[k] = r.At
		}
		if until, ok := b.auto[k]; ok && until-int64(autoTTL/time.Second) < r.At {
			delete(b.auto, k)
		}
	}
}

// Auto lists the live automatic entries.
func (b *Bypass) Auto(now time.Time) []AutoEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []AutoEntry{}
	for k, until := range b.auto {
		if until > now.Unix() {
			out = append(out, AutoEntry{Device: k.device, Name: k.name, Until: until})
		}
	}
	return out
}
