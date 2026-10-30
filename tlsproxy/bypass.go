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

// Bypass decides which names are relayed without decryption. It is safe for
// concurrent use.
type Bypass struct {
	mu       sync.Mutex
	builtin  []string
	own      []string
	auto     map[autoKey]int64 // expiry, Unix seconds
	removals map[autoKey]int64 // latest removal time, Unix seconds
}

// NewBypass returns a Bypass with the given built-in suffixes.
func NewBypass(builtin []string) *Bypass {
	b := &Bypass{
		auto:     make(map[autoKey]int64),
		removals: make(map[autoKey]int64),
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
// automatic entry of this device, and "" otherwise.
func (b *Bypass) Match(device, name string, now time.Time) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	b.mu.Lock()
	defer b.mu.Unlock()
	if suffixMatch(b.builtin, name) || suffixMatch(b.own, name) {
		return "bypass"
	}
	for n := name; n != ""; {
		if until, ok := b.auto[autoKey{device, n}]; ok && until > now.Unix() {
			return "auto_bypass"
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			break
		}
		n = n[i+1:]
	}
	return ""
}

// AddAuto adds or renews an automatic bypass for 24 hours. When the list is
// full, the entry that expires first is evicted. A name removed after now is
// not added.
func (b *Bypass) AddAuto(device, name string, now time.Time) {
	k := autoKey{device, strings.TrimSuffix(strings.ToLower(name), ".")}
	b.mu.Lock()
	defer b.mu.Unlock()
	if at, ok := b.removals[k]; ok && now.Unix() < at {
		return
	}
	if _, exists := b.auto[k]; !exists && len(b.auto) >= maxAuto {
		b.evict(now)
	}
	b.auto[k] = now.Add(autoTTL).Unix()
}

// evict drops expired entries, or the one expiring first when none has.
func (b *Bypass) evict(now time.Time) {
	var first autoKey
	var firstUntil int64
	found := false
	for k, until := range b.auto {
		if until <= now.Unix() {
			delete(b.auto, k)
			continue
		}
		if !found || until < firstUntil {
			first, firstUntil, found = k, until, true
		}
	}
	if len(b.auto) >= maxAuto && found {
		delete(b.auto, first)
	}
}

// Apply removes the automatic entries named by removals that were added before
// the removal time. It is idempotent: a removal never touches a later entry.
func (b *Bypass) Apply(removals []AutoRemoval) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, r := range removals {
		k := autoKey{r.Device, strings.TrimSuffix(strings.ToLower(r.Name), ".")}
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
