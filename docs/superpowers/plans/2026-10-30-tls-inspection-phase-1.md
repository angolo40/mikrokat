# HTTPS inspection, phase 1: engine and SOCKS. Implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An owner turns on HTTPS inspection in Settings, points one browser profile at a SOCKS port, and Suricata raises alerts on what used to be encrypted, tied to the real device and server.

**Architecture:** A small Go container terminates TLS for listed devices, verifies the real server, relays bytes both ways, and rebuilds a capped plaintext copy as TCP packets tagged VLAN 3900, sent as TZSP to the existing `tzsp` container. The web app and the proxy share only files: a control file written by the app, a state folder written by the proxy.

**Tech Stack:** Go 1.26 standard library only, `golang:1.26.9-alpine3.24` to build, `alpine:3.24.3` to run. Python web app, Suricata, EveBox as they are.

**Spec:** `docs/superpowers/specs/2026-10-30-tls-inspection-design.md`. Phase 2, transparent mode, is out of scope here.

## Global Constraints

- No third-party Go modules. `go.mod` has no `require` lines.
- All project text is in English, in the style of the existing README.
- Feature off by default. Off means no proxy port is open.
- The proxy never changes traffic and never hides a bad upstream certificate.
- The proxy offers only `http/1.1`. Leaf certificates: ECDSA P-256, 30 days. CA: ECDSA P-256, two years.
- Copy cap: 1 MiB per direction per connection. Emitter queue: 64 MiB. Decrypted VLAN: 3900. Destination port of rebuilt traffic: 80.
- ClientHello limit: 5 seconds. Automatic bypass: 24 hours. Control file read every 2 seconds, `stats.json` written every 10 seconds, health alarm after 60 seconds of silence.
- Passwords, cookies and bodies are never written to disk.
- The CA key never leaves `data/tls/private`, and only `tlsproxy` mounts that folder.
- Nothing in this phase changes the router or the operating system of a device.

## Review Focus

1. A long-lived or half-closed connection, such as a websocket or a client that stops sending but still reads, keeps working until both sides end. Pinned by `TestHalfCloseKeepsResponse` in Task 8.
2. A SOCKS request for `127.0.0.1`, `169.254.169.254`, or a name resolving to them is refused, so a listed device cannot reach services on the host. Pinned by `TestForbiddenDestination` and `TestForbiddenAfterResolve` in Task 9.
3. A half-written or invalid control file keeps the last good configuration and never crashes the proxy. Pinned by `TestBadConfigKeepsLast` in Task 2.
4. Turning the feature off, or removing a device, ends its open connections within one poll, not only new ones. Pinned by `TestDisableClosesPortAndConnections` and `TestRemovedDeviceLosesConnections` in Task 9.
5. A protocol where the server speaks first, on any port but 443, connects at once, and a client that stays silent on 443 is relayed after the limit instead of hanging. Pinned by `TestNon443RelaysWithoutWaiting` and `TestSilentClientOn443` in Task 8.

## Commands used throughout

```sh
# Go tests, from the repository root
docker run --rm -v "$PWD/tlsproxy:/src" -w /src golang:1.26.9-alpine3.24 \
  sh -c 'apk add -q --no-cache build-base && go test -race ./...'

# Python tests, from the repository root
docker build -q -t mikrokat-app-test app
docker run --rm -e DATA_DIR=/tmp/mk -e TLS_DIR=/tmp/mktls -v "$PWD/tests:/tests:ro" -w /app mikrokat-app-test \
  sh -c 'mkdir -p /tmp/mk /tmp/mktls/control /tmp/mktls/state && python3 -m unittest discover -s /tests'
```

Tasks 1 and 12 run on a disposable Linux host with Docker and `/dev/net/tun`, set up with the README install block. Commit messages follow the repository: a plain sentence starting with a verb. End each with the attribution line the session requires.

---

### Task 1: Accept local TZSP and prove the VLAN tag reaches Suricata

This checks the first risk in the spec before any Go is written.

**Files:**
- Modify: `tzsp/tzsp2tap.py` (the `SOURCE` check in `main`)
- Modify: `tools/send-test-alert.py`
- Modify: `README.md` (the sentence about leaving `ROUTER_HOST` empty)

**Interfaces:**
- Produces: `tzsp` accepts packets from `127.0.0.1` as well as `TZSP_SOURCE`. `send-test-alert.py [host] [port] [vlan]`. A decision for Tasks 7 and 11: the marker is VLAN 3900, or destination port 10080 if the tag is lost.

- [ ] **Step 1:** Add the optional third argument to `send-test-alert.py`. When present, `frame()` inserts `struct.pack("!HH", 0x8100, vlan)` before the `08 00` EtherType.
- [ ] **Step 2:** On the disposable host, set `ROUTER_HOST=192.0.2.1` in `.env`, run `docker compose up -d`, then `python3 tools/send-test-alert.py 127.0.0.1 37008 3900`.
Expected: no alert, and `[tzsp] ... rejected=` grows in `docker logs mikrokat-tzsp` after a minute. This is the failing state.
- [ ] **Step 3:** Change the check to `if SOURCE and addr[0] not in (SOURCE, "127.0.0.1"):`. Update the README: `ROUTER_HOST` no longer needs to be empty for the test.
- [ ] **Step 4:** Rebuild and repeat the command.
Run: `grep '"event_type":"alert"' data/logs/eve-*.json | tail -1 | python3 -c "import json,sys; e=json.loads(sys.stdin.read()); print(e.get('vlan'), e['src_ip'], e['dest_ip'])"`
Expected: `[3900] 192.168.50.10 198.51.100.7`. If `vlan` is missing, record that Tasks 7 and 11 use destination port 10080, as the spec says.
- [ ] **Step 5:** Commit: `Accept TZSP from the local host and tag test traffic`.

### Task 2: Go module, configuration and counters

**Files:**
- Create: `tlsproxy/go.mod`, `tlsproxy/config.go`, `tlsproxy/config_test.go`, `tlsproxy/stats.go`, `tlsproxy/stats_test.go`

**Interfaces:**
- Produces:
  - `type AutoRemoval struct { Device, Name string; At int64 }` with JSON keys `device`, `name`, `at`
  - `type Config struct { Enabled, Socks bool; SocksPort int; Devices, Bypass []string; CAGeneration int; AutoRemove []AutoRemoval }` with JSON keys `enabled`, `socks`, `socks_port`, `devices`, `bypass`, `ca_generation`, `auto_remove`
  - `func LoadConfig(path string, last Config) Config`
  - `func (c Config) Allowed(ip net.IP) bool`
  - `type Stats struct`, safe for concurrent use, with `Inspected()`, `Relayed(reason string)`, `Refused()`, `HandshakeFailed()`, `Copied(n int)`, `CopyDropped()`, `WriteFile(path string, auto []AutoEntry) error`
  - `type AutoEntry struct { Device, Name string; Until int64 }` with JSON keys `device`, `name`, `until`

- [ ] **Step 1: Write the failing tests**

```go
func TestMissingConfigIsOff(t *testing.T)   // LoadConfig on no file: Enabled == false
func TestBadConfigKeepsLast(t *testing.T)   // last := Config{Enabled: true}; file holds `{"enab`; result.Enabled == true
func TestAllowed(t *testing.T)              // Devices ["192.0.2.5"]: true for it, false for 192.0.2.6
func TestStatsFile(t *testing.T)            // keys at, started, inspected, relayed, refused, handshake_failures,
                                            // copied_bytes, copies_dropped, auto_bypass; relayed["bypass"] == 2 after two calls;
                                            // no leftover .tmp file in the folder
```

- [ ] **Step 2:** Run the Go tests. Expected: FAIL, undefined names.
- [ ] **Step 3:** Implement. `go.mod` is `module mikrokat/tlsproxy` with `go 1.26`. `WriteFile` writes a temporary file and renames it.
- [ ] **Step 4:** Run the Go tests. Expected: PASS.
- [ ] **Step 5:** Commit: `Add the proxy configuration and counters`.

### Task 3: ClientHello parser

**Files:**
- Create: `tlsproxy/hello.go`, `tlsproxy/hello_test.go`

**Interfaces:**
- Produces:
  - `type Hello struct { TLS bool; Name string }`
  - `func ParseClientHello(data []byte) (Hello, error)`, returning `ErrNeedMore` when the record is incomplete
  - `func ReadHello(r *bufio.Reader, c net.Conn, limit time.Duration) Hello`, using `Peek` only, so no byte is consumed, and clearing the read deadline before it returns

- [ ] **Step 1: Write the failing tests**

```go
func TestParseRealHello(t *testing.T)     // bytes captured from tls.Client: Name == "example.com", TLS == true
func TestParseNoSNI(t *testing.T)         // TLS == true, Name == ""
func TestParseNotTLS(t *testing.T)        // "GET / HTTP/1.1": TLS == false, no error
func TestParseTruncated(t *testing.T)     // each prefix of a real hello: ErrNeedMore or a Hello, never a panic
func TestReadHelloConsumesNothing(t *testing.T) // after ReadHello, the reader still returns the full hello
func FuzzParseClientHello(f *testing.F)   // seeded with a real hello; must not panic
```

- [ ] **Step 2:** Run the Go tests. Expected: FAIL.
- [ ] **Step 3:** Implement. Check every length against the slice. Accept only records of type 22 and handshake type 1. Parse one record only, up to 16 KiB; a hello spanning records returns `Hello{TLS: true}`.
- [ ] **Step 4:** Run the Go tests, then `go test -run='^$' -fuzz=FuzzParseClientHello -fuzztime=30s`. Expected: PASS, no crash.
- [ ] **Step 5:** Commit: `Read the server name from the ClientHello`.

### Task 4: SOCKS5 handshake

**Files:**
- Create: `tlsproxy/socks.go`, `tlsproxy/socks_test.go`

**Interfaces:**
- Produces:
  - `type Dest struct { Host string; IP net.IP; Port int }`
  - `func Greet(rw io.ReadWriter) (Dest, error)`
  - `func Reply(w io.Writer, code byte) error`
  - Constants `ReplyOK = 0`, `ReplyNotAllowed = 2`, `ReplyUnreachable = 4`, `ReplyCommandNotSupported = 7`

- [ ] **Step 1: Write the failing tests**

```go
func TestGreetIPv4(t *testing.T)     // CONNECT 198.51.100.7:443: Dest.IP, Port == 443
func TestGreetDomain(t *testing.T)   // CONNECT example.com:443: Host == "example.com", IP == nil
func TestGreetIPv6(t *testing.T)
func TestGreetNoAuthOnly(t *testing.T)  // client offers only username/password: reply 0xFF, error
func TestGreetUDPRefused(t *testing.T)  // UDP ASSOCIATE: reply code 7, error
func FuzzGreet(f *testing.F)         // must not panic
```

- [ ] **Step 2:** Run the Go tests. Expected: FAIL.
- [ ] **Step 3:** Implement with `io.ReadFull` and a 255 byte name limit. `Greet` sends no success reply: the caller does, after the upstream connection opens.
- [ ] **Step 4:** Run the Go tests and 30 seconds of `FuzzGreet`. Expected: PASS.
- [ ] **Step 5:** Commit: `Add the SOCKS5 handshake`.

### Task 5: Certificate authority

**Files:**
- Create: `tlsproxy/ca.go`, `tlsproxy/ca_test.go`

**Interfaces:**
- Produces:
  - `func LoadCA(privateDir, stateDir string, generation int) (*CA, error)`, creating `ca.key` (mode 600) and `generation` in `privateDir` and `ca.pem` in `stateDir`, and replacing the pair when `generation` differs from the stored one
  - `func (c *CA) Leaf(name string) (*tls.Certificate, error)`, cached in memory

- [ ] **Step 1: Write the failing tests**

```go
func TestCreateThenReload(t *testing.T)   // two LoadCA calls give the same public key; ca.key mode is 0600
func TestGenerationReplaces(t *testing.T) // generation 2 gives a different key and a new ca.pem
func TestLeafVerifies(t *testing.T)       // chain verifies against ca.pem for DNSName "example.com"; ECDSA P-256; NotAfter within 30 days
func TestLeafCached(t *testing.T)         // same pointer on the second call
func TestLeafLongName(t *testing.T)       // a 300 byte name returns an error, not a panic
```

- [ ] **Step 2:** Run the Go tests. Expected: FAIL.
- [ ] **Step 3:** Implement. The CA subject is `Mikrokat local CA`, with `IsCA`, `MaxPathLenZero`, and validity of two years. Start leaf validity one hour in the past to allow for clock skew.
- [ ] **Step 4:** Run the Go tests. Expected: PASS.
- [ ] **Step 5:** Commit: `Add the local certificate authority`.

### Task 6: Bypass

**Files:**
- Create: `tlsproxy/bypass.go`, `tlsproxy/bypass_test.go`, `tlsproxy/bypass.txt`

**Interfaces:**
- Consumes: `AutoRemoval`, `AutoEntry` from Task 2.
- Produces:
  - `func NewBypass(builtin []string) *Bypass`, and `//go:embed bypass.txt` as `BuiltinBypass`
  - `func (b *Bypass) SetOwn(names []string)`
  - `func (b *Bypass) Match(device, name string, now time.Time) string`, returning `""`, `"bypass"` or `"auto_bypass"`
  - `func (b *Bypass) AddAuto(device, name string, now time.Time)`
  - `func (b *Bypass) Apply(removals []AutoRemoval)`, removing entries added before `At`
  - `func (b *Bypass) Auto(now time.Time) []AutoEntry`

- [ ] **Step 1: Write the failing tests**

```go
func TestSuffixMatch(t *testing.T)    // "bank.example" matches "www.bank.example" and itself, not "notbank.example"
func TestCaseInsensitive(t *testing.T)
func TestAutoExpires(t *testing.T)    // matches at now, not at now + 24h + 1s
func TestAutoIsPerDevice(t *testing.T)// another device does not match
func TestApplyRemoves(t *testing.T)   // removal with At after the entry clears it; with At before keeps it
func TestBuiltinHasECHName(t *testing.T) // cloudflare-ech.com matches
```

- [ ] **Step 2:** Run the Go tests. Expected: FAIL.
- [ ] **Step 3:** Implement. `bypass.txt` has one suffix per line with `#` comments: `cloudflare-ech.com`, Windows and browser update names, and common health and bank names for Italy and Switzerland as a starting point. The guide says the list is not complete.
- [ ] **Step 4:** Run the Go tests. Expected: PASS.
- [ ] **Step 5:** Commit: `Add the bypass lists`.

### Task 7: Emitter

**Files:**
- Create: `tlsproxy/emit.go`, `tlsproxy/emit_test.go`

**Interfaces:**
- Consumes: `Stats` from Task 2.
- Produces:
  - `const DecryptedVLAN = 3900`, or port 10080 per the Task 1 decision
  - `func BuildFrame(src, dst net.IP, sport, dport uint16, seq, ack uint32, flags byte, payload []byte) []byte`
  - `func WrapTZSP(frame []byte) []byte`
  - `func NewEmitter(addr string, queueBytes int, stats *Stats) (*Emitter, error)`, `func (e *Emitter) Run()`
  - `func (e *Emitter) Open(client, server net.IP, clientPort uint16) *Stream`
  - `func (s *Stream) Client(p []byte)`, `func (s *Stream) Server(p []byte)`, `func (s *Stream) Close()`, all safe to call from two goroutines

- [ ] **Step 1: Write the failing tests**

```go
func TestFrameLayout(t *testing.T)   // bytes 12-13 == 0x8100, 14-15 == 3900, 16-17 == 0x0800; IPv4 header checksum valid
func TestTZSPHeader(t *testing.T)    // starts 01 00 00 01 01, then the frame unchanged
func TestConversation(t *testing.T)  // with a capturing sink: SYN, SYN-ACK, ACK; Client("GET") is a data segment at ISN+1,
                                     // followed by an ACK from the server side; Close sends FIN both ways
func TestSegments(t *testing.T)      // 4000 bytes make three segments of at most 1460
func TestCopyCap(t *testing.T)       // 2 MiB through Client: no more than 1 MiB copied; FIN still sent on Close
func TestQueueFullDrops(t *testing.T)// no Run(): Client returns at once, Stats copies_dropped > 0
func TestSendErrorsDoNotStop(t *testing.T) // nothing listening on the port: Run keeps going, frames counted as dropped
```

- [ ] **Step 2:** Run the Go tests. Expected: FAIL.
- [ ] **Step 3:** Implement. IDS reassembly in Suricata only inspects acknowledged data, so every data segment is followed by an ACK from the other side. TCP checksums stay zero: Mikrokat runs Suricata with checksum validation off. A single `Run` goroutine owns the UDP socket and keeps frames in order. Each stream takes a random ISN per side and its own mutex. Destination port is 80.
- [ ] **Step 4:** Run the Go tests. Expected: PASS.
- [ ] **Step 5:** Commit: `Rebuild decrypted traffic as tagged TCP packets`.

### Task 8: Engine

**Files:**
- Create: `tlsproxy/engine.go`, `tlsproxy/engine_test.go`

**Interfaces:**
- Consumes: `Dest` (Task 4), `Hello`, `ReadHello` (Task 3), `CA` (Task 5), `Bypass` (Task 6), `Emitter` (Task 7), `Stats` (Task 2).
- Produces:
  - `func Classify(d Dest, h Hello, match string) string`, returning the relay reason or `""` to inspect. Reasons: `not_443`, `ipv6`, `private`, `not_tls`, `no_name`, `bypass`, `auto_bypass`
  - `type Engine struct { CA *atomic.Pointer[CA]; Bypass *Bypass; Emitter *Emitter; Stats *Stats; Dial func(ctx context.Context, d Dest) (net.Conn, error); Roots *x509.CertPool; HelloLimit time.Duration; Now func() time.Time }`
  - `func (e *Engine) Handle(ctx context.Context, client net.Conn, device net.IP, d Dest, ready func(ok bool))`. `ready` sends the SOCKS reply once the first upstream dial has finished. `Roots` nil means the system pool.

- [ ] **Step 1: Write the failing tests**

Tests use `httptest.NewUnstartedServer` with TLS, a `Dial` that always reaches it, and `Dest{IP: 198.51.100.7, Port: 443}`, so classification passes.

```go
func TestClassify(t *testing.T)                   // table with every reason, and "" for a public 443 hello with a name
func TestInspectCopiesPlaintext(t *testing.T)     // client trusting our CA GETs /x; body returns; sink holds "GET /x"; inspected == 1
func TestOnlyHTTP11Offered(t *testing.T)          // the client's NegotiatedProtocol is "http/1.1" when it offers h2 and http/1.1
func TestBadUpstreamRelaysOriginal(t *testing.T)  // Roots without the server's CA: the client sees the server's own certificate; relayed["upstream"] == 1
func TestClientRejectsOurCert(t *testing.T)       // client without our CA fails; Bypass.Match is auto_bypass; a second connection is relayed
func TestHalfCloseKeepsResponse(t *testing.T)     // client CloseWrite after the request; the reply still arrives in full
func TestNon443RelaysWithoutWaiting(t *testing.T) // server speaks first on port 25: banner within 200 ms
func TestSilentClientOn443(t *testing.T)          // HelloLimit 50 ms: relayed["not_tls"] == 1 and bytes pass afterwards
func TestDialFailure(t *testing.T)                // ready(false) is called and the client connection closes
```

- [ ] **Step 2:** Run the Go tests. Expected: FAIL.
- [ ] **Step 3:** Implement `Handle` in this order:

```
dial upstream -> ready(ok)
if port != 443: relay "not_443"
ReadHello -> Classify -> relay when a reason comes back
tls.Client on the upstream conn (ServerName = name, NextProtos = http/1.1, RootCAs = e.Roots)
  on failure: dial again, relay "upstream", replaying the buffered hello
tls.Server on the buffered client conn (GetCertificate from CA, NextProtos = http/1.1)
  on failure: HandshakeFailed, AddAuto, close
Inspected, Emitter.Open, relay both ways through TeeReaders into Stream.Client and Stream.Server
```

Relaying uses one goroutine per direction and propagates half-close with `CloseWrite`. Everything closes when `ctx` is cancelled. Read client bytes through the same `bufio.Reader` used for the hello.

- [ ] **Step 4:** Run the Go tests with `-race`. Expected: PASS.
- [ ] **Step 5:** Commit: `Add the inspection engine`.

### Task 9: Server, container and compose service

**Files:**
- Create: `tlsproxy/server.go`, `tlsproxy/server_test.go`, `tlsproxy/main.go`, `tlsproxy/Dockerfile`
- Modify: `docker-compose.yml`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `func Forbidden(ip net.IP) bool`, true for loopback, link-local, multicast, unspecified
  - `func (s *Server) Apply(cfg Config)`, idempotent: opens or closes the listener, updates devices, cancels connections of removed devices, reloads the CA when `CAGeneration` changes, applies bypass changes
  - Container `mikrokat-tlsproxy`, folders `/tls/control`, `/tls/state`, `/tls/private`

- [ ] **Step 1: Write the failing tests**

```go
func TestDeviceOutsideListRefused(t *testing.T)      // connection closed before any SOCKS reply; refused == 1
func TestForbiddenDestination(t *testing.T)          // CONNECT 127.0.0.1 and 169.254.169.254: reply code 2, no dial
func TestForbiddenAfterResolve(t *testing.T)         // a name resolving to 127.0.0.1: reply code 2 (resolver injected)
func TestDisableClosesPortAndConnections(t *testing.T) // after Apply with Enabled false: dial refused, open connection ends
func TestRemovedDeviceLosesConnections(t *testing.T)
func TestApplyTwiceKeepsListener(t *testing.T)       // same config: open connections survive
```

- [ ] **Step 2:** Run the Go tests. Expected: FAIL.
- [ ] **Step 3:** Implement `Server` and `main`. `main` makes an Emitter to `127.0.0.1:37008` with a 64 MiB queue, reads the control file every 2 seconds, writes `stats.json` every 10 seconds even while off, and generates the CA only on the first time the feature is enabled.
- [ ] **Step 4:** Write `tlsproxy/Dockerfile`: multi-stage, `golang:1.26.9-alpine3.24` with `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w'`, then `alpine:3.24.3` with `ca-certificates`. Add the `tlsproxy` service to `docker-compose.yml`, following the `tzsp` service: `network_mode: host`, `cap_drop: [ALL]`, `no-new-privileges:true`, `read_only: true`, `logging: *logging`, volumes `./data/tls/control:/tls/control:ro`, `./data/tls/state:/tls/state`, `./data/tls/private:/tls/private`.
- [ ] **Step 5:** Run the Go tests, then `docker compose build tlsproxy && docker compose up -d tlsproxy`.
Expected: PASS, the container stays up, and `ss -ltn | grep 1080` shows nothing.
- [ ] **Step 6:** Commit: `Run the proxy as its own service, off by default`.

### Task 10: Settings tab, control file, PAC and CA download

**Files:**
- Modify: `app/store.py`, `app/web.py`, `docker-compose.yml`, `.env.example`
- Create: `tests/test_tls_settings.py`

**Interfaces:**
- Consumes: the JSON keys in Task 2, the `stats.json` keys in Task 2.
- Produces:
  - Settings `tls_enabled` (False), `tls_socks` (True), `tls_socks_port` (1080), `tls_devices` ([]), `tls_bypass` ([]), `tls_ca_generation` (0), `tls_auto_remove` ([])
  - `store.TLS_DIR`, from env `TLS_DIR`, default `/var/lib/mikrokat-tls`
  - `store.write_tls_control()`, called from `load()` and after every settings save
  - `store.tls_status() -> dict`, returning `{}` when the file is missing or invalid
  - `store.regenerate_ca()`, `store.remove_auto_bypass(device, name)`
  - `web.pac_text(host) -> str`

- [ ] **Step 1: Write the failing tests**

```python
class TlsSettings(unittest.TestCase):
    def test_off_by_default(self): ...              # write_tls_control(): config.json has enabled False
    def test_bad_device_is_refused(self): ...       # save_settings with tls_devices "not an ip" returns an error
    def test_port_conflict_is_refused(self): ...    # tls_socks_port 8088, 5636 and 37008 are refused
    def test_bad_bypass_name_is_refused(self): ...  # "bad name/" returns an error
    def test_control_file_keys(self): ...           # the seven keys in Task 2, with devices split by line
    def test_status_survives_bad_json(self): ...    # tls_status() == {}
    def test_regenerate_raises_generation(self): ...
    def test_remove_auto_bypass_is_capped(self): ...# at most 50 entries stay in tls_auto_remove

class Pac(unittest.TestCase):
    def test_on(self): ...   # 'SOCKS5 mikrokat.lan:1080; DIRECT' in pac_text("mikrokat.lan:8088")
    def test_off(self): ...  # feature off: 'return "DIRECT"'
```

- [ ] **Step 2:** Run the Python tests. Expected: FAIL.
- [ ] **Step 3:** Implement the store functions. `save_settings` keeps its pattern of returning an error message. Write the control file with a temporary file and rename.
- [ ] **Step 4:** Add to `web.py`:
  - tab `("https", "HTTPS inspection")` in `SETTINGS_TABS`, with `switch`, `.reveal` and `field` as the AI tab does
  - inside the reveal: entry point switch, port, devices and own bypass as textareas, a CA download link, a Regenerate button, automatic bypass rows with Remove, and the counters from `tls_status()`
  - plain warnings in the tab: URLs of inspected devices stay in the logs for as long as EVE and EveBox keep them, and inspect only your own devices or with the consent of the person using them
  - `GET /tls.pac` before `authorized()`, type `application/x-ns-proxy-autoconfig`
  - `GET /tls/ca.pem` after `authorized()`, type `application/x-x509-ca-cert`, 404 when missing
  - `POST /tls/regenerate` and `POST /tls/bypass/remove`, protected by the CSRF token like the other forms
  - an English section in `GUIDE`
- [ ] **Step 5:** In `docker-compose.yml`, mount `./data/tls/control:/var/lib/mikrokat-tls/control` and `./data/tls/state:/var/lib/mikrokat-tls/state:ro` in `mikrokat`.
- [ ] **Step 6:** Run the Python tests. Expected: PASS.
- [ ] **Step 7:** Commit: `Add the HTTPS inspection settings and PAC file`.

### Task 11: Decrypted badge and health alarm

**Files:**
- Modify: `app/mikrokat.py`, `app/store.py`, `app/web.py`, `app/health.py`
- Create: `tests/test_tls_health.py`

**Interfaces:**
- Consumes: `store.tls_status()`; the marker decided in Task 1.
- Produces:
  - `store.is_decrypted(event) -> bool`
  - table `hourly_decrypted(hour, address, count)`, cleaned with the other hourly tables
  - `store.decrypted_count(address, days=7) -> int`
  - `health.tls_problem() -> str | None`, and problem key `tls` in `health.check()`, with the message `HTTPS inspection has stopped. Devices are browsing without inspection.`

`health.check()` returns early when Suricata does not answer, so it calls `tls_problem()` before that return.

- [ ] **Step 1: Write the failing tests**

```python
class Decrypted(unittest.TestCase):
    def test_marker(self): ...          # {"vlan": [3900]} True; {"vlan": [10]} False; {} False
    def test_count_both_ends(self): ... # count_alert with a marked event counts src_ip and dest_ip

class Health(unittest.TestCase):
    def test_off_never_alarms(self): ...      # tls_enabled False and no stats file: tls_problem() is None
    def test_fresh_stats_ok(self): ...        # "at" 5 seconds ago: None
    def test_stale_stats_alarm(self): ...     # "at" 61 seconds ago: the message
    def test_missing_stats_alarm(self): ...   # tls_enabled True, no file: the message
```

- [ ] **Step 2:** Run the Python tests. Expected: FAIL.
- [ ] **Step 3:** Implement. In `handle`, pass `decrypted=store.is_decrypted(event)` to `activity_add`. In the Live script, add a `decrypted` badge when `e.decrypted` is true, using the `.badge` class. On the host page, add a tile `Decrypted alerts, 7 days` when the count is above zero.
- [ ] **Step 4:** Run the Python tests. Expected: PASS.
- [ ] **Step 5:** Commit: `Show decrypted alerts and warn when the proxy stops`.

### Task 12: End-to-end test, documentation and review

**Files:**
- Create: `tests/e2e/run.sh`, `tests/e2e/server.py`, `tests/e2e/docker-compose.e2e.yml`
- Modify: `README.md`, `.env.example`, `.gitignore` if needed

**Interfaces:**
- Consumes: the whole feature.
- Produces: `tests/e2e/run.sh`, which prints `PASS` or names the failing check and exits non-zero.

- [ ] **Step 1: Write `tests/e2e/run.sh`** for the disposable host. It uses a private CA and `SSL_CERT_FILE` in the compose override, so the proxy trusts the test server. It adds `198.51.100.7/32` to `lo`, because a private address would be relayed, and starts `server.py` on port 443 with a certificate for `test.example.net`. It writes `data/tls/control/config.json` with device `127.0.0.1`, and a rule in `rules/local.rules`:

```
alert http any any -> any any (msg:"MIKROKAT E2E"; http.uri; content:"/mikrokat-e2e"; sid:9000001; rev:1;)
```

Checks, each with `curl --socks5 127.0.0.1:1080 --resolve <name>:443:198.51.100.7`:

| Check | Expected |
|---|---|
| Fetch `https://test.example.net/mikrokat-e2e` with `--cacert ca.pem` | Body returned, leaf issued by `Mikrokat local CA` |
| Suricata | An alert with sid 9000001, `dest_ip` 198.51.100.7 and the decrypted marker |
| Wrong name, `https://bad.example.net/` | Curl fails on a certificate from the test CA, not ours; `relayed.upstream` grows |
| Client without our CA, twice | First fails, second is relayed; `auto_bypass` lists it |
| POST with `Cookie: e2e-cookie-value` and body `e2e-body-value` | `grep -r` for both values under `data/` finds nothing |
| Set `enabled` to false | Port 1080 refused within 3 seconds |
| Stop `tlsproxy` with the feature on | Health alarm text on the Overview page after 60 seconds, and `/tls.pac` still ends in `DIRECT` |

- [ ] **Step 2:** Run it on the disposable host. Expected: `PASS`. Fix what fails in the task that owns the code.
- [ ] **Step 3:** Measure on the disposable host and record the numbers. Off: `docker stats` under 30 MB. On: under 100 MB, and a 1 GiB download from `server.py` through SOCKS at 100 Mbps or more, with `copies_dropped` and bytes seen by Suricata compared.
- [ ] **Step 4:** Add a README section after Rules: what it does, what stays encrypted, how to import the CA into one Firefox profile, and how to use the PAC file. Then state the limits: apps must be configured, a program can ignore SOCKS, and URLs stay in the logs. Add `tlsproxy` to the requirement notes with the measured numbers.
- [ ] **Step 5:** Commit: `Add the end-to-end test and the HTTPS inspection guide`.
- [ ] **Step 6:** Run `ecc:go-reviewer` on `tlsproxy/` and `ecc:security-reviewer` on the whole branch diff. Fix what is confirmed, then repeat Steps 2 and 3 if code changed. Commit the fixes.
- [ ] **Step 7:** Stop before real use. Deploying to the real host and importing the CA into a Firefox profile is the owner's decision, and it comes with its own checks: common sites, a bank, a pinned app, and a test rule showing the real device.
