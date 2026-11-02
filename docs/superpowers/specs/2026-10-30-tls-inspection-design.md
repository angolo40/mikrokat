# HTTPS inspection for Mikrokat

Date: 2026-10-30. Status: implemented, phase 1. Branch: `tls-inspection`.

## Goal

Let Suricata read the HTTPS traffic of a few devices the owner chooses, without a third-party product and without giving up what makes Mikrokat useful: it is light, optional and it does not get in the way when it is off.

Success means an owner can turn the feature on from Settings, send one browser profile through it, and see a Suricata alert raised on content that used to be encrypted, tied to the real device and the real server.

## Decisions already taken

| Topic | Decision |
|---|---|
| Who writes the proxy | Our own. PolarProxy is not used: it is proprietary, free only up to 10 GB or 10,000 TLS sessions a day, and it has no TZSP output. The test network makes about 3,600 outbound HTTPS connections in two hours. |
| Scope | Only devices chosen by the owner. First device: one PC. |
| When the proxy stops | Devices keep browsing, uninspected (fail-open). |
| Where it lives | Inside Mikrokat: same stack, same login, same Settings page. |
| Switch | On and off from Settings, off by default. Each entry point can be enabled alone. |
| Entry points | Two entries, one engine: SOCKS first, transparent routing second. |
| Router changes | Rules are added by hand once, as for the existing Mikrokat rules. There is no automatic router setup. Mikrokat only edits an address list. |

## Out of scope

- Phones, TVs, voice assistants and IoT devices. Most cannot trust a private certificate authority.
- Devices on the same subnet as the Mikrokat host in transparent mode. They can use SOCKS.
- HTTP/2 and HTTP/3 parsing. The proxy offers HTTP/1.1 only, and QUIC is not proxied.
- Storing decrypted traffic in any capture file.
- Changing traffic. The proxy reads, it never edits. Blocking stays on the router, as today.
- Other sites, more than one router, automatic router setup.

## How it works

```
Device with our CA
   |                     (1) SOCKS: the app connects to the proxy
   |                     (2) Transparent: the router routes TCP 443 through the host
   v
tlsproxy container ---- verified TLS ----> real server
   |
   | plaintext copy, rebuilt as TCP packets, sent as TZSP to udp/37008
   v
tzsp container --> tzsp0 --> Suricata --> Mikrokat and EveBox
```

Suricata cannot decrypt anything. It reads the plaintext only because the proxy rebuilds it as ordinary packets and feeds them through the path that already exists.

## Components

### Container

New service `tlsproxy`, built from `tlsproxy/`, written in Go with the standard library only, and no third-party modules. The build uses an exact Go image tag and the final image is Alpine. Phase 2 adds `iptables` to it.

It runs apart from `mikrokat-app` because every web update restarts that process, which would drop live connections. It always runs, and listens on nothing while the feature is off, because Mikrokat has no Docker socket and cannot start containers.

Compose settings follow the other services: host network, `cap_drop: ALL`, `no-new-privileges`, `read_only`, the shared logging anchor. `NET_ADMIN` is added in phase 2 only.

### Engine

Each connection follows the same steps, whichever entry it came from:

1. Refuse it unless the source address is in the device list.
2. Get the destination address and port from the entry point, after resolving a name. Refuse loopback, link-local, multicast and unspecified destinations, private, CGNAT (100.64.0.0/10) and unique-local (fc00::/7) destinations, the host's own addresses, and the subnets of its Docker bridges, with no allow-list. A listed device, or a web page through DNS rebinding, then cannot reach the LAN, the router, services on the host, or containers without a login, such as EveBox, from the host's address.
3. If the port is 443, read the TLS ClientHello without consuming it, with a 5 second limit. Other ports skip this step, because protocols such as SMTP wait for the server to speak first.
4. Relay it untouched, counting the reason, if any of these is true:
   - the port is not 443, or the bytes are not TLS
   - the device or the destination is IPv6, or the destination is private, which only the transparent entry can bring here
   - there is no server name
   - the name matches the bypass list or the automatic bypass
   - a leaf cannot be signed, because the CA has expired. The reason is `ca_expired`, and it adds no automatic entry
5. Open TLS to the real server, verify its chain, name and dates against the roots in the image, and offer only `http/1.1`.
6. If that verification fails, relay the original connection untouched, so the client sees the real certificate and shows its usual warning. The proxy never hides a certificate that fails these checks. They are all it does: revocation and Certificate Transparency are lost for inspected sites, because the browser sees only our leaf, so a revoked certificate is hidden.
7. Present a leaf certificate for the same name, signed by our CA.
8. Relay bytes both ways and hand a copy to the emitter.

### SOCKS entry (phase 1)

SOCKS5 without authentication, TCP `CONNECT` only, port 1080 by default. `UDP ASSOCIATE` is refused, so QUIC falls back to TCP by itself. Access is limited by the device list.

Mikrokat serves a PAC file at `/tls.pac`, without login, so browsers get the fail-open behaviour:

```
function FindProxyForURL(url, host) {
  if (url.substring(0, 6) != "https:" && url.substring(0, 4) != "wss:") return "DIRECT";
  if (isPlainHostName(host)) return "DIRECT";
  if (/<literal private address>/i.test(host)) return "DIRECT";
  return "SOCKS5 <host>:1080; DIRECT";
}
```

Traffic that is not HTTPS is never inspected, and neither are private addresses, so proxying them would only hide the real device.

### Transparent entry (phase 2)

Routing instead of NAT, because NAT would hide the real destination and leave connections without a server name with nowhere to go.

On the router, added by hand once:

- address list `mikrokat-tls`
- routing table `mikrokat-tls`, with a default route through the Mikrokat host and `check-gateway=ping`
- a mangle rule marking TCP 443 from that list, limited to the client LAN interface, so packets forwarded back by the host cannot loop
- a Netwatch TCP check on the transparent port that disables the mangle rule when the port stops answering

On the host, the proxy adds an `iptables` `REDIRECT` from TCP 443 of the listed devices to port 8443 when transparent mode starts, removes it when it stops, and reads the destination with `SO_ORIGINAL_DST`.

Mikrokat adds and removes devices in `mikrokat-tls` through its existing router API access, so the switch acts at once.

### Certificates

The proxy creates a private CA the first time the feature is turned on: ECDSA P-256, two years. Leaf certificates are ECDSA P-256, valid 30 days, and cached in memory.

The CA key stays in `data/tls/private`, mounted only in `tlsproxy`, mode 600. The public certificate is downloadable from Settings. A Regenerate button replaces the pair at once, whether or not the feature is on, and devices must then import the new one.

### Bypass

- **Built-in list:** suffixes for banks, health services and Windows and browser update services, stored as a file in the repository. It also holds the public names used by Encrypted Client Hello, such as `cloudflare-ech.com`: a real ECH extension cannot be told from the fake one browsers send, so the outer name is the only signal.
- **Own list:** names the owner adds in Settings.
- **Automatic:** when a client aborts the handshake with our certificate twice within 10 minutes, with an alert, a plain close or a reset, that device and exact name are relayed untouched for 24 hours. This is how apps with pinned certificates keep working. A device that completed a handshake with our certificate for that name in the last 24 hours earns no entry, and neither does a client the proxy itself refused for ALPN or TLS version: it never saw our certificate.

### Emitter

Plaintext is rebuilt as a normal TCP conversation: handshake, data in 1460 byte segments with correct sequence numbers, then close. Addresses are the real device and the real server, the destination port is 80, and each frame carries VLAN tag 3900. The tag marks decrypted traffic in EVE and keeps it apart from real flows.

Frames are wrapped in TZSP and sent to `127.0.0.1:37008`. The `tzsp` container must also accept loopback, not only `TZSP_SOURCE`.

Two limits protect the host:

- Copies stop after 1 MiB per direction per connection, the depth Suricata reassembles by default. Relaying continues.
- The emitter queue is bounded at 64 MiB. When it is full the copy is dropped and counted, and browsing is never slowed down.

### Control and status

The app has no socket to the proxy. They share files:

| Folder | Written by | Holds |
|---|---|---|
| `data/tls/control` | app | `config.json`: on or off, entry points, devices, own bypass list. The proxy reads it every 2 seconds. |
| `data/tls/state` | proxy | `ca.pem`, and `stats.json` every 10 seconds and when the state of the port changes |
| `data/tls/private` | proxy | `ca.key` |

### Web

New Settings tab, HTTPS inspection, using the existing switch and reveal pattern and hidden details while off:

- main switch and one switch per entry point
- device list, chosen from known names or typed
- CA download and Regenerate
- own bypass list, and the current automatic bypass entries with a Remove button
- counters: inspected, relayed by reason, refused, handshake failures, copies dropped
- English setup guide beside the form, including the consent note below

Alerts from decrypted traffic get a `decrypted` badge on Live and on the host page. The allowlist and notifications need no change: they already work on the addresses in the event. Block never acts on these alerts, which are recorded as `Would block`: a page could otherwise send a crafted URL to a shared CDN and get it blocked for the whole network.

### Health

`health.check()` reports a problem when the feature is on and `stats.json` is older than 60 seconds, so a stopped proxy reaches the owner through the usual channels. It also reports one when SOCKS is on and `stats.json` says `listening` is false, with the reason from `error`: a taken port or a CA that cannot load leaves the proxy running and the PAC going direct. Without this, fail-open would be silent. `stats.json` also holds `ca_expires`, and a separate problem appears when that is under 30 days away.

## Security and privacy

- The CA key can impersonate any site to every device that trusts it. It never leaves `data/tls/private`. LXC backups contain it, and the guide says so. Regenerate does not contain a leak by itself, because a new CA does not revoke the old one: the guide says to delete the old CA from every device, and on removal also to destroy backups that hold the key.
- Each device trusts our CA by choice. For the first test only a Firefox profile does, not the operating system.
- Passwords, cookies and bodies are never written to disk. `dump-all-headers`, `http-body` and alert `payload` stay off, and a test checks it.
- Suricata's `http` events do store host, URL and user agent for decrypted traffic, and its alerts add the referrer and redirect target, so a password or token in a URL is written. EVE keeps them for `Keep logs for`, 1 to 90 days, up to 4 GB. EveBox keeps them for 7 days and 4 GB whatever is set. This cannot be filtered per flow in Suricata, so Settings states it plainly.
- Root on the host can capture plaintext on `tzsp0` up to the copy limit, though nothing stores it.
- The guide says to inspect only your own devices, or with the consent of the person using them.
- Everything arriving at the proxy is attacker-controlled. The ClientHello and SOCKS parsers are bounded and fuzzed.

## Failure behaviour

| Event | SOCKS | Transparent |
|---|---|---|
| Feature switched off | Port closes, PAC goes direct | List emptied, port closes |
| Proxy stops, host alive | PAC goes direct | Packets are forwarded by the host, then Netwatch disables the rule |
| Host off | PAC goes direct | `check-gateway` drops the route |
| Router unreachable when switching off | Not affected | Error shown, `REDIRECT` removed, traffic still flows through the host |
| Real server has a bad certificate | Relayed, client warns | Same |
| Client rejects our certificate | Automatic bypass after the second try within 10 minutes | Same |
| Emitter queue full | Copy dropped and counted | Same |
| CA has expired | Relayed, counted as `ca_expired` | Same |
| Port cannot open, or the CA cannot load | Health alarm with the reason, PAC goes direct | Not decided yet |
| Over a connection cap | Closed at once, counted as refused | Same |

## Delivery

**Phase 1: engine and SOCKS.** Container, engine, certificates, bypass, emitter, Settings tab, health, tests. Nothing on the router or in the operating system of the test PC changes. First use: one Firefox profile on that PC.

**Phase 2: transparent mode.** Starts only after phase 1 works and needs its own approval, because it changes the router and every HTTPS connection of the PC. It begins with a test of `REDIRECT` in the unprivileged LXC, on a spare address, and the PC moves to it only with a way back ready.

## Testing

- Go unit tests: SOCKS parsing, ClientHello parsing with fuzzing, leaf certificates, frame building, bypass matching, automatic bypass.
- Integration, in Docker with a private test server:
  - plain fetch through SOCKS
  - a local Suricata rule fires on a path inside TLS, with the real addresses and VLAN 3900
  - a source outside the list is refused
  - a bad upstream certificate reaches the client unchanged
  - a client that rejects our certificate triggers the bypass
  - switching off closes the ports
  - stopping the proxy makes the PAC go direct
  - no password or cookie sent in a test request appears anywhere under `data/`
- Review by `ecc:go-reviewer` and `ecc:security-reviewer` before phase 1 is called done.
- Measured on the real host: CPU, RAM and throughput.

## Differences in the implementation

Measurements and reviews changed the design in these places.

- **Pacing.** The emitter sends 16 KiB per millisecond, about 10 MB/s, because UDP to `tzsp` has no backpressure and the kernel dropped frames that Suricata then missed as gaps. Copies of faster transfers wait in the queue or are dropped. Loss between the proxy and `tzsp` under overload is not counted. `tests/e2e/run.sh` checks for it.
- **Memory limit.** The Go heap is limited to the 64 MiB queue plus 32 MiB, 96 MiB in all, so a full queue does not double. While the queue is full, the collector costs the relay some speed. Compose adds `mem_limit: 256m` and `pids_limit: 128`.
- **105 MB peak under overload.** A full queue with 100 connections at once peaks at about 105 MB, over the 100 MB in the success criteria. This is accepted: normal use is 13 MB, and the peak needs a sustained overload.
- **Connection limits.** The proxy holds 512 connections, 128 per device, and closes any over a cap at once, counted as refused. A relay ends after 10 minutes with no bytes in either direction, and 60 seconds after the first half-close, because a hostile server could otherwise keep a half-closed connection for ever.
- **Private destinations refused.** The design relayed private destinations. SOCKS now refuses them, with CGNAT and unique-local ones and with no allow-list, and the PAC file sends them direct, because they gave a listed device, or a web page through DNS rebinding, the network position of the host.
- **Own CA.** The design had only the generated CA. An owner can now upload a private CA on the tab: the app leaves it in a new folder, `data/tls/incoming`, mounted in both containers, and the proxy checks it, installs it as `own-ca.pem` and `own-ca.key` in `data/tls/private`, and deletes both from `incoming`. While it is in use, `ca.pem` holds its chain and `generated-ca.pem` in the private folder keeps the certificate it replaced, so going back finds the same CA. Own files that stop being valid close the port with no fallback, unlike a generated pair, which is replaced. Stop using my CA is a `remove-own-ca` file in `incoming`, because a request in the control file would stay there and take the next upload too.
- **Own CA request.** The recommended way to use an own CA keeps its key on the proxy. The app raises `ca_request` in the control file (with `ca_request_name`), the proxy makes an ECDSA P-256 key in `private/own-ca-request.key` and a signing request in `state/own-ca.csr`, and the owner signs it with their own root and uploads the certificate alone. The proxy checks it as an upload, with the pending key, and installs both. `ca_request_cancel` drops the pending pair. The counters the proxy has handled are kept in `private/own-ca-request.seen`, so a restart does not make a new key. A certificate that arrives with no key and no pending request is refused at once. Stats add `ca_request_pending` and `ca_request_name`.

## Success criteria

Phase 1 is done when:

- common sites work normally in the test Firefox profile, and a bank and a pinned client still work through bypass
- a test rule fires on decrypted content and shows the test PC and the real server
- with the feature off, no proxy port is open and the proxy uses under 30 MB of RAM
- with the feature on, it uses under 100 MB, and a download through SOCKS reaches at least 100 Mbps
- stopping the proxy leaves the profile browsing directly, and the owner gets a health alarm

## Risks to check first

| Risk | Check | If it fails |
|---|---|---|
| The VLAN tag is lost on the way to Suricata | First integration test | Mark decrypted traffic with destination port 10080 |
| Loopback TZSP loses packets under load | Throughput test, comparing bytes sent and seen | Lower the copy limit |
| `REDIRECT` does not work in the unprivileged LXC | First step of phase 2 | Run the transparent entry on a privileged host, or keep SOCKS only |
| Encrypted Client Hello grows | Counter of relayed connections by reason, and the `cloudflare-ech.com` bypass entry | Accept it: those connections stay uninspected |
