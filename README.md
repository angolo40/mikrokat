# Mikrokat

Lightweight intrusion detection for MikroTik routers.

Mikrokat runs Suricata next to your router, shows what it finds on a clean dashboard, notifies you, and can block attackers on the router through its API. It installs with one `docker compose` and needs about 600 MB of RAM with the full ET Open ruleset.

It is the lightweight successor of [mikrocata2selks](https://github.com/angolo40/mikrocata2selks), without the heavy NDR stack.

![Mikrokat overview, with sample data](docs/overview.png)

## Features

- **Detection:** Suricata 8 with the ET Open ruleset, updated from the web page without stopping it.
- **Dashboard:** alerts per hour, top rules and addresses, and a world map of where alerts come from.
- **Device names:** shows the names from your router's DHCP leases instead of bare addresses, with a page for each host.
- **Health alarms:** warns you if traffic stops arriving, the rules get old, the disk fills up or the router stops answering.
- **Automatic rule updates:** daily or weekly, without stopping Suricata.
- **Live page:** alerts and actions as they happen, with repeats grouped.
- **HTTPS inspection:** optional and off by default. Suricata can read the HTTPS of the devices you choose.
- **Blocking:** automatic or by hand, through a MikroTik address list. Blocks are put back after a router restart, and repeat offenders can be blocked for longer.
- **Safe by default:** starts in Monitor mode, which only reports. Private networks and major DNS servers are protected from blocks.
- **Notifications:** Telegram, email and webhooks for Slack, Discord, Microsoft Teams or your own service, plus an optional daily summary.
- **Explain:** optional button that describes a rule in plain words, using your own AI model. It only sends the rule text and cannot block anything.
- **SIEM export:** optional alert file, syslog or Splunk HEC, in Suricata's EVE format.
- **Events:** [EveBox](https://evebox.org) is included for browsing alerts, behind the same sign-in.
- **Single sign-on:** optional OpenID Connect, for Authentik, Keycloak, Authelia and others.

## How it works

```
MikroTik  -- TZSP/UDP 37008 -->  tzsp (TAP device tzsp0)  -->  Suricata  -->  eve log
    ^                                                                            |
    |                                                                            v
    +------ address list (when blocking is on) <---------------------------  Mikrokat
                                                                              |     |
                                                    notifications and SIEM <--+     +--> web pages
```

The router copies traffic to Mikrokat with TZSP. Mikrokat only sees what the router sends, so it does not need to sit in the traffic path. If it stops, your network keeps working.

| Container | Role |
|---|---|
| `mikrokat-tzsp` | Receives TZSP and feeds a virtual interface |
| `mikrokat-suricata` | Inspects the traffic |
| `mikrokat-app` | Web pages, alert handling, blocking, notifications |
| `mikrokat-evebox` | Event browser |
| `mikrokat-rules` | Applies rule updates on request |
| `mikrokat-tlsproxy` | Optional HTTPS inspection. Listens on nothing while it is off |

## Requirements

| | Minimum | Recommended |
|---|---|---|
| CPU | 2 cores, x86-64-v2 | 4 cores |
| RAM | 2 GB | 4 GB |
| Disk | 16 GB | 32 GB SSD |

You also need:

- Linux with Docker Engine and the Compose plugin ([install guide](https://docs.docker.com/engine/install/)), plus `git`.
- `/dev/net/tun` available to Docker.
- A MikroTik router with RouterOS 7. Blocking needs the API service, on port 8729 or 8728.

**Proxmox LXC:** works unprivileged. Turn on `nesting` and `keyctl`, and pass `/dev/net/tun`. On a VM, set the CPU type to `host`.

**Measured use:** about 600 MB of RAM and 1.1 GB of images, with 53,000 rules on a 4-core Intel N305. At about 3,000 packets per second (20 Mbps), Suricata and the TZSP receiver used about 5% of one core each. Applying rules briefly needs 500 MB more. Heavier links need more CPU, so watch **Packets dropped** on the Overview page.

**HTTPS inspection:** while off, `mikrokat-tlsproxy` uses about 3 MB of RAM and opens no port. While on, on the same CPU and with both ends on that host, a 1 GiB download through it reached 2.4 to 3.2 Gbps, with the proxy using one core and 13 MB of RAM. With 100 downloads at once and its queue full it peaked at about 105 MB. The copy for Suricata is paced to about 10 MB/s: of a 1 MiB burst, 1,546 frames were sent and 1,546 arrived.

Disk use is capped: Suricata logs at 4 GB, the EveBox database at 4 GB, and container logs at 30 MB each.

Do not run Mikrokat on the router. A container on a MikroTik device has little memory, slows routing, and puts a parser of hostile traffic on your gateway.

## Install

```sh
git clone https://github.com/angolo40/mikrokat.git
cd mikrokat
cp .env.example .env
sed -i "s/^WEB_PASSWORD=.*/WEB_PASSWORD=$(tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 20)/" .env
chmod 600 .env
docker compose run -T --rm --no-deps suricata suricata-update --no-reload </dev/null
docker compose up -d
grep WEB_PASSWORD .env
```

The first run takes a few minutes: it builds three images and downloads the others and the rules. The last line shows your password.

Open `http://<host>:8088` and sign in as `admin`. The Settings page has a setup guide next to the form, and you can change the password there.

To check the path without touching the router (needs `python3`):

```sh
python3 tools/send-test-alert.py
```

A `Would block` entry appears on the Overview page. `ROUTER_HOST` can stay set: Mikrokat also accepts TZSP from its own host (`127.0.0.1`).

## Router setup

### 1. Send traffic to Mikrokat

Replace `WAN` with your interface list and `192.0.2.10` with the Mikrokat host.

```
/ip firewall mangle add chain=forward out-interface-list=WAN action=sniff-tzsp sniff-target=192.0.2.10 sniff-target-port=37008 comment=mikrokat
/ip firewall mangle add chain=forward in-interface-list=WAN action=sniff-tzsp sniff-target=192.0.2.10 sniff-target-port=37008 comment=mikrokat
```

These rules send only the traffic to and from the internet. In the forward chain the router still sees internal addresses, so you can tell which host was involved. Fasttracked connections skip the mangle table, so they are not inspected.

Set `ROUTER_HOST` in `.env` to accept TZSP only from your router, then run `docker compose up -d`.

### 2. Allow blocking (optional)

Give Mikrokat only the rights it needs, and only from its own address:

```
/user group add name=mikrokat policy=api,read,write
/user add name=mikrokat group=mikrokat address=192.0.2.10 password=CHOOSE_ONE
/ip firewall raw add chain=prerouting action=drop src-address-list=mikrokat comment=mikrokat
/ip firewall raw add chain=prerouting action=drop dst-address-list=mikrokat comment=mikrokat
```

For IPv6, repeat the raw rules under `/ipv6 firewall raw` and turn on **Block IPv6 addresses**.

Enter the connection in Settings, then use **Test connection**. RouterOS rights are not limited to one list: this user can change the router's configuration, though not its users. Keep the address restriction.

### 3. Start in Monitor

Leave Mikrokat in Monitor for a few days. Mute noisy rules on the Overview page, and add your public addresses and trusted hosts to the Allowlist. Then switch to Block in Settings.

Your own servers can trigger rules. Without an allowlist entry, Block would cut them off.

To remove everything from the router:

```
/ip firewall mangle remove [find comment~"mikrokat"]
/ip firewall raw remove [find comment~"mikrokat"]
/ipv6 firewall raw remove [find comment~"mikrokat"]
/user remove mikrokat
/user group remove mikrokat
```

## Pages

| Page | What it does |
|---|---|
| **Overview** | Status, charts, map, devices, top rules and addresses |
| **Host** | One device or address: its rules, contacts and actions. Open it from any address |
| **Live** | Alerts and actions as they arrive |
| **Blocked** | The block list: block and unblock by hand, in any mode |
| **Rules** | Turn rules off, add your own, apply updates |
| **Allowlist** | Addresses that are never blocked or reported |
| **Connections** | With HTTPS inspection on: what the proxy did with each connection, with statistics for the last 24 hours |
| **Settings** | Protection, notifications, router, data, HTTPS inspection and account |
| **Events** | EveBox, on port 5636 |

## Rules

Mikrokat starts from ET Open and updates it every day at 04:00. You can change that on the Data tab of Settings. On the Rules page you can turn rules off, add your own and press **Apply rules** to update right away, without stopping Suricata. The same files live in `rules/` if you prefer an editor, and `tools/update-rules.sh` applies them.

To keep a rule in Events but stop its notifications and blocks, use **Mute**.

## HTTPS inspection

Suricata cannot read HTTPS, so it sees little more than a name and a size. For the devices you choose, Mikrokat can read that traffic. `mikrokat-tlsproxy` connects to the real site, checks its certificate chain, name and dates, and gives the browser a certificate of its own, signed by a private CA that you trust on that device. It makes a copy of the traffic in memory and feeds it to Suricata as plain HTTP. Your rules then fire on URLs and content, and each alert shows the real device and server, with a `decrypted` badge on the Live page.

It is off by default. The proxy only reads: it never changes traffic, and blocking stays on the router. A site whose certificate fails those checks is passed through untouched, so the browser shows its usual warning. If the proxy stops, or it cannot open its port, browsers using the PAC file below go direct, and a health alarm appears within about two minutes. Another alarm warns when the CA has less than 30 days left.

**Inspect only your own devices, or with the consent of the person using them.** Whoever runs Mikrokat can see the URLs they open.

### What stays encrypted

Suricata sees nothing inside these. The Numbers card on the HTTPS inspection tab counts by reason the connections that reach the proxy. Programs that do not use the proxy, QUIC, and bytes past the first 1 MiB have no counter.

- Devices that are not on your list, and programs on a listed device that do not use the proxy.
- Names on the bypass list. The **Never inspect these names** field on the tab opens already filled in with the defaults from [`tlsproxy/bypass.txt`](tlsproxy/bypass.txt): banks and payments, health and public services, update services and Google. The proxy writes them to `data/tls/state/bypass-defaults.txt` for the page to show. Edit the field freely: the first time you save, what is in it becomes your whole list, so removing a default really removes it, and the defaults never come back by themselves. `cloudflare-ech.com` always stays skipped, because Encrypted Client Hello needs it. The list is a starting point, not a complete one: it names a few institutions, in Italy and Switzerland, plus PayPal. Any other bank, payment or health site is decrypted unless you add it first.
- Apps that refuse the Mikrokat certificate, such as those with a pinned certificate. After two refusals within 10 minutes, that device and that exact name are relayed untouched for 24 hours. A device that finished a handshake with the Mikrokat certificate for a name in the last 24 hours does not earn this for that name.
- Sites that ask for a client certificate, and sites with a bad certificate.
- Everything, once the CA has expired. Connections keep working and are counted as `ca_expired`. Press **Regenerate the CA** before that, or upload a new CA if you use your own.
- Connections without a server name, and Encrypted Client Hello, whose outer name `cloudflare-ech.com` is on the bypass list.
- Ports other than 443, IPv6 destinations, and devices that reach the proxy over IPv6.
- QUIC. The proxy takes TCP only, so browsers fall back to TCP.
- Everything after the first 1 MiB in each direction of a connection. It is relayed, but no copy is made. A rule on an HTTP response body sees less: Suricata reads the first 100 KiB by default.

### Set up one Firefox profile

1. On the HTTPS inspection tab of Settings, add the address of the device, turn on the switch and save.
2. Wait a few seconds, so the proxy can make the CA, then use **Download the CA certificate** on the same tab.
3. In Firefox, open `about:profiles`, create a new profile and launch it. Only this profile will trust the CA, not the rest of the computer.
4. In that profile, open Settings, Privacy & Security, Certificates, View Certificates, Authorities, then Import. Choose the file and tick **Trust this CA to identify websites**.
5. Under Settings, General, Network Settings, choose **Automatic proxy configuration URL**, enter `http://<host>:8088/tls.pac` and tick **Proxy DNS when using SOCKS v5**. The proxy then looks up each name. Otherwise Firefox does it, outside the proxy, and can learn the keys for Encrypted Client Hello, which hide the name from the proxy.

To check it, open a site in that profile and look at its certificate: the issuer is `Mikrokat local CA`, or your own CA's name if you uploaded one.

### Use your own CA

If you already run a private CA and your devices trust it, the proxy can sign with that one instead of the CA it generates.

Make a dedicated intermediate CA for this, with a short life, and never upload your root.

**Recommended: create the key on the proxy.** The key never crosses the network, and your root key never leaves your machine. Signing never happens on the page.

1. On the HTTPS inspection tab, under **Create a key here**, set the CA name (default `Mikrokat Inspection CA`) and press **Create request**. A new request replaces an older pending one.
2. After a few seconds, reload the tab. Download the request (`mikrokat-ca.csr`) and the extensions (`mikrokat-ca.ext`), and sign them with your root, on your machine:

   ```
   openssl x509 -req -in mikrokat-ca.csr -CA root.crt -CAkey root.key -CAcreateserial -days 365 -sha256 -extfile mikrokat-ca.ext -out mikrokat-ca.pem
   ```

3. Choose `mikrokat-ca.pem` under **Upload signed certificate** and press the button. A chain is fine: the signed CA first, then the root if you like. No key is needed, because the proxy has it.
4. Reload after a few seconds. The tab shows the CA in use, or why the certificate was refused. A certificate that does not fit the pending key, or that fails any check of an upload, leaves the pending request and the CA in use as they were. **Cancel request** deletes the pending key.

The pending key is `data/tls/private/own-ca-request.key`, mode 600. Only the request, which holds no secret, is in `data/tls/state`.

**Or upload a certificate and key you already have.** The form under that heading takes both files.

1. Prepare two PEM files. The chain holds the CA that signs first, then any intermediates, up to the root if you like. The key is RSA, ECDSA or Ed25519, in PKCS#8, PKCS#1 or SEC1, without a passphrase. To remove one, use `openssl pkey -in key.pem -out plain.pem`.
2. Choose both files and press **Upload**.
3. Reload the page after a few seconds. The tab shows the CA in use, or why the upload was refused. A refused upload leaves the CA in use untouched.

- **With the two-file upload, the key can cross your network in the clear.** The pages are plain HTTP unless they are behind HTTPS, so upload only from a trusted network.
- **Where the key goes.** The app leaves both files in `data/tls/incoming`. The proxy checks them, moves a valid pair to `data/tls/private` and deletes both from `incoming`, whether they were valid or not. If the proxy is not running, they wait there until it starts.
- **Devices must already trust it.** Mikrokat changes nothing on them. **Download the CA certificate** gives you the chain you uploaded.
- **A CA with name constraints works only for those names.** For any other name the device refuses the certificate, and the automatic bypass then relays that name untouched.
- **Regenerate does not apply,** so the tab hides it. To change the CA, upload a new one.
- **If your CA expires while the proxy runs,** connections keep working uninspected and are counted as `ca_expired`, as with the generated CA. An alarm warns when it has less than 30 days left.
- **If your CA stops being valid,** for example it has expired by the time the proxy restarts, the proxy does not go back to the generated CA by itself. The port stays closed, the tab and the alarm say why, and browsers using the PAC file go direct. You decide: upload a valid CA, or press **Stop using my CA**.
- **Stop using my CA** deletes both files and returns to the generated CA, the same one as before if there was one. Devices then need that CA.
- **If the key may have leaked,** revoke that CA on your own systems and stop using it here, and destroy any backup that holds `data/tls/private`. Deleting it from this host does not stop a copy from working.

### The PAC file

`/tls.pac` tells a browser where to send its traffic, and it needs no login. While the feature is on, it answers `SOCKS5 <host>:1080; DIRECT` for `https:` and `wss:` addresses, which means use the proxy, or go direct if the proxy does not answer. Everything else goes direct: other schemes, plain host names and private addresses. The proxy inspects none of that, and relaying it would only hide the real device. While the feature is off, the file answers `DIRECT`.

Other programs on a listed device can use the same SOCKS5 proxy on port 1080, if they trust the CA. Through it, a listed device reaches public sites only, with the address of the Mikrokat host. The proxy refuses private addresses (10/8, 172.16/12, 192.168/16, fc00::/7), the CGNAT range 100.64/10, loopback and link-local addresses, the addresses of the host and the subnets of its Docker networks, and it does so also for a name that resolves to one of them. There is no allow-list, so an HTTPS site on your LAN with a full name, such as `nas.home.example`, fails in a browser using the PAC file. Open it from another profile.

### Connections

The **Connections** page, in the menu while HTTPS inspection is on, shows what went through the proxy and what it did with it: how many connections were inspected and how many were passed untouched, and why; the data moved; the top sites and devices; and the latest 200 connections, which you can filter by device and by part of a site name. The Overview has a **Decrypted, 24h** tile that opens it. The numbers are for the last 24 hours, with a 7 day total under them.

It comes from a log the proxy writes, `data/tls/state/connections.jsonl`, with one line for each connection: when it ended, the device, the site name (the name in the TLS hello, else the name the device asked SOCKS for), the address and port, whether it was inspected, passed or refused and why, the bytes each way and how long it lasted. Bytes are those relayed, not the copy sent to Suricata. **No URL, path, header or content is ever written there.** A connection that fails before any relay starts, such as one the site did not answer, is not logged. Refused connections are written at most once a second for each source, so a port scan cannot fill the file; the rest are counted as `log_skipped` in `stats.json`. If the writer cannot keep up, lines are dropped and counted as `log_dropped`.

The file is rotated at 5 MiB to `connections.jsonl.1`, so the log holds at most about 10 MiB. The app reads new lines every 30 seconds into hourly statistics that it keeps for 7 days, at most the 200 biggest sites for each hour.

It only shows traffic through the proxy, from the devices on your list. It says nothing about the rest of the network, and nothing about what a program does inside a connection it passed untouched.

The log shows which sites each listed device visited, so the consent note above applies to it too. **Keep a log of connections** on the HTTPS inspection tab turns it off (on by default): the proxy then writes nothing, the page empties as the 24 hours pass, and the existing file stays until you delete it.

### Limits

- **Apps must be configured.** Nothing on the router changes, so a program is inspected only if it is set to use the proxy and trusts the CA.
- **A program can ignore SOCKS.** A proxy setting is a request, not a control. Do not count on this to catch software that wants to hide.
- **Only decrypted alerts show the real device.** Connections the proxy relays, and its own connections to sites, appear in Suricata as the Mikrokat host.
- **Bot protection can object.** Sites with bot protection show a CAPTCHA or an "unusual traffic" page to an inspected device, because they see the proxy's TLS fingerprint and HTTP/1.1 instead of the browser's. Google is skipped by default, as corporate proxies do. Other sites with bot protection, such as those behind Cloudflare, go in your own skip list.
- **A device behind a VPN or overlay shows as its gateway.** A device that reaches Mikrokat through a VPN or an overlay network such as NetBird appears with the address of that gateway, not its LAN address. Put the gateway's address in Devices. Every client behind that gateway then counts as the same device, and alerts show the gateway.
- **A site can choose not to be inspected.** Like a port other than 443 or an IPv6 address, a hostile site can stay out of reach: if it resets the proxy's connection, or shows the proxy a certificate that fails, the proxy relays the browser on a fresh connection, and the site can answer that one normally.
- **Only the chain, name and dates are checked.** Revocation and Certificate Transparency are lost for inspected sites, because the browser sees only the Mikrokat certificate. A site with a revoked certificate looks fine.
- **URLs are written.** For every inspected request Suricata stores the host, URL, content type and user agent. An alert also stores the referrer, redirect target, method, status and length. A password or token in any of those URLs is therefore written. Passwords, cookies and bodies sent in headers or in the body are not written to disk, and `tests/e2e/run.sh` checks that.
- **Two stores keep those URLs.** EVE follows **Keep logs for** on the Data tab, 1 to 90 days, up to 4 GB. EveBox stays at 7 days and 4 GB whatever is set, so lowering **Keep logs for** does not remove URLs from EveBox.
- **Root on the host sees the plaintext.** It can capture it on `tzsp0`, up to the copy limit, though nothing stores it.
- **The CA key can impersonate any site** to every device that trusts it. The generated key stays in `data/tls/private`, which only the proxy can read, but a backup of the host contains it. An own CA's key is less closed: it passes through the memory of the web app and waits in `data/tls/incoming` until the proxy takes it (the proxy deletes it from there within seconds, also when it refuses it), and then it sits in `data/tls/private` too. If a generated key may have leaked, use **Regenerate the CA**, delete the old `Mikrokat local CA` from every device and import the new certificate. Regenerate does not apply to an own CA: revoke that CA the way you run it, and upload a new one. A new CA does not revoke the old one: a device keeps trusting the old key until you delete it there.
- **Copies are paced.** The copy for Suricata goes out at about 10 MB/s, and its queue holds 64 MiB. Above that rate the queue fills, and Suricata misses the rest of those connections while they keep working. With 200 downloads of 1 MiB, 100 at a time, that happened to 25 to 43 of them. **Copies dropped** on the Numbers card shows it. Frames can also be lost between the proxy and `tzsp` when the host is overloaded. That loss is not counted there, and `tests/e2e/run.sh` checks for it.
- **Connections are limited.** The proxy holds at most 512 connections, 128 per device, and closes any over that at once. It closes a connection after 10 minutes with no bytes in either direction, which also ends a quiet websocket, and 60 seconds after one side has finished, so a hostile server cannot hold them open.
- **Decrypted alerts never block.** They are recorded as `Would block`, also in Block mode. A web page can send a crafted URL to a shared CDN, and a block would then cut that CDN off for the whole network.
- **HTTP/1.1 only.** The proxy offers no HTTP/2, so sites answer over HTTP/1.1. A program that speaks only HTTP/2 is refused, and the automatic bypass does not apply to it, because the program never rejected the certificate. Add its names to the bypass list. The same goes for a program that only speaks a TLS version older than 1.2.
- **A client certificate requested late fails.** A TLS 1.2 site that asks for one after the connection is up is refused by the proxy, and the page fails. Add its name to the bypass list.

## Sending alerts to a SIEM

Mikrokat does not need a SIEM. If you have one, the Data tab of Settings offers three ways to send alerts, all using the same record: Suricata's EVE JSON, plus Mikrokat's action, target and country under `mikrokat`.

- **Alert file:** `data/logs/alerts.json`, for an agent or forwarder to read.
- **Syslog:** RFC 5424 over UDP or TCP, with the JSON as the message body.
- **Webhook:** generic JSON, or the Splunk HEC format on the Notifications tab.

Setup notes for Splunk, Elastic, Wazuh and Graylog are in [integrations](integrations/README.md).

## Single sign-on

On the Account tab of Settings you can add any OpenID Connect provider. Create a confidential client with the redirect URI shown there, and set the group allowed to sign in. Mikrokat has one role, so everyone in that group gets full control. The password keeps working as a fallback. If you publish Mikrokat behind a reverse proxy, set `PUBLIC_URL`.

## Explain

On the AI tab of Settings, enter the address of any OpenAI-compatible API, such as `http://host:11434/v1` for Ollama, and a model name. An Explain button then appears next to rules. Mikrokat sends only the rule text, its severity and how many alerts it caused, never addresses or traffic, and it keeps each answer so it asks only once.

## Security notes

- The pages use plain HTTP. Publish them through a reverse proxy with TLS if you open them from outside your LAN. The sign-in cookie is shared by host name, so use the same host for ports 8088 and 5636.
- Router, mail and Telegram secrets are stored in `data/app/settings.json`, readable only by root.
- The app has no access to Docker. Rule updates run in a separate container.
- Countries are looked up in a local database. No address is sent to an outside service.

## Update

```sh
git pull
docker compose up -d --build
```

The root certificates the proxy trusts are fixed in its image. To refresh them, run `docker compose build --pull --no-cache tlsproxy`, then `docker compose up -d`.

## Remove

```sh
docker compose down -v
```

Then delete the `data` folder, and remove the rules from the router as shown above. If you used HTTPS inspection, delete `Mikrokat local CA` (and your own CA, if you used it for this and nothing else) from every device, and destroy any backup that holds `data/tls/private`: until then that key can impersonate any site to a device that trusts it.

## Configuration

Most settings are on the Settings page. `.env` holds the first values, and `.env.example` lists them all. Once you save the page, its values replace those in `.env`.

## Troubleshooting

- **The page does not open:** `WEB_PASSWORD` is empty, so the web pages stay off. Set it in `.env` and run `docker compose up -d`. `docker logs mikrokat-app` shows the same message.
- **Packets stay at 0:** the router is not sending traffic to Mikrokat. Check the mangle rules and the target address, and that `ROUTER_HOST` is the address the router sends from.
- **A container does not start:** check `docker compose ps -a` and `docker logs` for that container. Without `/dev/net/tun`, `mikrokat-tzsp` cannot start.

## License

GPL-3.0. See [LICENSE](LICENSE). Inspired by [zzbe/mikrocata](https://github.com/zzbe/mikrocata).

Built with [Suricata](https://suricata.io) and [EveBox](https://evebox.org). IP country data by [DB-IP](https://db-ip.com), CC BY 4.0, downloaded monthly and read locally. Map data from [Natural Earth](https://www.naturalearthdata.com), public domain.
