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

The first run takes a few minutes: it builds two images and downloads the others and the rules. The last line shows your password.

Open `http://<host>:8088` and sign in as `admin`. The Settings page has a setup guide next to the form, and you can change the password there.

To check the path without touching the router (needs `python3`):

```sh
python3 tools/send-test-alert.py
```

A `Would block` entry appears on the Overview page. Leave `ROUTER_HOST` empty in `.env` for this test, because it limits TZSP to your router.

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
| **Settings** | Protection, notifications, router, data and account |
| **Events** | EveBox, on port 5636 |

## Rules

Mikrokat starts from ET Open and updates it every day at 04:00. You can change that on the Data tab of Settings. On the Rules page you can turn rules off, add your own and press **Apply rules** to update right away, without stopping Suricata. The same files live in `rules/` if you prefer an editor, and `tools/update-rules.sh` applies them.

To keep a rule in Events but stop its notifications and blocks, use **Mute**.

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

## Remove

```sh
docker compose down -v
```

Then delete the `data` folder, and remove the rules from the router as shown above.

## Configuration

Most settings are on the Settings page. `.env` holds the first values, and `.env.example` lists them all. Once you save the page, its values replace those in `.env`.

## Troubleshooting

- **The page does not open:** `WEB_PASSWORD` is empty, so the web pages stay off. Set it in `.env` and run `docker compose up -d`. `docker logs mikrokat-app` shows the same message.
- **Packets stay at 0:** the router is not sending traffic to Mikrokat. Check the mangle rules and the target address, and that `ROUTER_HOST` is the address the router sends from.
- **A container does not start:** check `docker compose ps -a` and `docker logs` for that container. Without `/dev/net/tun`, `mikrokat-tzsp` cannot start.

## License

GPL-3.0. See [LICENSE](LICENSE). Inspired by [zzbe/mikrocata](https://github.com/zzbe/mikrocata).

Built with [Suricata](https://suricata.io) and [EveBox](https://evebox.org). IP country data by [DB-IP](https://db-ip.com), CC BY 4.0, downloaded monthly and read locally. Map data from [Natural Earth](https://www.naturalearthdata.com), public domain.
