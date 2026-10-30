"""Settings, allowlist and statistics, all kept under DATA_DIR."""
import collections
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time

DATA_DIR = os.environ.get("DATA_DIR", "/var/lib/mikrokat")
ALLOWLIST_FILE = os.path.join(DATA_DIR, "allowlist.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
BLOCKS_FILE = os.path.join(DATA_DIR, "blocks.json")
SCHEDULE_FILE = os.path.join(DATA_DIR, "schedule.json")
DATABASE = os.path.join(DATA_DIR, "stats.db")
STATS_DAYS = 30

FIXED_ALLOWLIST = [ipaddress.ip_network(n.strip(), strict=False) for n in os.environ.get(
    "ALLOWLIST", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,fe80::/10,1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9").split(",") if n.strip()]

settings = {
    "mode": os.environ.get("MODE", "monitor").lower(),
    "severities": [s.strip() for s in os.environ.get("SEVERITIES", "1,2").split(",") if s.strip()],
    "ignore_sids": [s.strip() for s in os.environ.get("IGNORE_SIDS", "").split(",") if s.strip()],
    "dedupe_seconds": int(os.environ.get("DEDUPE_SECONDS", "300")),
    "retention_days": int(os.environ.get("RETENTION_DAYS", "7")),
    "block_timeout": os.environ.get("BLOCK_TIMEOUT", "1d"),
    "block_ipv6": os.environ.get("BLOCK_IPV6", "false").lower() == "true",
    "progressive": False,
    "block_steps": "1d 7d 30d",
    "health_minutes": 5,
    "rules_auto": "daily",
    "rules_hour": 4,
    "digest_enabled": False,
    "digest_hour": 8,
    "ai_enabled": False,
    "ai_url": "",
    "ai_model": "",
    "ai_key": "",
    "ai_language": "English",
    "router_host": os.environ.get("ROUTER_HOST", ""),
    "router_user": os.environ.get("ROUTER_USER", "mikrokat"),
    "router_password": os.environ.get("ROUTER_PASSWORD", ""),
    "router_tls": os.environ.get("ROUTER_TLS", "false").lower() == "true",
    "router_tls_insecure": os.environ.get("ROUTER_TLS_INSECURE", "false").lower() == "true",
    "router_port": int(os.environ.get("ROUTER_PORT", "8729" if os.environ.get("ROUTER_TLS", "").lower() == "true" else "8728")),
    "address_list": os.environ.get("ADDRESS_LIST", "mikrokat"),
    "telegram_enabled": bool(os.environ.get("TELEGRAM_TOKEN", "")),
    "telegram_token": os.environ.get("TELEGRAM_TOKEN", ""),
    "telegram_chat": os.environ.get("TELEGRAM_CHATID", ""),
    "telegram_proxy": os.environ.get("TELEGRAM_PROXY", ""),
    "email_enabled": False,
    "email_host": "",
    "email_port": 587,
    "email_security": "starttls",
    "email_user": "",
    "email_password": "",
    "email_from": "",
    "email_to": "",
    "webhook_enabled": False,
    "webhook_url": "",
    "webhook_format": "json",
    "webhook_secret": "",
    "alert_file_enabled": False,
    "syslog_enabled": False,
    "syslog_host": "",
    "syslog_port": 514,
    "syslog_protocol": "udp",
    "password_hash": "",
    "builtin_off": [],
    "oidc_enabled": False,
    "oidc_label": "SSO",
    "oidc_issuer": "",
    "oidc_client_id": "",
    "oidc_client_secret": "",
    "oidc_group": "",
    "oidc_scopes": "openid profile email",
}
custom = []
networks = list(FIXED_ALLOWLIST)
blocks = {}
strikes = {}
router_uptime = 0
names = {}
problems = {}
schedule = {}
pending_hosts = {}
pending_peers = {}
HOST_DAYS = 7
STRIKE_DAYS = 90
lock = threading.Lock()
pending_alerts = {}
pending_addresses = {}
pending_countries = {}
activity = collections.deque(maxlen=300)
activity_changed = threading.Condition()
activity_last = 0


def activity_add(kind, text, **details):
    """Add a line to the live feed."""
    global activity_last
    with activity_changed:
        activity_last += 1
        activity.append({"id": activity_last, "time": time.strftime("%H:%M:%S"), "kind": kind, "text": text, **details})
        activity_changed.notify_all()


def activity_since(last, timeout):
    """Wait up to timeout seconds and return the feed entries newer than last."""
    with activity_changed:
        activity_changed.wait_for(lambda: activity_last > last, timeout)
        return [entry for entry in activity if entry["id"] > last]


def write_json(path, value):
    temp = path + ".tmp"
    with open(os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as target:
        json.dump(value, target, indent=1)
    os.replace(temp, path)


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as source:
            return json.load(source)
    except (FileNotFoundError, ValueError):
        return default


def database():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


def load():
    global custom, router_uptime
    os.makedirs(DATA_DIR, exist_ok=True)
    settings.update(read_json(SETTINGS_FILE, {}))
    custom = read_json(ALLOWLIST_FILE, [])
    saved = read_json(BLOCKS_FILE, {})
    blocks.update(saved.get("blocks", {}))
    strikes.update(saved.get("strikes", {}))
    router_uptime = saved.get("router_uptime", 0)
    schedule.update(read_json(SCHEDULE_FILE, {}))
    rebuild_networks()
    with database() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS hourly_alerts (hour TEXT, severity INT, sid INT, signature TEXT, count INT, PRIMARY KEY (hour, sid));
            CREATE TABLE IF NOT EXISTS hourly_addresses (hour TEXT, address TEXT, count INT, PRIMARY KEY (hour, address));
            CREATE TABLE IF NOT EXISTS hourly_countries (hour TEXT, country TEXT, count INT, PRIMARY KEY (hour, country));
            CREATE TABLE IF NOT EXISTS hourly_hosts (hour TEXT, address TEXT, sid INT, severity INT, signature TEXT, count INT, PRIMARY KEY (hour, address, sid));
            CREATE TABLE IF NOT EXISTS hourly_peers (hour TEXT, address TEXT, peer TEXT, count INT, PRIMARY KEY (hour, address, peer));
            CREATE TABLE IF NOT EXISTS explanations (sid INT PRIMARY KEY, text TEXT, at TEXT);
            CREATE TABLE IF NOT EXISTS actions (at TEXT, address TEXT, severity INT, sid INT, signature TEXT, action TEXT, outbound INT);
        """)


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"{salt.hex()}:{digest.hex()}"


def has_password():
    return bool(settings["password_hash"] or os.environ.get("WEB_PASSWORD", ""))


def check_password(password):
    """Check against the password set on the page, or WEB_PASSWORD until one is set."""
    stored = settings["password_hash"]
    if stored:
        salt, digest = stored.split(":")
        return hmac.compare_digest(hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex(), digest)
    expected = os.environ.get("WEB_PASSWORD", "")
    return bool(expected) and hmac.compare_digest(password.encode(), expected.encode())


def seconds(text):
    """Turn a RouterOS time like 1d2h3m4s into seconds."""
    units = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    return sum(int(value) * units[unit] for value, unit in re.findall(r"(\d+)([wdhms])", str(text)))


def save_blocks():
    write_json(BLOCKS_FILE, {"blocks": blocks, "strikes": strikes, "router_uptime": router_uptime})


def remember_block(address, comment, timeout):
    with lock:
        blocks[address] = {"comment": comment, "until": time.time() + seconds(timeout)}
        save_blocks()


def block_time_for(address):
    """Return how long to block: longer each time an address comes back, if that is turned on."""
    if not settings["progressive"]:
        return settings["block_timeout"]
    steps = settings["block_steps"].split()
    strike = strikes.get(address, {})
    count = strike.get("count", 0) if strike.get("last", 0) > time.time() - STRIKE_DAYS * 86400 else 0
    return steps[min(count, len(steps) - 1)]


def note_strike(address):
    with lock:
        now = time.time()
        old = strikes.get(address, {})
        count = old.get("count", 0) if old.get("last", 0) > now - STRIKE_DAYS * 86400 else 0
        strikes[address] = {"count": count + 1, "last": now}
        for key in [k for k, v in strikes.items() if v["last"] < now - STRIKE_DAYS * 86400]:
            del strikes[key]
        save_blocks()


def mark_schedule(key, value):
    schedule[key] = value
    write_json(SCHEDULE_FILE, schedule)


def name_of(ip):
    return names.get(ip, "")


def forget_block(address):
    with lock:
        if blocks.pop(address, None) is not None:
            save_blocks()


def active_blocks():
    """Return {address: entry} for blocks that have not run out yet."""
    now = time.time()
    with lock:
        for address in [a for a, e in blocks.items() if e["until"] <= now]:
            del blocks[address]
        return dict(blocks)


def note_router_uptime(value):
    """Store the uptime. Return True when it went backwards, which means the router restarted."""
    global router_uptime
    with lock:
        restarted = 0 < value < router_uptime
        router_uptime = value
        save_blocks()
    return restarted


def router_ready():
    return bool(settings["router_host"] and settings["router_password"])


def save_settings(form):
    """Validate and store the settings page. Return an error message, or None when it worked.

    Empty secret fields keep the stored value, so the page never has to show them.
    """
    mode = form.get("mode", "monitor")
    host = form.get("router_host", "").strip()
    user = form.get("router_user", "").strip()
    password = form.get("router_password", "") or settings["router_password"]
    address_list = form.get("address_list", "").strip()
    token = form.get("telegram_token", "").strip() or settings["telegram_token"]
    chat = form.get("telegram_chat", "").strip()
    notify = bool(form.get("telegram_enabled"))
    proxy = form.get("telegram_proxy", "").strip()
    if proxy.lower() == "none":
        proxy_value = ""
    elif proxy and not re.fullmatch(r"https?://\S{1,200}", proxy):
        return "The Telegram proxy looks like http://user:pass@host:port."
    else:
        proxy_value = proxy or settings["telegram_proxy"]
    email = bool(form.get("email_enabled"))
    email_host = form.get("email_host", "").strip()
    email_from = form.get("email_from", "").strip()
    email_to = form.get("email_to", "").strip()
    email_security = form.get("email_security", "starttls")
    webhook = bool(form.get("webhook_enabled"))
    webhook_url = form.get("webhook_url", "").strip() or settings["webhook_url"]
    if webhook_url.lower() == "none":
        webhook_url = ""
    webhook_format = form.get("webhook_format", "json")
    if email_security not in ("starttls", "tls", "none"):
        return "Unknown mail security."
    if email and not (email_host and email_from and email_to):
        return "Mail notifications need a server, a sender and a recipient."
    if any(address and not re.fullmatch(r"[^@\s]+@[^@\s]+", address) for address in [email_from] + re.split(r"[\s,]+", email_to)):
        return "Mail addresses look like name@example.com."
    syslog = bool(form.get("syslog_enabled"))
    syslog_host = form.get("syslog_host", "").strip()
    syslog_protocol = form.get("syslog_protocol", "udp")
    if syslog_protocol not in ("udp", "tcp"):
        return "Syslog uses UDP or TCP."
    if syslog and not syslog_host:
        return "Syslog needs a server address."
    if syslog_host and not re.fullmatch(r"[A-Za-z0-9.:-]{1,100}", syslog_host):
        return "The syslog address does not look right."
    if webhook_format not in ("json", "slack", "discord", "teams", "splunk"):
        return "Unknown webhook format."
    if webhook and not webhook_url:
        return "Webhook notifications need a URL."
    if webhook_url and not re.fullmatch(r"https?://\S{1,500}", webhook_url):
        return "The webhook URL starts with http:// or https://."
    steps = form.get("block_steps", "").split()
    if not steps or not all(re.fullmatch(r"\d+[smhdw]", step) for step in steps):
        return "Block steps look like 1d 7d 30d."
    rules_auto = form.get("rules_auto", "daily")
    if rules_auto not in ("off", "daily", "weekly"):
        return "Unknown rule update schedule."
    ai = bool(form.get("ai_enabled"))
    ai_url = form.get("ai_url", "").strip().rstrip("/")
    ai_model = form.get("ai_model", "").strip()
    if ai_url and not re.fullmatch(r"https?://\S{1,300}", ai_url):
        return "The AI address starts with http:// or https://."
    if ai and not (ai_url and ai_model):
        return "Explain needs an address and a model."
    oidc = bool(form.get("oidc_enabled"))
    oidc_issuer = form.get("oidc_issuer", "").strip()
    oidc_client = form.get("oidc_client_id", "").strip()
    oidc_secret = form.get("oidc_client_secret", "") or settings["oidc_client_secret"]
    oidc_group = form.get("oidc_group", "").strip()
    if oidc_issuer and not re.fullmatch(r"https?://\S{1,300}", oidc_issuer):
        return "The issuer URL starts with https://."
    if oidc and not (oidc_issuer and oidc_client and oidc_secret and oidc_group):
        return "Single sign-on needs the issuer, client ID, client secret and an allowed group."
    new_password = form.get("new_password", "")
    if new_password and len(new_password) < 12:
        return "The new password needs at least 12 characters."
    if new_password != form.get("new_password2", ""):
        return "The two passwords do not match."
    severities = [s for s in ("1", "2", "3") if form.get(f"severity{s}")]
    sids = [s for s in re.split(r"[\s,]+", form.get("ignore_sids", "")) if s]
    timeout = form.get("block_timeout", "").strip()
    if mode not in ("monitor", "block"):
        return "Unknown mode."
    if mode == "block" and not (host and password):
        return "Automatic blocking needs the router address and password."
    if host and not re.fullmatch(r"[A-Za-z0-9.:-]{1,100}", host):
        return "The router address does not look right."
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,50}", address_list):
        return "The address list name can use letters, numbers, - and _."
    if chat and not re.fullmatch(r"-?\d{1,20}|@\w{1,64}", chat):
        return "The chat ID is a number or an @channel name."
    if notify and not (token and chat):
        return "Telegram notifications need a bot token and a chat ID."
    if not severities:
        return "Pick at least one severity."
    if not all(s.isdigit() for s in sids):
        return "Ignored rules must be numbers."
    if not re.fullmatch(r"\d+[smhdw]", timeout):
        return "The block time looks like 12h or 1d."
    try:
        dedupe, retention, port = int(form.get("dedupe_seconds", "")), int(form.get("retention_days", "")), int(form.get("router_port", ""))
        email_port = int(form.get("email_port") or 587)
        rules_hour, digest_hour = int(form.get("rules_hour") or 4), int(form.get("digest_hour") or 8)
        health_minutes = int(form.get("health_minutes") or 5)
        syslog_port = int(form.get("syslog_port") or 514)
    except ValueError:
        return "Repeat time, log days and router port must be numbers."
    if not (0 <= rules_hour <= 23 and 0 <= digest_hour <= 23):
        return "Hours go from 0 to 23."
    if not 1 <= health_minutes <= 1440:
        return "The traffic alarm goes from 1 to 1440 minutes."
    if not 0 <= dedupe <= 86400 or not 1 <= retention <= 90:
        return "Repeat time goes from 0 to 86400 seconds, log days from 1 to 90."
    with lock:
        settings.update(mode=mode, severities=severities, ignore_sids=sids, dedupe_seconds=dedupe, retention_days=retention,
                        block_timeout=timeout, block_ipv6=bool(form.get("block_ipv6")), telegram_proxy=proxy_value, router_host=host, router_user=user, router_password=password, router_port=port,
                        router_tls=bool(form.get("router_tls")), router_tls_insecure=bool(form.get("router_tls_insecure")),
                        address_list=address_list, telegram_enabled=notify, telegram_token=token, telegram_chat=chat)
        settings.update(alert_file_enabled=bool(form.get("alert_file_enabled")), syslog_enabled=syslog, syslog_host=syslog_host, syslog_port=syslog_port,
                        syslog_protocol=syslog_protocol, email_enabled=email, email_host=email_host, email_port=email_port, email_security=email_security,
                        email_user=form.get("email_user", "").strip(), email_password=form.get("email_password", "") or settings["email_password"],
                        email_from=email_from, email_to=email_to, webhook_enabled=webhook, webhook_url=webhook_url, webhook_format=webhook_format,
                        webhook_secret=form.get("webhook_secret", "").strip() or settings["webhook_secret"])
        settings.update(progressive=bool(form.get("progressive")), block_steps=" ".join(steps), rules_auto=rules_auto, rules_hour=rules_hour,
                        health_minutes=health_minutes, digest_enabled=bool(form.get("digest_enabled")), digest_hour=digest_hour, ai_enabled=ai, ai_url=ai_url,
                        ai_model=ai_model, ai_key=form.get("ai_key", "") or settings["ai_key"], ai_language=form.get("ai_language", "").strip()[:30] or "English")
        settings.update(oidc_enabled=oidc, oidc_issuer=oidc_issuer, oidc_client_id=oidc_client, oidc_client_secret=oidc_secret, oidc_group=oidc_group,
                        oidc_label=form.get("oidc_label", "").strip()[:30] or "SSO", oidc_scopes=form.get("oidc_scopes", "").strip() or "openid profile email")
        if new_password:
            settings["password_hash"] = hash_password(new_password)
        write_json(SETTINGS_FILE, settings)
    return None


def ignore_sid(sid):
    with lock:
        if str(sid) not in settings["ignore_sids"]:
            settings["ignore_sids"].append(str(sid))
            write_json(SETTINGS_FILE, settings)


def rebuild_networks():
    global networks
    active = [n for n in FIXED_ALLOWLIST if str(n) not in settings["builtin_off"]]
    networks = active + [ipaddress.ip_network(e["network"]) for e in custom]


def allowed(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks if addr.version == net.version)


def add_allowed(value, note):
    """Add an address or network. Return an error message, or None when it worked."""
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return f"Not a valid address or network: {value}"
    if network.prefixlen == 0:
        return "A network that covers everything would turn detection off."
    with lock:
        if any(e["network"] == str(network) for e in custom):
            return f"{network} is already on the list."
        custom.append({"network": str(network), "note": note.strip()[:120], "added": time.strftime("%Y-%m-%d %H:%M")})
        write_json(ALLOWLIST_FILE, custom)
        rebuild_networks()
    return None


def set_builtin(value, enabled):
    """Turn one built-in allowlist entry on or off."""
    if value not in [str(n) for n in FIXED_ALLOWLIST]:
        return
    with lock:
        off = [n for n in settings["builtin_off"] if n != value]
        settings["builtin_off"] = off if enabled else off + [value]
        write_json(SETTINGS_FILE, settings)
        rebuild_networks()


def remove_allowed(value):
    with lock:
        custom[:] = [e for e in custom if e["network"] != value]
        write_json(ALLOWLIST_FILE, custom)
        rebuild_networks()


def count_alert(event, address, country=""):
    """Count an alert in memory. flush() writes the counters out in one go."""
    alert = event.get("alert") or {}
    hour = time.strftime("%Y-%m-%d %H")
    key = (hour, alert.get("severity", 3), alert.get("signature_id", 0), str(alert.get("signature", ""))[:200])
    pending_alerts[key] = pending_alerts.get(key, 0) + 1
    if address:
        key = (hour, address)
        pending_addresses[key] = pending_addresses.get(key, 0) + 1
    if country:
        key = (hour, country)
        pending_countries[key] = pending_countries.get(key, 0) + 1
    source, destination = event.get("src_ip"), event.get("dest_ip")
    for side, peer in ((source, destination), (destination, source)):
        if side and peer:
            key = (hour, side, alert.get("signature_id", 0), alert.get("severity", 3), str(alert.get("signature", ""))[:200])
            pending_hosts[key] = pending_hosts.get(key, 0) + 1
            key = (hour, side, peer)
            pending_peers[key] = pending_peers.get(key, 0) + 1


def flush():
    if not (pending_alerts or pending_addresses or pending_countries):
        return
    alerts, addresses, countries = dict(pending_alerts), dict(pending_addresses), dict(pending_countries)
    hosts, peers = dict(pending_hosts), dict(pending_peers)
    pending_alerts.clear()
    pending_addresses.clear()
    pending_countries.clear()
    pending_hosts.clear()
    pending_peers.clear()
    with database() as db:
        db.executemany("""INSERT INTO hourly_alerts VALUES (?, ?, ?, ?, ?)
                          ON CONFLICT (hour, sid) DO UPDATE SET count = count + excluded.count""",
                       [(*k, v) for k, v in alerts.items()])
        db.executemany("""INSERT INTO hourly_addresses VALUES (?, ?, ?)
                          ON CONFLICT (hour, address) DO UPDATE SET count = count + excluded.count""",
                       [(*k, v) for k, v in addresses.items()])
        db.executemany("""INSERT INTO hourly_countries VALUES (?, ?, ?)
                          ON CONFLICT (hour, country) DO UPDATE SET count = count + excluded.count""",
                       [(*k, v) for k, v in countries.items()])
        db.executemany("""INSERT INTO hourly_hosts VALUES (?, ?, ?, ?, ?, ?)
                          ON CONFLICT (hour, address, sid) DO UPDATE SET count = count + excluded.count""",
                       [(*k, v) for k, v in hosts.items()])
        db.executemany("""INSERT INTO hourly_peers VALUES (?, ?, ?, ?)
                          ON CONFLICT (hour, address, peer) DO UPDATE SET count = count + excluded.count""",
                       [(*k, v) for k, v in peers.items()])


def record_action(address, alert, action, outbound):
    with database() as db:
        db.execute("INSERT INTO actions VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (time.strftime("%Y-%m-%d %H:%M:%S"), address, alert.get("severity"), alert.get("signature_id"),
                    str(alert.get("signature", ""))[:200], action, int(outbound)))


def prune():
    limit = time.strftime("%Y-%m-%d %H", time.localtime(time.time() - STATS_DAYS * 86400))
    recent = time.strftime("%Y-%m-%d %H", time.localtime(time.time() - HOST_DAYS * 86400))
    with database() as db:
        db.execute("DELETE FROM hourly_hosts WHERE hour < ?", (recent,))
        db.execute("DELETE FROM hourly_peers WHERE hour < ?", (recent,))
        db.execute("DELETE FROM hourly_alerts WHERE hour < ?", (limit,))
        db.execute("DELETE FROM hourly_addresses WHERE hour < ?", (limit,))
        db.execute("DELETE FROM hourly_countries WHERE hour < ?", (limit,))
        db.execute("DELETE FROM actions WHERE rowid NOT IN (SELECT rowid FROM actions ORDER BY at DESC LIMIT 2000)")


def since_yesterday():
    return time.strftime("%Y-%m-%d %H", time.localtime(time.time() - 23 * 3600))


def hourly_series():
    """Return 24 (label, important, informational) rows, oldest first, including empty hours."""
    hours = [time.strftime("%Y-%m-%d %H", time.localtime(time.time() - i * 3600)) for i in range(23, -1, -1)]
    with database() as db:
        rows = db.execute("""SELECT hour, SUM(CASE WHEN severity <= 2 THEN count ELSE 0 END), SUM(CASE WHEN severity > 2 THEN count ELSE 0 END)
                             FROM hourly_alerts WHERE hour >= ? GROUP BY hour""", (hours[0],)).fetchall()
    found = {r[0]: r[1:] for r in rows}
    return [(h[-2:] + ":00", *found.get(h, (0, 0))) for h in hours]


def top_rules(limit=8):
    with database() as db:
        return db.execute("""SELECT sid, MIN(severity), signature, SUM(count) AS total FROM hourly_alerts WHERE hour >= ?
                             GROUP BY sid ORDER BY MIN(severity) <= 2 DESC, total DESC LIMIT ?""", (since_yesterday(), limit)).fetchall()


def top_addresses(limit=8):
    with database() as db:
        return db.execute("""SELECT address, SUM(count) AS total FROM hourly_addresses WHERE hour >= ?
                             GROUP BY address ORDER BY total DESC LIMIT ?""", (since_yesterday(), limit)).fetchall()


def countries_today():
    with database() as db:
        return db.execute("""SELECT country, SUM(count) AS total FROM hourly_countries WHERE hour >= ?
                             GROUP BY country ORDER BY total DESC""", (since_yesterday(),)).fetchall()


def top_hosts(limit=8):
    """Internal hosts with the most alerts in the last 24 hours, important ones first."""
    with database() as db:
        rows = db.execute("""SELECT address, SUM(CASE WHEN severity <= 2 THEN count ELSE 0 END) AS important, SUM(count) AS total
                             FROM hourly_hosts WHERE hour >= ? GROUP BY address ORDER BY important DESC, total DESC LIMIT 200""", (since_yesterday(),)).fetchall()
    return [r for r in rows if allowed(r[0])][:limit]


def host_summary(address):
    """Return (rules, peers, actions, first seen, last seen) for one address, from the last 7 days."""
    with database() as db:
        rules = db.execute("""SELECT sid, MIN(severity), signature, SUM(count) AS total, MAX(hour) FROM hourly_hosts WHERE address = ?
                              GROUP BY sid ORDER BY MIN(severity), total DESC LIMIT 30""", (address,)).fetchall()
        peers = db.execute("""SELECT peer, SUM(count) AS total FROM hourly_peers WHERE address = ?
                              GROUP BY peer ORDER BY total DESC LIMIT 15""", (address,)).fetchall()
        taken = db.execute("SELECT at, severity, sid, signature, action FROM actions WHERE address = ? ORDER BY at DESC LIMIT 15", (address,)).fetchall()
        first, last = db.execute("SELECT MIN(hour), MAX(hour) FROM hourly_hosts WHERE address = ?", (address,)).fetchone()
    return rules, peers, taken, first, last


def rule_facts(sid):
    """Return (signature, severity, alerts in the last 24 hours) for a rule."""
    with database() as db:
        return db.execute("SELECT MAX(signature), MIN(severity), SUM(CASE WHEN hour >= ? THEN count ELSE 0 END) FROM hourly_alerts WHERE sid = ?",
                          (since_yesterday(), sid)).fetchone()


def saved_explanation(sid):
    with database() as db:
        row = db.execute("SELECT text FROM explanations WHERE sid = ?", (sid,)).fetchone()
    return row[0] if row else None


def save_explanation(sid, text):
    with database() as db:
        db.execute("INSERT OR REPLACE INTO explanations VALUES (?, ?, ?)", (sid, text, time.strftime("%Y-%m-%d %H:%M")))


def recent_actions(limit=10):
    with database() as db:
        return db.execute("SELECT at, address, severity, sid, signature, action, outbound FROM actions ORDER BY at DESC LIMIT ?", (limit,)).fetchall()


def actions_today():
    with database() as db:
        return db.execute("SELECT COUNT(*) FROM actions WHERE at >= ? AND (action LIKE 'Blocked%' OR action LIKE 'Would block%')", (since_yesterday(),)).fetchone()[0]


def rule_names():
    with database() as db:
        return dict(db.execute("SELECT sid, MAX(signature) FROM hourly_alerts GROUP BY sid").fetchall())
