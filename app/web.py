"""Mikrokat web pages: overview, rules, allowlist and settings. EveBox stays the place for events."""
import base64
import glob
import gzip
import hmac
import html
import http.client
import http.cookies
import json
import math
import os
import ipaddress
import re
import secrets
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import actions
import geo
import health
import sso
import store

WEB_PORT = int(os.environ.get("WEB_PORT", "8088"))
EVENTS_PORT = int(os.environ.get("EVENTS_PORT", "5636"))
EVEBOX_URL = os.environ.get("EVEBOX_URL", "")
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")
EVEBOX_UPSTREAM = os.environ.get("EVEBOX_UPSTREAM", "evebox:5636")
SESSION_COOKIE = "mikrokat_session"
SESSION_HOURS = 12
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"}
sessions = {}
RULES_DIR = os.environ.get("RULES_DIR", "/rules")
SOCKET = os.environ.get("SURICATA_SOCKET", "/var/run/suricata/suricata-command.socket")
LOG_GLOB = os.environ.get("EVE_GLOB", "/var/log/suricata/eve-*.json")
MAX_BODY = 131072
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "worldmap.json"), encoding="utf-8") as source:
    WORLD = json.load(source)
csrf_token = secrets.token_urlsafe(32)
esc = html.escape

NOTICES = {
    "saved": "Saved.",
    "added": "Added.",
    "removed": "Removed.",
    "ignored": "That rule stays in the events, but no longer notifies or blocks.",
    "pending": "Saved. Press Apply rules to use it.",
    "applying": "Applying rules. This takes a minute or two.",
    "blocked": "Blocked on the router.",
    "unblocked": "Removed from the router.",
    "unblocked-allowed": "Removed from the router and added to the allowlist.",
}
STYLE = """
:root { color-scheme: light; --surface: #fcfcfb; --raised: #f4f3ef; --card: #ffffff; --line: #e4e3de; --text: #0b0b0b; --muted: #5f5e5a;
  --accent: #2a78d6; --accent-soft: #e3eefb; --accent-text: #fff; --error: #b3261e; --series-1: #2a78d6; --series-2: #eb6834; --shadow: 0 1px 2px rgb(0 0 0 / 6%);
  --geo-1: #cde2fb; --geo-2: #9ec5f4; --geo-3: #6da7ec; --geo-4: #2a78d6; --geo-5: #184f95; --good: #0b7a4b; --good-soft: #dcf1e7; --serious: #b4510b; --serious-soft: #fcebdc; --critical: #b3261e; --critical-soft: #fbe4e2; }
@media (prefers-color-scheme: dark) { :root { color-scheme: dark; --surface: #161615; --raised: #242422; --card: #1e1e1c; --line: #33332f; --text: #f0efec;
  --muted: #b5b4aa; --accent: #3987e5; --accent-soft: #1f3550; --accent-text: #fff; --error: #ff8a80; --series-1: #3987e5; --series-2: #d95926; --shadow: none;
  --geo-1: #184f95; --geo-2: #256abf; --geo-3: #3987e5; --geo-4: #6da7ec; --geo-5: #b7d3f6; --good: #4ec08b; --good-soft: #17352a; --serious: #f0a36b; --serious-soft: #3a2719; --critical: #ff8a80; --critical-soft: #3d1f1d; } }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; background: var(--surface); color: var(--text); }
header { position: sticky; top: 0; z-index: 5; display: flex; flex-wrap: wrap; align-items: center; gap: 4px 14px; padding: 10px 16px; background: var(--surface); border-bottom: 1px solid var(--line); }
header strong { font-size: 17px; letter-spacing: -.01em; margin-right: 6px; }
nav { display: flex; gap: 2px; flex: 1; min-width: 0; overflow-x: auto; scrollbar-width: none; white-space: nowrap; }
nav a { padding: 6px 12px; border-radius: 8px; color: var(--muted); text-decoration: none; }
nav a:hover { background: var(--raised); color: var(--text); text-decoration: none; }
nav a.on { background: var(--accent-soft); color: var(--text); font-weight: 600; }
main { max-width: 1120px; margin: 0 auto; padding: 16px 16px 40px; }
button { white-space: nowrap; }
td.n { white-space: nowrap; }
td.when { white-space: nowrap; }
.stack { display: flex; flex-direction: column; gap: 14px; }
.panel form + form, .panel .fields + .actions { margin-top: 12px; }
.toolbar { display: flex; flex-wrap: wrap; gap: 10px; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.small { font-size: 12px; }
.pill { display: inline-block; padding: 4px 9px; margin: 0 4px 4px 0; border-radius: 8px; background: var(--accent-soft); font-size: 13px; }
.answer { font-size: 15px; line-height: 1.6; }
.panel h2 + .row, .panel .row { margin-top: 6px; }
.cc { display: inline-block; padding: 0 5px; margin-left: 2px; border-radius: 4px; background: var(--raised); color: var(--muted); font-size: 11px; font-weight: 600; }
.geo-grid { display: grid; grid-template-columns: minmax(0, 1fr) 250px; gap: 20px; align-items: start; }
svg.world { background: none; }
svg.world path { stroke: var(--card); stroke-width: .5; }
svg.world path:hover { stroke: var(--text); stroke-width: 1; }
.geo-0 { fill: var(--raised); } .geo-1 { fill: var(--geo-1); background: var(--geo-1); } .geo-2 { fill: var(--geo-2); background: var(--geo-2); }
.geo-3 { fill: var(--geo-3); background: var(--geo-3); } .geo-4 { fill: var(--geo-4); background: var(--geo-4); } .geo-5 { fill: var(--geo-5); background: var(--geo-5); }
.geo-legend { display: flex; align-items: center; gap: 3px; margin-top: 6px; font-size: 12px; color: var(--muted); }
.geo-legend span { margin: 0 5px; } .geo-swatch { width: 22px; height: 9px; border-radius: 2px; }
.source { font-size: 11px; color: var(--muted); margin: 6px 0 0; }
.feed { font-size: 14px; height: calc(100vh - 330px); min-height: 300px; overflow-y: auto; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }
.feed .line { display: grid; grid-template-columns: 70px 76px minmax(0, 1fr) auto; gap: 10px; padding: 6px 2px; border-bottom: 1px solid var(--line); align-items: baseline; }
.feed .line:last-child { border-bottom: 0; }
.feed .line[hidden] { display: none; }
.feed .tools { margin-top: 3px; }
.feed .count { font-size: 12px; font-weight: 600; color: var(--muted); font-variant-numeric: tabular-nums; }
.foot { margin: 8px 0 0; font-size: 12px; }
.feed time { color: var(--muted); font-size: 12px; font-variant-numeric: tabular-nums; }
.badge.action { background: var(--accent-soft); color: var(--accent); }
.badge.system { background: var(--raised); color: var(--text); }
.badge.error { background: var(--critical-soft); color: var(--critical); }
.feed .sub { display: block; color: var(--muted); font-size: 12px; }
a { color: var(--accent); text-decoration: none; } a:hover { text-decoration: underline; }
h1 { font-size: 24px; letter-spacing: -.02em; margin: 10px 0 14px; } h2 { font-size: 16px; margin: 28px 0 8px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; margin-bottom: 14px; }
.tile { background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 16px 18px; box-shadow: var(--shadow); }
.tile b { display: block; font-size: 34px; line-height: 1.15; font-weight: 600; letter-spacing: -.02em; font-variant-numeric: tabular-nums; }
.tile span { color: var(--muted); font-size: 13px; }
.status { display: flex; flex-wrap: wrap; gap: 8px 26px; align-items: center; background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 12px 18px; margin-bottom: 14px; box-shadow: var(--shadow); }
.status .state { display: flex; align-items: center; gap: 8px; font-weight: 600; margin-right: auto; }
.status .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--good); box-shadow: 0 0 0 3px var(--good-soft); }
.status .dot.off { background: var(--critical); box-shadow: 0 0 0 3px var(--critical-soft); }
.status .dot.idle { background: var(--muted); box-shadow: 0 0 0 3px var(--raised); }
.status .fact { font-size: 13px; color: var(--muted); }
.status .fact b { color: var(--text); font-weight: 600; font-variant-numeric: tabular-nums; }
.panels { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 14px; }
.panel { grid-column: span 12; background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 14px 18px 16px; box-shadow: var(--shadow); min-width: 0; }
.panel.half { grid-column: span 6; } .panel.third { grid-column: span 5; } .panel.rest { grid-column: span 7; }
.panel h2 { margin: 0 0 2px; font-size: 15px; font-weight: 600; }
.panel > p { margin: 0 0 8px; color: var(--muted); font-size: 13px; }
.panel table tr:last-child td { border-bottom: 0; }
.panel tr:hover td { background: var(--raised); }
.panel tr:first-child:hover th { background: none; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.badge.high { background: var(--critical-soft); color: var(--critical); }
.badge.medium { background: var(--serious-soft); color: var(--serious); }
.badge.low { background: var(--raised); color: var(--muted); }
.actions-cell { white-space: nowrap; text-align: right; }
svg { display: block; width: 100%; height: auto; }
svg text { fill: var(--muted); font-size: 11px; }
svg line { stroke: var(--line); }
svg rect.hit { fill: transparent; }
svg rect.hit:hover { fill: var(--raised); }
.bar-1 { fill: var(--series-1); } .bar-2 { fill: var(--series-2); }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 500; font-size: 12px; }
td.n, th.n { text-align: right; font-variant-numeric: tabular-nums; }
.scroll { overflow-x: auto; }
.row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
input, textarea, select { font: inherit; padding: 8px 10px; background: var(--surface); color: inherit; border: 1px solid var(--line); border-radius: 8px; max-width: 100%; }
input:focus-visible, textarea:focus-visible, button:focus-visible, .choice input:focus-visible + span, .switch input:focus-visible + span { outline: 2px solid var(--accent); outline-offset: 2px; }
textarea { width: 100%; min-height: 180px; font-family: ui-monospace, monospace; font-size: 13px; }
button { font: inherit; font-weight: 500; padding: 8px 14px; background: var(--accent); color: var(--accent-text); border: 0; border-radius: 8px; cursor: pointer; }
button.quiet { background: var(--raised); color: var(--text); padding: 4px 9px; font-size: 13px; }
button.ghost { background: transparent; color: var(--text); border: 1px solid var(--line); }
button.ghost:hover, button.quiet:hover { background: var(--line); }
form { margin: 0; } form.inline { display: inline-block; margin: 0 4px 4px 0; }
.note { padding: 8px 12px; border-radius: 8px; background: var(--accent-soft); margin: 0 0 12px; }
.note.error, .error { color: var(--error); font-weight: 600; }
.muted { color: var(--muted); }
pre { background: var(--raised); border-radius: 8px; padding: 10px; overflow-x: auto; font-size: 12px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 16px 18px 18px; margin-bottom: 16px; box-shadow: var(--shadow); }
.card h2 { margin: 0; font-size: 16px; }
.card > p { margin: 2px 0 14px; color: var(--muted); font-size: 14px; }
.fields { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 14px; }
.field { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.field > span, .group-label { font-size: 13px; font-weight: 500; }
.field input { width: 100%; }
.hint { color: var(--muted); font-size: 12px; font-weight: 400; }
.group { margin-bottom: 14px; }
.group-label { display: block; margin-bottom: 6px; }
.choices { display: flex; flex-wrap: wrap; gap: 6px; }
.choice { position: relative; cursor: pointer; }
.choice input, .switch input { position: absolute; opacity: 0; width: 0; height: 0; }
.choice span { display: block; padding: 6px 14px; border: 1px solid var(--line); border-radius: 8px; color: var(--muted); }
.choice small { display: block; font-size: 12px; font-weight: 400; color: var(--muted); }
.choice input:checked + span { background: var(--accent-soft); border-color: var(--accent); color: var(--text); font-weight: 600; }
.reveal { display: none; }
.switch:has(input:checked) ~ .reveal { display: block; }
.howto { margin-top: 12px; font-size: 14px; }
.howto summary { cursor: pointer; color: var(--accent); }
.howto ol { padding-left: 20px; margin: 8px 0; }
.howto p { color: var(--muted); margin: 6px 0; }
.switch { display: flex; align-items: center; gap: 10px; cursor: pointer; margin-bottom: 12px; position: relative; }
.switch span { width: 38px; height: 22px; flex: none; border-radius: 11px; background: var(--line); position: relative; transition: background .15s; }
.switch span::after { content: ""; position: absolute; top: 3px; left: 3px; width: 16px; height: 16px; border-radius: 50%; background: #fff; transition: transform .15s; }
.switch input:checked + span { background: var(--accent); }
.switch input:checked + span::after { transform: translateX(16px); }
.actions { margin-top: 14px; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.savebar { position: sticky; bottom: 0; display: flex; justify-content: flex-end; padding: 12px 0; background: linear-gradient(transparent, var(--surface) 35%); }
form > input[name=tab] { position: absolute; opacity: 0; width: 0; height: 0; }
.tabbar { display: flex; gap: 2px; padding: 3px; margin-bottom: 14px; background: var(--raised); border-radius: 10px; overflow-x: auto; scrollbar-width: none; }
.tabbar label { padding: 6px 14px; border-radius: 8px; color: var(--muted); cursor: pointer; white-space: nowrap; }
.tabbar label:hover { color: var(--text); }
.pane { display: none; }
#tab-protection:checked ~ #pane-protection { display: block; } #tab-protection:checked ~ .tabbar label[for=tab-protection] { background: var(--card); color: var(--text); font-weight: 600; box-shadow: var(--shadow); }
#tab-notifications:checked ~ #pane-notifications { display: block; } #tab-notifications:checked ~ .tabbar label[for=tab-notifications] { background: var(--card); color: var(--text); font-weight: 600; box-shadow: var(--shadow); }
#tab-router:checked ~ #pane-router { display: block; } #tab-router:checked ~ .tabbar label[for=tab-router] { background: var(--card); color: var(--text); font-weight: 600; box-shadow: var(--shadow); }
#tab-data:checked ~ #pane-data { display: block; } #tab-data:checked ~ .tabbar label[for=tab-data] { background: var(--card); color: var(--text); font-weight: 600; box-shadow: var(--shadow); }
#tab-account:checked ~ #pane-account { display: block; } #tab-account:checked ~ .tabbar label[for=tab-account] { background: var(--card); color: var(--text); font-weight: 600; box-shadow: var(--shadow); }
#tab-ai:checked ~ #pane-ai { display: block; } #tab-ai:checked ~ .tabbar label[for=tab-ai] { background: var(--card); color: var(--text); font-weight: 600; box-shadow: var(--shadow); }
select { width: 100%; }
.with-guide { display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 24px; align-items: start; }
.guide { position: sticky; top: 64px; max-height: calc(100vh - 80px); overflow-y: auto; background: var(--raised); border-radius: 14px; padding: 6px 16px 12px; font-size: 14px; }
.guide h2 { font-size: 14px; margin: 14px 0 4px; }
.guide p { margin: 4px 0; color: var(--muted); }
.guide pre { background: var(--surface); white-space: pre-wrap; overflow-wrap: anywhere; font-size: 11.5px; }
.login-page main { min-height: 100vh; display: grid; place-items: center; padding: 16px; }
.login { width: 100%; max-width: 380px; margin: 0; padding: 28px 28px 30px; }
.login h1 { margin: 0; font-size: 26px; }
.login .tagline { margin: 2px 0 20px; color: var(--muted); font-size: 14px; }
.login form { display: flex; flex-direction: column; gap: 14px; }
.login input { width: 100%; }
.login button { width: 100%; margin-top: 6px; padding: 10px 14px; }
.sso { display: block; text-align: center; padding: 10px 14px; border-radius: 8px; background: var(--accent); color: var(--accent-text); font-weight: 500; }
.sso:hover { text-decoration: none; }
.or { display: flex; align-items: center; gap: 10px; margin: 18px 0; color: var(--muted); font-size: 13px; }
.or::before, .or::after { content: ""; flex: 1; border-top: 1px solid var(--line); }
@media (max-width: 880px) { .with-guide { grid-template-columns: minmax(0, 1fr); } .guide { position: static; max-height: none; }
  .geo-grid { grid-template-columns: minmax(0, 1fr); }
  .panel.half, .panel.third, .panel.rest { grid-column: span 12; } .status .state { margin-right: 0; width: 100%; }
  header strong { width: auto; } nav { order: 3; flex-basis: 100%; }
  .tiles { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; } .tile { padding: 12px 14px; } .tile b { font-size: 26px; }
  .actions-cell form.inline { display: block; margin: 0 0 4px; } .feed .line { grid-template-columns: 62px minmax(0, 1fr) auto; } .feed .line .text { grid-column: 1 / -1; grid-row: 2; } }
"""


def suricata(command):
    """Ask Suricata over its control socket. Return the reply message, or None if it is not reachable."""
    def exchange(sock, payload):
        sock.sendall(json.dumps(payload).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        return json.loads(data)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(4)
            sock.connect(SOCKET)
            exchange(sock, {"version": "0.2"})
            reply = exchange(sock, {"command": command})
        return reply.get("message") if reply.get("return") == "OK" else None
    except (OSError, ValueError):
        return None


def number(value):
    return f"{value:,}".replace(",", " ") if isinstance(value, int) else str(value)


def short_number(value):
    for limit, suffix in ((1e9, "G"), (1e6, "M"), (1e3, "k")):
        if value >= limit:
            return f"{value / limit:.1f}{suffix}"
    return str(int(value))


def duration(seconds):
    days, hours = seconds // 86400, seconds % 86400 // 3600
    return f"{days}d {hours}h" if days else f"{hours}h {seconds % 3600 // 60}m"


def nice_top(value):
    if value <= 0:
        return 1
    base = 10 ** math.floor(math.log10(value))
    return next(step * base for step in (1, 2, 5, 10) if step * base >= value)


def bar_chart(title, labels, values, series):
    """Bars for 24 hours. Each hour carries a native hover tooltip."""
    width, height, left, bottom, top_gap = 480, 170, 36, 22, 8
    plot = height - bottom - top_gap
    band = (width - left) / len(values)
    bar = min(24, band * 0.72)
    top = nice_top(max(values))
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{esc(title)}, peak {max(values)} in one hour">']
    for share in (0, 0.5, 1):
        y = top_gap + plot * (1 - share)
        parts.append(f'<line x1="{left}" x2="{width}" y1="{y:.1f}" y2="{y:.1f}"/>'
                     f'<text x="{left - 6}" y="{y + 4:.1f}" text-anchor="end">{short_number(top * share)}</text>')
    for i, (label, value) in enumerate(zip(labels, values)):
        x = left + band * i
        parts.append(f'<rect class="hit" x="{x:.1f}" y="{top_gap}" width="{band:.1f}" height="{plot}"><title>{esc(label)}: {number(int(value))}</title></rect>')
        if value:
            h = max(2.0, plot * value / top)
            r = min(4.0, bar / 2, h)
            bx, by, base = x + (band - bar) / 2, top_gap + plot - h, top_gap + plot
            parts.append(f'<path class="bar-{series}" pointer-events="none" d="M{bx:.1f} {base:.1f}V{by + r:.1f}Q{bx:.1f} {by:.1f} {bx + r:.1f} {by:.1f}'
                         f'H{bx + bar - r:.1f}Q{bx + bar:.1f} {by:.1f} {bx + bar:.1f} {by + r:.1f}V{base:.1f}Z"/>')
        if i % 6 == 0:
            parts.append(f'<text x="{x + band / 2:.1f}" y="{height - 6}" text-anchor="middle">{esc(label)}</text>')
    parts.append("</svg>")
    return f'<section class="panel half"><h2>{esc(title)}</h2><p>Last 24 hours</p>{"".join(parts)}</section>'


def events_base(host):
    return EVEBOX_URL or f"http://{host.split(':')[0]}:{EVENTS_PORT}"


def link_events(host, page, query, label):
    """Link to the matching view in EveBox, which opens in its own tab."""
    url = f"{events_base(host)}/#/{page}?q={urllib.parse.quote(query, safe='')}"
    return f'<a href="{esc(url, quote=True)}" target="_blank" rel="noopener">{esc(str(label))}</a>'


def rule_link(host, sid, label):
    return link_events(host, "alerts", f"@sid:{sid}", label)


def host_link(ip):
    """Show the device name when the router knows it, and open the host page."""
    name = store.name_of(ip)
    label = f'{esc(name)} <span class="muted small">{esc(ip)}</span>' if name else esc(ip)
    return f'<a href="/host?ip={urllib.parse.quote(ip, safe="")}">{label}</a>'


def explain_button(sid):
    if not store.settings["ai_enabled"]:
        return ""
    return f'<a class="pill" href="/explain?sid={int(sid)}">Explain</a>'


def request_rule_update():
    with open(os.path.join(RULES_DIR, ".update-request"), "w", encoding="utf-8"):
        pass


def address_buttons(ip):
    """Block works in both modes, so an address can be stopped by hand while Monitor is on."""
    return button("/block", {"address": ip}, "Block", "/") + button("/allow", {"network": ip}, "Allow", "/")


def country_tag(ip):
    code = geo.country(ip)
    if not code:
        return ""
    name = WORLD.get(code, [code])[0]
    return f' <span class="cc" title="{esc(name, quote=True)}">{esc(code)}</span>'


def world_map(counts):
    """Countries shaded by alerts. The scale is logarithmic, so one noisy country does not wash out the rest."""
    top = max(counts.values(), default=1)
    shapes = []
    for code, (name, shape) in WORLD.items():
        total = counts.get(code, 0)
        step = math.ceil(math.log(total + 1) / math.log(top + 1) * 5) if total and top else 0
        label = f"{name}: {number(total)}" if total else name
        shapes.append(f'<path class="geo-{step}" d="{shape}"><title>{esc(label)}</title></path>')
    legend = "".join(f'<i class="geo-swatch geo-{n}"></i>' for n in range(1, 6))
    return (f'<svg class="world" viewBox="0 0 960 460" role="img" aria-label="Alerts by country in the last 24 hours">{"".join(shapes)}</svg>'
            f'<div class="geo-legend"><span>Fewer</span>{legend}<span>More</span></div>')


def hidden(back=""):
    field = f'<input type="hidden" name="back" value="{esc(back, quote=True)}">' if back else ""
    return f'<input type="hidden" name="token" value="{csrf_token}">{field}'


def button(path, fields, label, back=""):
    inputs = "".join(f'<input type="hidden" name="{k}" value="{esc(str(v), quote=True)}">' for k, v in fields.items())
    return f'<form class="inline" method="post" action="{path}">{hidden(back)}{inputs}<button class="quiet">{label}</button></form>'


def layout(active, title, body, host, notice="", error=""):
    events = events_base(host)
    links = [("/", "Overview"), ("/live", "Live"), ("/blocked", "Blocked"), ("/rules", "Rules"), ("/allowlist", "Allowlist"), ("/settings", "Settings")]
    nav = "".join(f'<a href="{p}"{" class=on" if p == active else ""}>{n}</a>' for p, n in links)
    nav += f'<a href="{esc(events, quote=True)}" target="_blank" rel="noopener">Events ↗</a>'
    leave = f'<form method="post" action="/logout">{hidden()}<button class="quiet">Sign out</button></form>'
    banner = "".join(f'<p class="note error">{esc(text)}</p>' for text in store.problems.values())
    banner += f'<p class="note">{esc(notice)}</p>' if notice else ""
    banner += f'<p class="note error">{esc(error)}</p>' if error else ""
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>Mikrokat</title><style>{STYLE}</style></head><body><header><strong>Mikrokat</strong><nav>{nav}</nav>{leave}</header>'
            f'<main><h1>{esc(title)}</h1>{banner}{body}</main></body></html>')


def table(headers, rows, empty, numeric=()):
    if not rows:
        return f'<p class="muted">{esc(empty)}</p>'
    head = "".join(f'<th{" class=n" if i in numeric else ""}>{h}</th>' for i, h in enumerate(headers))
    def cell(i, c):
        kind = " class=n" if i in numeric else " class=actions-cell" if "<form" in str(c) else " class=when" if "when-text" in str(c) else ""
        return f"<td{kind}>{c}</td>"
    cells = "".join("<tr>" + "".join(cell(i, c) for i, c in enumerate(row)) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><tr>{head}</tr>{cells}</table></div>'


def panel(title, content, hint="", size=""):
    note = f"<p>{esc(hint)}</p>" if hint else ""
    return f'<section class="panel {size}"><h2>{esc(title)}</h2>{note}{content}</section>'


def severity_badge(value):
    name = {1: "high", 2: "medium"}.get(value, "low")
    return f'<span class="badge {name}">{name.capitalize()}</span>'


def fact(value, label):
    return f'<span class="fact"><b>{esc(str(value))}</b> {esc(label)}</span>'


def tile(value, label):
    return f'<div class="tile"><b>{esc(str(value))}</b><span>{esc(label)}</span></div>'


def overview_page(host, notice="", error=""):
    series = store.hourly_series()
    labels = [r[0] for r in series]
    important, info = [int(r[1]) for r in series], [int(r[2]) for r in series]
    uptime = suricata("uptime")
    counters = suricata("dump-counters") or {}
    capture = counters.get("capture", {}) if isinstance(counters, dict) else {}
    packets, drops = capture.get("kernel_packets", 0), capture.get("kernel_drops", 0)
    ruleset = suricata("ruleset-stats")
    loaded = ruleset[0].get("rules_loaded", 0) if isinstance(ruleset, list) and ruleset else "?"
    logs = sum(os.path.getsize(f) for f in glob.glob(LOG_GLOB))
    now_blocked = len(store.active_blocks())
    running = isinstance(uptime, int) and not store.problems
    blocking = store.settings["mode"] == "block"
    state = ("Blocking" if blocking else "Monitoring") if running else "Needs attention"
    status = (f'<div class="status"><span class="state"><i class="dot{"" if running else " off"}"></i>{state}</span>'
              + (fact(duration(uptime), "uptime") if isinstance(uptime, int) else "")
              + fact(short_number(packets), "packets") + fact(f"{drops / packets * 100:.2f}%" if packets else "0%", "dropped")
              + fact(number(loaded), "rules") + fact(f"{logs / 2**30:.2f} GB", "logs") + "</div>")
    tiles = "".join([
        tile(number(sum(important)), "Important alerts, 24h"),
        tile(number(store.actions_today()), "Blocked, 24h" if blocking else "Would block, 24h"),
        tile(number(now_blocked), "On the block list now"),
        tile(short_number(sum(info)), "Informational, 24h"),
    ])
    hours = table(["Hour", "Important", "Informational"], [[esc(r[0]), number(int(r[1])), number(int(r[2]))] for r in reversed(series)], "", (1, 2))
    rows = [[severity_badge(sev), rule_link(host, sid, sig), number(int(total)),
             explain_button(sid) + button("/ignore", {"sid": sid}, "Mute", "/") + button("/rules/disable", {"entry": sid}, "Turn off", "/")]
            for sid, sev, sig, total in store.top_rules()]
    addresses = [[host_link(ip) + country_tag(ip), number(int(total)), address_buttons(ip)] for ip, total in store.top_addresses()]
    devices = [[host_link(ip), number(int(important)), number(int(total))] for ip, important, total in store.top_hosts()]
    latest = [[f'<span class="when-text">{esc(a[0][5:16])}</span>', host_link(a[1]) + country_tag(a[1]), esc(a[5]), rule_link(host, a[3], a[4] or a[3]), address_buttons(a[1])] for a in store.recent_actions()]
    countries = [(c, int(t)) for c, t in store.countries_today()]
    places = table(["Country", "Alerts"], [[esc(WORLD.get(c, [c])[0]), number(t)] for c, t in countries[:8]], "No alerts with a country yet.", (1,))
    geography = f'<div class="geo-grid"><div>{world_map(dict(countries))}</div><div>{places}</div></div><p class="source">IP data by <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP</a>.</p>'
    body = (status + f'<div class="tiles">{tiles}</div><div class="panels">'
            + bar_chart("Important alerts per hour", labels, important, 2) + bar_chart("Informational alerts per hour", labels, info, 1)
            + panel("Where alerts come from", geography, "Remote addresses in the last 24 hours. Countries are looked up on this host.")
            + panel("Top rules", table(["Severity", "Rule", "Alerts", ""], rows, "No alerts yet.", (2,)),
                    "Open a rule to see its alerts in Events. Mute stops notifications and blocks, Turn off disables the rule.")
            + panel("Your devices", table(["Device", "Important", "All"], devices, "No alerts on your devices yet.", (1, 2)), "Internal hosts seen in alerts.", size="third")
            + panel("Top remote addresses", table(["Address", "Alerts", ""], addresses, "No alerts yet.", (1,)), size="rest")
            + panel("Latest actions", table(["Time", "Address", "Action", "Rule", ""], latest, "Nothing to report."))
            + panel("Hourly numbers", f'<details><summary class="muted">Show as a table</summary>{hours}</details>')
            + "</div>")
    return layout("/", "Overview", body, host, notice, error)


def host_page(host, ip):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return layout("/", "Unknown address", panel("Not found", '<p class="muted">That is not a valid address.</p>'), host)
    rules, peers, taken, first, last = store.host_summary(ip)
    internal = store.allowed(ip)
    name = store.name_of(ip)
    important, total = sum(int(r[3]) for r in rules if r[1] <= 2), sum(int(r[3]) for r in rules)
    blocked = ip in store.active_blocks()
    state = f'<i class="dot{" off" if blocked or important else ""}"></i>{"Blocked" if blocked else "Internal device" if internal else "Remote address"}'
    status = (f'<div class="status"><span class="state">{state}</span>{fact(ip, "")}{fact(geo.country(ip) or "No country", "")}'
              f'{fact(first or "never", "first seen")}{fact(last or "never", "last seen")}</div>')
    tiles = tile(number(important), "Important alerts, 7 days") + tile(number(total), "All alerts, 7 days") + tile(number(len(peers)), "Addresses in contact")
    rows = [[severity_badge(sev), rule_link(host, sid, sig), number(int(count)), explain_button(sid)] for sid, sev, sig, count, _ in rules]
    contacts = [[host_link(peer) + country_tag(peer), number(int(count))] for peer, count in peers]
    latest = [[f'<span class="when-text">{esc(a[0][5:16])}</span>', esc(a[4]), rule_link(host, a[2], a[3] or a[2])] for a in taken]
    tools = address_buttons(ip) if not internal else ""
    actions_row = f'<div class="row">{link_events(host, "events", f"@ip:{ip}", "Open in Events")}{tools}</div>'
    body = (status + f'<div class="tiles">{tiles}</div><div class="panels">'
            + panel("Actions", actions_row)
            + panel("Rules that matched", table(["Severity", "Rule", "Alerts", ""], rows, "No alerts in the last 7 days.", (2,)), "Last 7 days.")
            + panel("Addresses in contact", table(["Address", "Alerts"], contacts, "Nothing yet.", (1,)), size="third")
            + panel("Actions taken", table(["Time", "Action", "Rule"], latest, "Nothing yet."), size="rest") + "</div>")
    return layout("/", name or ip, body, host)


def explain_page(host, sid):
    if not (store.settings["ai_enabled"] and sid.isdigit()):
        return layout("/", "Explain", panel("Not available", '<p class="muted">Turn on Explain on the AI tab of Settings.</p>'), host)
    number_id = int(sid)
    signature, severity, count = store.rule_facts(number_id)
    if not signature:
        return layout("/", "Explain", panel("Not found", '<p class="muted">Mikrokat has not seen this rule yet.</p>'), host)
    try:
        text = esc(actions.explain(number_id)).replace("\n", "<br>")
    except Exception as failure:
        text = f'<span class="error">The model did not answer ({esc(failure.__class__.__name__)}). Check the AI tab of Settings.</span>'
    body = (f'<div class="status"><span class="state">{severity_badge(severity)}</span>{fact(number(int(count or 0)), "alerts, 24h")}{fact(number_id, "rule")}</div>'
            + panel(signature, f'<p class="answer">{text}</p>', "Written by your AI model. Only the rule text was sent: no addresses and no traffic.")
            + f'<p>{rule_link(host, number_id, "See the alerts in Events")}</p>')
    return layout("/", "Explain", body, host)


def conf_lines(name):
    try:
        with open(os.path.join(RULES_DIR, name), encoding="utf-8") as source:
            return source.read().splitlines()
    except FileNotFoundError:
        return []


def write_conf(name, lines):
    temp = os.path.join(RULES_DIR, name + ".tmp")
    with open(temp, "w", encoding="utf-8") as target:
        target.write("\n".join(lines) + "\n")
    os.replace(temp, os.path.join(RULES_DIR, name))


def disabled_entries():
    return [line.strip() for line in conf_lines("disable.conf") if line.strip() and not line.startswith("#")]


def add_disabled(entry):
    entry = entry.strip()
    if not re.fullmatch(r"\d+|(re|group):[^\n\r]{1,200}", entry):
        return "Use a rule number, re:some text or group:name.rules."
    if entry not in disabled_entries():
        write_conf("disable.conf", conf_lines("disable.conf") + [entry])
    return None


def remove_disabled(entry):
    write_conf("disable.conf", [line for line in conf_lines("disable.conf") if line.strip() != entry.strip()])


def rules_page(host, notice="", error=""):
    names = store.rule_names()
    rows = [[rule_link(host, e, e) if e.isdigit() else esc(e), esc(names.get(int(e), "") if e.isdigit() else ""), button("/rules/enable", {"entry": e}, "Turn on")]
            for e in disabled_entries()]
    status = (conf_lines(".update-status") or ["never"])[0]
    log_tail = "\n".join(conf_lines(".update.log")[-6:])
    local = esc("\n".join(conf_lines("local.rules")))
    ruleset = suricata("ruleset-stats")
    loaded = ruleset[0] if isinstance(ruleset, list) and ruleset else {}
    failed = loaded.get("rules_failed", "?")
    state = (f'<div class="status"><span class="state"><i class="dot{"" if status.split()[0] != "failed" else " off"}"></i>Last update: {esc(status)}</span>'
             f'{fact(number(loaded.get("rules_loaded", "?")), "rules loaded")}{fact(number(failed), "failed")}</div>')
    tiles = tile(number(loaded.get("rules_loaded", "?")), "Rules loaded") + tile(len(rows), "Turned off here") + tile(len(store.settings["ignore_sids"]), "Muted")
    apply_form = (f'<form method="post" action="/rules/apply">{hidden()}<button>Apply rules</button></form>' + (f"<pre>{esc(log_tail)}</pre>" if log_tail else ""))
    add = (f'<form method="post" action="/rules/disable">{hidden("/rules")}<div class="fields">'
           f'<label class="field"><span>Turn off a rule</span><input name="entry" placeholder="2033078 or re:some text" required></label></div>'
           f'<div class="actions"><button class="ghost">Add</button></div></form>')
    own = (f'<form method="post" action="/rules/local">{hidden()}<textarea name="text" spellcheck="false">{local}</textarea>'
           f'<div class="actions"><button class="ghost">Save</button></div></form>')
    body = (state + f'<div class="tiles">{tiles}</div><div class="stack">'
            + panel("Apply changes", apply_form, "Downloads the latest rules, applies this page and reloads Suricata without stopping it.")
            + panel("Turned off", table(["Rule", "Name", ""], rows, "Every rule from the rulesets is in use.") + add)
            + panel("Your rules", own, "Suricata rule syntax. Use numbers from 1000000 to 1999999.") + "</div>")
    return layout("/rules", "Rules", body, host, notice, error)


def blocked_page(host, notice="", error=""):
    blocking = store.settings["mode"] == "block"
    state = "Automatic blocking is on" if blocking else "Automatic blocking is off"
    form = (f'<form method="post" action="/block">{hidden()}<div class="fields">'
            f'<label class="field"><span>Address</span><input name="address" placeholder="203.0.113.5" required></label>'
            f'<label class="field"><span>Block time</span><input name="timeout" value="{esc(store.settings["block_timeout"], quote=True)}"></label>'
            f'<label class="field"><span>Note</span><input name="note" placeholder="Why"></label></div><div class="actions"><button>Block</button></div></form>')
    if not store.router_ready():
        return layout("/blocked", "Blocked", f'<div class="stack">{panel("Router not set up", "<p class=muted>Add the router connection in Settings to see the block list.</p>")}</div>', host, notice, error)
    try:
        entries, age, failed = actions.blocked_copy()
    except Exception as failure:
        return layout("/blocked", "Blocked", f'<div class="stack">{panel("Router not reachable", f"<p class=error>{esc(failure.__class__.__name__)}</p>")}</div>', host, notice, error)
    rows = []
    for e in entries:
        fields = {"id": e["id"], "family": e["family"], "address": e["address"]}
        rows.append([host_link(e["address"]) + country_tag(e["address"]), esc(e["comment"]), f'<span class="when-text">{esc(duration(e["left"]) if e["left"] is not None else "no limit")}</span>',
                     button("/unblock", fields, "Unblock") + button("/unblock-allow", fields, "Unblock and allow")])
    list_name = esc(store.settings["address_list"])
    status = (f'<div class="status"><span class="state"><i class="dot{"" if blocking else " idle"}"></i>{state}</span>'
              f'{fact(store.settings["address_list"], "list")}{fact(store.settings["block_timeout"], "block time")}'
              f'{fact("Router not answering" if failed else f"{age}s ago", "" if failed else "updated")}</div>')
    tiles = tile(number(len(entries)), "On the block list now") + tile(number(store.actions_today()), "Blocked, 24h" if blocking else "Would block, 24h")
    body = (status + f'<div class="tiles">{tiles}</div><div class="stack">'
            + panel("Block list", table(["Address", "Reason", "Time left", ""], rows, "Nothing is blocked right now."), f"Addresses in the {store.settings['address_list']} list on the router.")
            + panel("Block an address", form, "Works in both modes. Allowlisted addresses are refused.") + "</div>")
    return layout("/blocked", "Blocked", body, host, notice, error)


def allowlist_page(host, notice="", error=""):
    rows = [[esc(e["network"]), esc(e["note"]), f'<span class="when-text">{esc(e["added"])}</span>', button("/remove", {"network": e["network"]}, "Remove")] for e in store.custom]
    built_in, removed = [], []
    for network in store.FIXED_ALLOWLIST:
        name = str(network)
        kind = "Private network" if network.is_private else "Public DNS resolver"
        if name in store.settings["builtin_off"]:
            removed.append([esc(name), kind, button("/builtin", {"network": name, "enabled": "1"}, "Restore")])
        else:
            built_in.append([esc(name), kind, button("/builtin", {"network": name}, "Remove")])
    restore = (f'<details><summary class="muted">Removed entries ({len(removed)})</summary>{table(["Network", "Type", ""], removed, "")}</details>' if removed else "")
    form = (f'<form method="post" action="/allow">{hidden("/allowlist")}<div class="fields">'
            f'<label class="field"><span>Address or network</span><input name="network" placeholder="203.0.113.5 or 203.0.113.0/24" required></label>'
            f'<label class="field"><span>Note</span><input name="note" placeholder="Why"></label></div><div class="actions"><button>Add</button></div></form>')
    tiles = tile(number(len(rows)), "Your entries") + tile(number(len(store.FIXED_ALLOWLIST) - len(store.settings["builtin_off"])), "Built in, active")
    body = (f'<div class="tiles">{tiles}</div><div class="stack">'
            + panel("Add to the allowlist", form, "These addresses are never blocked or reported. Events still shows them.")
            + panel("Your entries", table(["Network", "Note", "Added", ""], rows, "Nothing yet."))
            + panel("Built in", table(["Network", "Type", ""], built_in, "Every built-in entry is removed.") + restore,
                    "Protects your own networks and common DNS servers. If you remove a private network, Mikrokat can block hosts inside it.") + "</div>")
    return layout("/allowlist", "Allowlist", body, host, notice, error)


GUIDE = """<aside class="guide">
<h2>1. Send traffic here</h2>
<p>Copy the traffic to and from the internet to this host. Replace WAN with your interface list.</p>
<pre>/ip firewall mangle add chain=forward out-interface-list=WAN action=sniff-tzsp sniff-target={ip} sniff-target-port=37008 comment=mikrokat
/ip firewall mangle add chain=forward in-interface-list=WAN action=sniff-tzsp sniff-target={ip} sniff-target-port=37008 comment=mikrokat</pre>
<p>Fasttracked connections skip these rules, so they are not inspected.</p>
<h2>2. Create an API user</h2>
<p>Give Mikrokat only the rights it needs, and only from this host.</p>
<pre>/user group add name=mikrokat policy=api,read,write
/user add name=mikrokat group=mikrokat address={ip} password=CHOOSE_ONE</pre>
<p>Enter the router address, user and password on this page. Use port 8729 with TLS, or 8728 without. Tick Accept any certificate if the router has a self-signed or expired one.</p>
<h2>3. Add the drop rules</h2>
<p>Mikrokat fills an address list. These rules make the router act on it. Use the same name as Address list.</p>
<pre>/ip firewall raw add chain=prerouting action=drop src-address-list=mikrokat comment=mikrokat
/ip firewall raw add chain=prerouting action=drop dst-address-list=mikrokat comment=mikrokat</pre>
<p>For IPv6, repeat them under /ipv6 firewall raw and turn on Block IPv6 addresses.</p>
<h2>4. Choose your notifications</h2>
<p>On the Notifications tab, turn on Telegram, email or a webhook. For Telegram, message @BotFather to create a bot, send it a message, then open api.telegram.org/bot&lt;token&gt;/getUpdates to read your chat ID.</p>
<h2>5. Test</h2>
<p>Each section has its own test button. It saves what is on screen, then tries it.</p>
<h2>6. Start in Monitor</h2>
<p>Leave Monitor on for a few days. Mute noisy rules from Overview and add your public addresses and other trusted hosts to the Allowlist. Then switch to Block.</p>
<p>Every block shows on the Blocked page, where you can remove it.</p>
</aside>"""


SETTINGS_TABS = (("protection", "Protection"), ("notifications", "Notifications"), ("router", "Router"), ("data", "Data"), ("ai", "AI"), ("account", "Account"))


def settings_page(host, notice="", error="", tab=""):
    s = store.settings
    tab = tab if tab in dict(SETTINGS_TABS) else "protection"

    def checked(flag):
        return " checked" if flag else ""

    def field(label, name, value="", kind="text", hint="", extra=""):
        note = f'<span class="hint">{esc(hint)}</span>' if hint else ""
        return (f'<label class="field"><span>{label}</span><input type="{kind}" name="{name}" autocomplete="off" '
                f'value="{esc(str(value), quote=True)}" {extra}>{note}</label>')

    def secret(label, name, stored, empty="Not set yet."):
        return field(label, name, "", "password", "Stored. Leave empty to keep it." if stored else empty)

    def switch(name, label, on):
        return f'<label class="switch"><input type="checkbox" name="{name}"{checked(on)}><span></span>{label}</label>'

    def select(label, name, value, options):
        items = "".join(f'<option value="{v}"{" selected" if v == value else ""}>{t}</option>' for v, t in options)
        return f'<label class="field"><span>{label}</span><select name="{name}">{items}</select></label>'

    def test(path, label):
        return f'<div class="actions"><button class="ghost" formaction="{path}">{label}</button></div>'

    mode = "".join(f'<label class="choice"><input type="radio" name="mode" value="{v}"{checked(s["mode"] == v)}><span>{t}<small>{d}</small></span></label>'
                   for v, t, d in (("monitor", "Monitor", "Notify only"), ("block", "Block", "Add addresses to the router")))
    severity = "".join(f'<label class="choice"><input type="checkbox" name="severity{n}"{checked(n in s["severities"])}><span>{t}</span></label>'
                       for n, t in (("1", "1 High"), ("2", "2 Medium"), ("3", "3 Low")))
    protection = (f'<section class="card"><h2>What to do</h2><p>How Mikrokat reacts when an alert matches.</p>'
                  f'<div class="group"><span class="group-label">Mode</span><div class="choices">{mode}</div></div>'
                  f'<div class="group"><span class="group-label">React to severity</span><div class="choices">{severity}</div></div>'
                  f'<div class="fields">{field("Block time", "block_timeout", s["block_timeout"], hint="For example 12h or 1d")}'
                  f'{field("Repeat window (seconds)", "dedupe_seconds", s["dedupe_seconds"], "number", "The same alert stays quiet this long")}</div>'
                  f'<div class="group"></div>{switch("block_ipv6", "Block IPv6 addresses (needs the IPv6 drop rules)", s["block_ipv6"])}'
                  f'{switch("progressive", "Block repeat offenders for longer", s["progressive"])}<div class="reveal"><div class="fields">'
                  + field("Block steps", "block_steps", s["block_steps"], hint="First, second and later blocks. Memory lasts 90 days. This replaces Block time.")
                  + '</div></div></section>')
    notifications = (
        f'<section class="card"><h2>Daily summary</h2><p>One message a day with the alerts, the top rules and any problem, on the channels below.</p>'
        f'{switch("digest_enabled", "Send a daily summary", s["digest_enabled"])}<div class="reveal"><div class="fields">'
        + field("Hour", "digest_hour", s["digest_hour"], "number", "From 0 to 23") + '</div>' + test("/test/digest", "Send one now") + '</div></section>'
        f'<section class="card"><h2>Telegram</h2><p>Message a bot, a group or a channel.</p>{switch("telegram_enabled", "Send to Telegram", s["telegram_enabled"])}<div class="reveal">'
        f'<div class="fields">{secret("Bot token", "telegram_token", s["telegram_token"])}{field("Chat ID", "telegram_chat", s["telegram_chat"])}'
        + field("Proxy", "telegram_proxy", "", "password", "Stored. Leave empty to keep it, type none to remove it." if s["telegram_proxy"] else "Optional, if Telegram is blocked in your country.")
        + '</div>' + test("/test/telegram", "Send a test message") + '</div></section>'
        f'<section class="card"><h2>Email</h2><p>Send through your own mail server.</p>{switch("email_enabled", "Send by email", s["email_enabled"])}<div class="reveal">'
        f'<div class="fields">{field("Mail server", "email_host", s["email_host"], hint="For example mail.example.com")}{field("Port", "email_port", s["email_port"], "number")}'
        + select("Security", "email_security", s["email_security"], (("starttls", "STARTTLS"), ("tls", "TLS"), ("none", "None")))
        + field("User", "email_user", s["email_user"]) + secret("Password", "email_password", s["email_password"], "Leave empty if the server needs no login.")
        + field("From", "email_from", s["email_from"]) + field("To", "email_to", s["email_to"], hint="One or more, separated by spaces")
        + '</div>' + test("/test/email", "Send a test email") + '</div></section>'
        f'<section class="card"><h2>Webhook</h2><p>Post each alert to Slack, Discord, Teams or your own service.</p>{switch("webhook_enabled", "Send to a webhook", s["webhook_enabled"])}<div class="reveal">'
        f'<div class="fields">{field("URL", "webhook_url", "", "password", "Stored. Leave empty to keep it, type none to remove it." if s["webhook_url"] else "The address that receives the alerts.")}'
        + select("Format", "webhook_format", s["webhook_format"], (("json", "Generic JSON"), ("slack", "Slack or Mattermost"), ("discord", "Discord"), ("teams", "Microsoft Teams"), ("splunk", "Splunk HEC")))
        + secret("Secret", "webhook_secret", s["webhook_secret"], "Optional. Signing secret, or the token for Splunk HEC.")
        + '</div>' + test("/test/webhook", "Send a test") + '</div></section>')
    router = (f'<section class="card"><h2>MikroTik connection</h2><p>Used to block, unblock and show the block list.</p>'
              f'<div class="fields">{field("Router address", "router_host", s["router_host"])}{field("Port", "router_port", s["router_port"], "number", "8729 with TLS, 8728 without")}'
              f'{field("User", "router_user", s["router_user"])}{secret("Password", "router_password", s["router_password"])}'
              f'{field("Address list", "address_list", s["address_list"], hint="The list your drop rules use")}</div><div class="group"></div>'
              f'{switch("router_tls", "Use TLS", s["router_tls"])}{switch("router_tls_insecure", "Accept any certificate", s["router_tls_insecure"])}'
              + test("/test/router", "Test connection") + '</section>')
    data = (f'<section class="card"><h2>Rule updates</h2><p>Old rules miss new threats. Mikrokat warns you when they pass 8 days.</p><div class="fields">'
            + select("Update automatically", "rules_auto", s["rules_auto"], (("daily", "Every day"), ("weekly", "Every week"), ("off", "Off")))
            + field("Hour", "rules_hour", s["rules_hour"], "number", "From 0 to 23") + '</div></section>'
            f'<section class="card"><h2>Health</h2><p>Mikrokat warns you if it stops seeing traffic, the rules get old, the disk fills up or the router stops answering.</p><div class="fields">'
            + field("Traffic alarm after (minutes)", "health_minutes", s["health_minutes"], "number") + '</div></section>'
            f'<section class="card"><h2>Logs and rules</h2><p>What to keep and what to skip.</p>'
            f'<div class="fields">{field("Keep logs for (days)", "retention_days", s["retention_days"], "number")}'
            f'{field("Muted rules", "ignore_sids", " ".join(s["ignore_sids"]), hint="Rule numbers, separated by spaces")}</div></section>'
            f'<section class="card"><h2>Send alerts to a SIEM</h2><p>For Splunk, Elastic, Wazuh, Graylog or any log collector. Optional: Mikrokat does not need any of them.</p>'
            f'<div>{switch("alert_file_enabled", "Write an alert file", s["alert_file_enabled"])}<p class="hint reveal">data/logs/alerts.json, one JSON line per alert in Suricata EVE format. It rotates at 20 MB.</p></div>'
            f'<div>{switch("syslog_enabled", "Send over syslog", s["syslog_enabled"])}<div class="reveal">'
            f'<div class="fields">{field("Syslog server", "syslog_host", s["syslog_host"])}{field("Port", "syslog_port", s["syslog_port"], "number")}'
            + select("Protocol", "syslog_protocol", s["syslog_protocol"], (("udp", "UDP"), ("tcp", "TCP")))
            + '</div>' + test("/test/syslog", "Send a test event") + '</div></div></section>')
    account = (f'<section class="card"><h2>Password</h2><p>Signs in to these pages and Events. It keeps working when single sign-on is on.</p>'
               f'<div class="fields">{field("New password", "new_password", "", "password", "At least 12 characters. Leave empty to keep it.")}'
               f'{field("Repeat it", "new_password2", "", "password")}</div></section>'
               f'<section class="card"><h2>Single sign-on</h2><p>Sign in through Authentik, Keycloak, Authelia or any OpenID Connect provider.</p>'
               f'{switch("oidc_enabled", "Show the single sign-on button", s["oidc_enabled"])}<div class="reveal">'
               f'<div class="fields">{field("Button name", "oidc_label", s["oidc_label"], hint="For example Authentik")}'
               f'{field("Issuer URL", "oidc_issuer", s["oidc_issuer"], hint="For Authentik: https://host/application/o/slug/")}'
               f'{field("Client ID", "oidc_client_id", s["oidc_client_id"])}{secret("Client secret", "oidc_client_secret", s["oidc_client_secret"])}'
               f'{field("Allowed group", "oidc_group", s["oidc_group"], hint="Everyone in it gets full control")}'
               f'{field("Scopes", "oidc_scopes", s["oidc_scopes"], hint="Add groups if your provider needs it")}</div>'
               f'<p class="hint">Redirect URI to register: {esc(callback_url(host))}</p>'
               f'<details class="howto"><summary>How to set it up</summary><ol>'
               f'<li>In your provider, create a confidential OAuth2/OpenID client with the redirect URI above.</li>'
               f'<li>Copy its client ID and secret here.</li>'
               f'<li>Create a group for the people who can use Mikrokat, and enter its name in Allowed group.</li>'
               f'<li>Save, sign out and try the button. The password keeps working if something goes wrong.</li></ol>'
               f'<p><b>Authentik:</b> use Applications, Create with Provider. The issuer is https://your-host/application/o/your-slug/ and groups come with the profile scope.</p>'
               f'<p><b>Keycloak:</b> the issuer is https://your-host/realms/your-realm. Add a Group Membership mapper with the claim name groups and Full group path off.</p>'
               f'<p><b>Authelia:</b> the issuer is https://your-host. Add groups to Scopes here and on the client.</p></details></div></section>')
    assistant = (f'<section class="card"><h2>Explain</h2><p>Adds an Explain button that describes a rule in plain words, on request. It only ever sends the rule text, never addresses or traffic, and it cannot block anything.</p>'
                 f'{switch("ai_enabled", "Show the Explain button", s["ai_enabled"])}<div class="reveal"><div class="fields">'
                 + field("Address", "ai_url", s["ai_url"], hint="Any OpenAI-compatible API, such as http://host:11434/v1 for Ollama")
                 + field("Model", "ai_model", s["ai_model"]) + secret("API key", "ai_key", s["ai_key"], "Leave empty for a local model.")
                 + field("Answer language", "ai_language", s["ai_language"]) + '</div></div></section>')
    panes = {"protection": protection, "notifications": notifications, "router": router, "data": data, "ai": assistant, "account": account}
    radios = "".join(f'<input type="radio" name="tab" id="tab-{k}" value="{k}"{checked(k == tab)}>' for k, _ in SETTINGS_TABS)
    labels = "".join(f'<label for="tab-{k}">{t}</label>' for k, t in SETTINGS_TABS)
    content = "".join(f'<div class="pane" id="pane-{k}">{panes[k]}</div>' for k, _ in SETTINGS_TABS)
    body = (f'<form method="post" action="/settings" autocomplete="off">{hidden()}{radios}<div class="tabbar">{labels}</div>{content}'
            f'<div class="savebar"><button>Save changes</button></div></form>')
    guide = GUIDE.format(ip=esc(host.split(":")[0]))
    return layout("/settings", "Settings", f'<div class="with-guide"><div>{body}</div>{guide}</div>', host, notice, error)


LIVE_SCRIPT = """
const feed = document.getElementById('feed'), state = document.getElementById('state'), dot = document.getElementById('dot');
const rate = document.getElementById('rate'), pause = document.getElementById('pause'), clear = document.getElementById('clear'), base = feed.dataset.events;
const filters = () => [...document.querySelectorAll('[data-filter]')].filter(i => i.checked).map(i => i.dataset.filter);
const rows = new Map(), limit = 150, empty = document.getElementById('empty'), token = feed.dataset.token;
function act(path, name, value, text) {
  const form = document.createElement('form'); form.method = 'post'; form.action = path; form.className = 'inline';
  for (const [k, v] of [['token', token], ['back', '/live'], [name, value]]) { const i = document.createElement('input'); i.type = 'hidden'; i.name = k; i.value = v; form.append(i); }
  const b = document.createElement('button'); b.className = 'quiet'; b.textContent = text; form.append(b); return form;
}
let paused = false;
function group(e) { return e.kind === 'alert' ? (e.severity <= 2 ? 'important' : 'info') : e.kind === 'action' ? 'action' : 'system'; }
function label(e) { return e.kind === 'alert' ? ({1: 'High', 2: 'Medium'}[e.severity] || 'Low') : {action: 'Action', error: 'Error', system: 'You'}[e.kind]; }
function style(e) { return e.kind === 'alert' ? ({1: 'high', 2: 'medium'}[e.severity] || 'low') : e.kind === 'action' ? 'action' : e.kind === 'error' ? 'error' : 'system'; }
function link(page, query, text) { const a = document.createElement('a'); a.href = base + '/#/' + page + '?q=' + encodeURIComponent(query); a.target = '_blank'; a.rel = 'noopener'; a.textContent = text; return a; }
function line(e) {
  const row = document.createElement('div'); row.className = 'line'; row.dataset.group = group(e);
  const when = document.createElement('time'); when.textContent = e.time;
  const badge = document.createElement('span'); badge.innerHTML = '<span class="badge"></span>'; badge.firstChild.classList.add(style(e)); badge.firstChild.textContent = label(e);
  const text = document.createElement('div'); text.className = 'text';
  text.append(e.sid ? link('alerts', '@sid:' + e.sid, e.text) : e.text);
  const sub = document.createElement('span'); sub.className = 'sub';
  if (e.source) { sub.append(link('events', '@ip:' + e.source, e.source_name || e.source), ' to ', link('events', '@ip:' + e.destination, e.destination_name || e.destination)); }
  if (e.country) { sub.append(' · ' + e.country); }
  if (e.rule) { sub.textContent = e.rule; }
  text.append(sub);
  const remote = e.address || (e.kind === 'alert' && e.remote);
  if (remote) { const tools = document.createElement('div'); tools.className = 'tools'; tools.append(act('/block', 'address', remote, 'Block'), act('/allow', 'network', remote, 'Allow')); text.append(tools); }
  const count = document.createElement('span'); count.className = 'count'; count.hidden = true; count.dataset.n = '1';
  row.append(when, badge, text, count); return row;
}
function add(e) {
  const key = [e.kind, e.sid, e.source, e.destination, e.text].join('|');
  let row = rows.get(key);
  if (row) {
    const count = row.lastChild; count.dataset.n = Number(count.dataset.n) + 1; count.textContent = '×' + count.dataset.n; count.hidden = false;
    row.firstChild.textContent = e.time;
  } else {
    row = line(e); rows.set(key, row); row.dataset.key = key;
    row.hidden = !filters().includes(row.dataset.group);
  }
  feed.prepend(row);
  while (feed.children.length > limit) { rows.delete(feed.lastChild.dataset.key); feed.lastChild.remove(); }
  note();
}
function note() { const all = feed.children.length, seen = [...feed.children].filter(r => !r.hidden).length; empty.hidden = seen > 0; empty.textContent = all ? all + ' lines are hidden by the filters above.' : 'Waiting for the first events.'; }
function show() { const on = filters(); for (const row of feed.children) row.hidden = !on.includes(row.dataset.group); note(); }
const source = new EventSource('/live/stream');
source.onopen = () => { state.textContent = 'Live'; dot.className = 'dot'; };
source.onerror = () => { state.textContent = 'Reconnecting'; dot.className = 'dot off'; };
source.onmessage = m => { if (!paused) add(JSON.parse(m.data)); };
source.addEventListener('stats', m => { rate.textContent = JSON.parse(m.data).packets_per_second.toLocaleString(); });
try {
  const saved = JSON.parse(localStorage.getItem('mikrokat-live') || 'null');
  if (saved) document.querySelectorAll('[data-filter]').forEach(i => { i.checked = saved.includes(i.dataset.filter); });
} catch (e) {}
document.querySelectorAll('[data-filter]').forEach(i => i.addEventListener('change', () => {
  show();
  try { localStorage.setItem('mikrokat-live', JSON.stringify(filters())); } catch (e) {}
}));
pause.addEventListener('click', () => { paused = !paused; pause.textContent = paused ? 'Resume' : 'Pause'; });
clear.addEventListener('click', () => { rows.clear(); feed.replaceChildren(); note(); });
note();
"""


def live_page(host, notice="", error=""):
    def chip(name, text, on):
        return f'<label class="choice"><input type="checkbox" data-filter="{name}"{" checked" if on else ""}><span>{text}</span></label>'
    filters = chip("action", "Actions", True) + chip("important", "Important", True) + chip("info", "Informational", True) + chip("system", "System", True)
    body = (f'<div class="status"><span class="state"><i id="dot" class="dot idle"></i><span id="state">Connecting</span></span>'
            f'<span class="fact"><b id="rate">0</b> packets/s</span></div>'
            f'<section class="panel"><div class="toolbar"><div class="choices">{filters}</div><div class="row"><button class="ghost" id="pause" type="button">Pause</button>'
            f'<button class="ghost" id="clear" type="button">Clear</button></div></div>'
            f'<p class="muted foot" id="empty"></p><div class="feed" id="feed" data-events="{esc(events_base(host), quote=True)}" data-token="{csrf_token}"></div>'
            f'<p class="muted foot">Latest 150 lines. Repeats are grouped. The full record is in Events.</p></section><script>{LIVE_SCRIPT}</script>')
    return layout("/live", "Live", body, host, notice, error)


def callback_url(host):
    return f"{PUBLIC_URL or 'http://' + host}/auth/callback"


def login_page(error=""):
    message = f'<p class="note error">{esc(error)}</p>' if error else ""
    single = (f'<a class="sso" href="/auth/login">Sign in with {esc(store.settings["oidc_label"])}</a><div class="or"><span>or use your password</span></div>'
              if store.settings["oidc_enabled"] else "")
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>Sign in to Mikrokat</title><style>{STYLE}</style></head><body class="login-page"><main><section class="card login">'
            f'<h1>Mikrokat</h1><p class="tagline">Intrusion detection for MikroTik</p>{message}{single}'
            f'<form method="post" action="/login">'
            f'<label class="field"><span>User</span><input name="username" autocomplete="username" autofocus required></label>'
            f'<label class="field"><span>Password</span><input type="password" name="password" autocomplete="current-password" required></label>'
            f'<button>Sign in</button></form></section></main></body></html>')


PAGES = {"/": overview_page, "/live": live_page, "/blocked": blocked_page, "/rules": rules_page, "/allowlist": allowlist_page, "/settings": settings_page}


def manual_block(form):
    """Block one address from the page. Return an error message, or None."""
    try:
        address = str(ipaddress.ip_address(form.get("address", "").strip()))
    except ValueError:
        return "That is not a valid address."
    if store.allowed(address):
        return f"{address} is on the allowlist, so it cannot be blocked."
    if ":" in address and not store.settings["block_ipv6"]:
        return "IPv6 blocking is off. Turn it on in Settings."
    timeout = form.get("timeout", "").strip() or store.settings["block_timeout"]
    if not re.fullmatch(r"\d+[smhdw]", timeout):
        return "The block time looks like 12h or 1d."
    note = form.get("note", "").strip() or "Blocked by hand"
    return None if actions.block(address, f"Mikrokat: {note}", timeout) else "The router refused the block. See the app log."


def unblock(form):
    """Remove one entry from the router list. Return an error message, or None."""
    entry, family, address = form.get("id", ""), form.get("family", ""), form.get("address", "")
    if not re.fullmatch(r"\*[0-9A-Fa-f]+", entry) or family not in ("0", "1"):
        return "That entry is not valid."
    try:
        actions.unblock(int(family), entry, address)
    except Exception as failure:
        return f"The router refused ({failure.__class__.__name__})."
    return None


def test_router():
    try:
        return f"Router answered: {actions.test_router()}.", ""
    except Exception as failure:
        return "", f"The router did not answer ({failure.__class__.__name__}). Check the address, user, password and port."


def session_from(headers):
    """Return True when the request carries a valid session cookie."""
    try:
        cookie = http.cookies.SimpleCookie(headers.get("Cookie", ""))
    except http.cookies.CookieError:
        return False
    morsel = cookie.get(SESSION_COOKIE)
    return bool(morsel) and sessions.get(morsel.value, 0) > time.time()


def new_session():
    now = time.time()
    for token in [t for t, until in sessions.items() if until <= now]:
        del sessions[token]
    token = secrets.token_urlsafe(32)
    sessions[token] = now + SESSION_HOURS * 3600
    return token


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def authorized(self):
        if session_from(self.headers):
            return True
        self.send_response(303)
        self.send_header("Location", "/login")
        self.end_headers()
        return False

    def reply(self, body):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if "gzip" in self.headers.get("Accept-Encoding", ""):
            data = gzip.compress(data, 5)
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def stream(self):
        """Send the live feed as server-sent events until the browser goes away."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        last, before, stamp = 0, None, time.monotonic()
        try:
            while True:
                entries = store.activity_since(last, 3)
                for entry in entries:
                    last = entry["id"]
                    self.wfile.write(f"data: {json.dumps(entry)}\n\n".encode())
                now = time.monotonic()
                if now - stamp >= 5:
                    counters = suricata("dump-counters") or {}
                    packets = (counters.get("capture") or {}).get("kernel_packets", 0) if isinstance(counters, dict) else 0
                    if before is not None and packets >= before:
                        rate = round((packets - before) / (now - stamp))
                        self.wfile.write(f"event: stats\ndata: {json.dumps({'packets_per_second': rate})}\n\n".encode())
                    before, stamp = packets, now
                self.wfile.write(b": keep-alive\n\n")
                self.wfile.flush()
        except OSError:
            return

    def single_sign_on(self):
        if not store.settings["oidc_enabled"]:
            self.send_error(404)
            return
        try:
            target, state = sso.begin(callback_url(self.headers.get("Host", "localhost")))
        except (OSError, ValueError, KeyError):
            self.reply(login_page("The sign-in provider is not answering."))
            return
        self.send_response(303)
        self.send_header("Set-Cookie", f"mikrokat_sso={state}; Path=/auth; HttpOnly; SameSite=Lax; Max-Age={sso.PENDING_SECONDS}")
        self.send_header("Location", target)
        self.end_headers()

    def single_sign_on_done(self, query):
        code, state = query.get("code", [""])[0], query.get("state", [""])[0]
        cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", "")).get("mikrokat_sso")
        if not code or not cookie or not hmac.compare_digest(cookie.value, state):
            self.reply(login_page("This sign-in could not be completed. Please try again."))
            return
        try:
            name = sso.finish(code, state, callback_url(self.headers.get("Host", "localhost")))
        except sso.SignInError as refusal:
            self.reply(login_page(str(refusal)))
            return
        except (OSError, ValueError, KeyError, IndexError):
            self.reply(login_page("The sign-in provider gave an unexpected answer."))
            return
        store.activity_add("system", f"{name} signed in")
        self.send_response(303)
        self.send_header("Set-Cookie", f"{SESSION_COOKIE}={new_session()}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_HOURS * 3600}")
        self.send_header("Location", "/")
        self.end_headers()

    def redirect(self, path, code):
        self.send_response(303)
        self.send_header("Location", f"{path}?ok={code}")
        self.end_headers()

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/login":
            self.reply(login_page())
            return
        if url.path == "/auth/login":
            self.single_sign_on()
            return
        if url.path == "/auth/callback":
            self.single_sign_on_done(urllib.parse.parse_qs(url.query))
            return
        if not self.authorized():
            return
        if url.path == "/live/stream":
            self.stream()
            return
        if url.path in ("/host", "/explain"):
            value = urllib.parse.parse_qs(url.query)
            host = self.headers.get("Host", "localhost")
            self.reply(host_page(host, value.get("ip", [""])[0]) if url.path == "/host" else explain_page(host, value.get("sid", [""])[0]))
            return
        page = PAGES.get(url.path)
        if not page:
            self.send_error(404)
            return
        query = urllib.parse.parse_qs(url.query)
        code = query.get("ok", [""])[0]
        host = self.headers.get("Host", "localhost")
        if page is settings_page:
            self.reply(settings_page(host, NOTICES.get(code, ""), "", query.get("tab", [""])[0]))
        else:
            self.reply(page(host, NOTICES.get(code, "")))

    def do_POST(self):
        length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
        form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(length).decode(errors="replace"), keep_blank_values=True).items()}
        if self.path == "/login":
            if form.get("username", "").strip().lower() == "admin" and store.check_password(form.get("password", "")):
                self.send_response(303)
                self.send_header("Set-Cookie", f"{SESSION_COOKIE}={new_session()}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_HOURS * 3600}")
                self.send_header("Location", "/")
                self.end_headers()
            else:
                time.sleep(1)
                self.reply(login_page("Wrong user or password."))
            return
        if not self.authorized():
            return
        if not hmac.compare_digest(form.get("token", "").encode(), csrf_token.encode()):
            self.send_error(403)
            return
        if self.path == "/logout":
            cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            sessions.pop(cookie[SESSION_COOKIE].value, None)
            self.send_response(303)
            self.send_header("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; Max-Age=0")
            self.send_header("Location", "/login")
            self.end_headers()
            return
        back = form.get("back") if form.get("back") in PAGES else None
        host = self.headers.get("Host", "localhost")
        if self.path == "/allow":
            error = store.add_allowed(form.get("network", ""), form.get("note", ""))
            done, page = "added", back or "/allowlist"
        elif self.path == "/remove":
            store.remove_allowed(form.get("network", ""))
            error, done, page = None, "removed", "/allowlist"
        elif self.path == "/builtin":
            store.set_builtin(form.get("network", ""), bool(form.get("enabled")))
            error, done, page = None, "saved", "/allowlist"
        elif self.path == "/ignore":
            store.ignore_sid(form.get("sid", ""))
            error, done, page = None, "ignored", back or "/"
        elif self.path == "/rules/disable":
            error = add_disabled(form.get("entry", ""))
            done, page = "pending", "/rules"
        elif self.path == "/rules/enable":
            remove_disabled(form.get("entry", ""))
            error, done, page = None, "pending", "/rules"
        elif self.path == "/rules/local":
            write_conf("local.rules", form.get("text", "").replace("\r\n", "\n").splitlines())
            error, done, page = None, "pending", "/rules"
        elif self.path == "/rules/apply":
            request_rule_update()
            error, done, page = None, "applying", "/rules"
        elif self.path == "/settings":
            error = store.save_settings(form)
            actions.reset()
            actions.reset_copy()
            done, page = "saved", "/settings"
        elif self.path == "/block":
            error = manual_block(form)
            done, page = "blocked", back or "/blocked"
        elif self.path == "/unblock":
            error = unblock(form)
            done, page = "unblocked", "/blocked"
        elif self.path == "/unblock-allow":
            error = unblock(form) or store.add_allowed(form.get("address", ""), "Unblocked by hand")
            done, page = "unblocked-allowed", "/blocked"
        elif self.path in ("/test/router", "/test/telegram", "/test/email", "/test/webhook", "/test/syslog", "/test/digest"):
            # The test buttons sit inside the settings form: save what is on screen, then try it.
            tab = form.get("tab", "")
            failure = store.save_settings(form)
            actions.reset()
            if failure:
                self.reply(settings_page(host, "", failure, tab))
            elif self.path == "/test/router":
                self.reply(settings_page(host, *test_router(), tab))
            elif self.path == "/test/digest":
                actions.notify(health.digest_text())
                self.reply(settings_page(host, "Summary queued for the channels that are on.", "", tab))
            elif self.path == "/test/syslog":
                failure = actions.send_syslog({"event_type": "test", "text": "Test event from the Mikrokat settings page."})
                self.reply(settings_page(host, "" if failure else "Test event sent.", failure or "", tab))
            else:
                send = actions.CHANNELS[self.path.rsplit("/", 1)[1]][1]
                failure = send("Test message from the Mikrokat settings page.")
                self.reply(settings_page(host, "" if failure else "Test message sent.", failure or "", tab))
            return
        else:
            self.send_error(404)
            return
        if error and self.path == "/settings":
            self.reply(settings_page(host, "", error, form.get("tab", "")))
        elif error:
            self.reply(PAGES[page](host, "", error))
        elif self.path == "/settings":
            store.activity_add("system", "Saved the settings")
            self.send_response(303)
            self.send_header("Location", f"/settings?ok=saved&tab={urllib.parse.quote(form.get('tab', ''))}")
            self.end_headers()
        else:
            what = {"/allow": f"Allowed {form.get('network', '')}", "/remove": f"Removed {form.get('network', '')} from the allowlist",
                    "/ignore": f"Muted rule {form.get('sid', '')}", "/builtin": f"Changed the built-in entry {form.get('network', '')}", "/rules/disable": f"Turned off {form.get('entry', '')}", "/rules/enable": f"Turned on {form.get('entry', '')}",
                    "/rules/local": "Saved your rules", "/rules/apply": "Asked for a rule update", "/settings": "Saved the settings",
                    "/block": f"Blocked {form.get('address', '')} by hand", "/unblock": f"Unblocked {form.get('address', '')}", "/unblock-allow": f"Unblocked and allowed {form.get('address', '')}"}
            store.activity_add("system", what.get(self.path, self.path))
            self.redirect(page, done)


class EventsProxy(BaseHTTPRequestHandler):
    """Put the Mikrokat login in front of EveBox, which only listens on the internal network."""

    def log_message(self, *args):
        pass

    def forward(self):
        if not session_from(self.headers):
            host = self.headers.get("Host", "localhost").split(":")[0]
            self.send_response(303)
            self.send_header("Location", f"http://{host}:{WEB_PORT}/login")
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_HEADERS and k.lower() not in ("host", "cookie")}
        upstream = http.client.HTTPConnection(EVEBOX_UPSTREAM, timeout=60)
        try:
            upstream.request(self.command, self.path, body=body, headers=headers)
            response = upstream.getresponse()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in HOP_HEADERS:
                    self.send_header(key, value)
            self.end_headers()
            while chunk := response.read(65536):
                self.wfile.write(chunk)
        except OSError:
            self.send_error(502, "EveBox is not answering")
        finally:
            upstream.close()

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = forward


def serve(port, handler):
    server = ThreadingHTTPServer(("0.0.0.0", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def start():
    if not store.has_password():
        print("[mikrokat] web pages off: set WEB_PASSWORD to turn them on", flush=True)
        return
    serve(WEB_PORT, Handler)
    serve(EVENTS_PORT, EventsProxy)
    print(f"[mikrokat] web pages on port {WEB_PORT}, events on port {EVENTS_PORT}", flush=True)
