#!/usr/bin/env python3
"""Mikrokat: follow Suricata's eve log, notify on Telegram and optionally block on a MikroTik router."""
import glob
import json
import os
import threading
import time

import actions
import geo
import health
import store
import web

EVE_GLOB = os.environ.get("EVE_GLOB", "/var/log/suricata/eve-*.json")
LOG_LIMIT_BYTES = int(float(os.environ.get("LOG_LIMIT_GB", "4")) * 2**30)
seen = {}


def log(*args):
    print("[mikrokat]", *args, flush=True)


def pick_target(event):
    """Return (ip to act on, service port, outbound), or None if both sides are on the allowlist.

    Outbound means the allowlisted side started the flow, so the internal host deserves a look too.
    """
    src, dest = event.get("src_ip", ""), event.get("dest_ip", "")
    if store.allowed(src):
        return None if store.allowed(dest) else (dest, event.get("dest_port"), True)
    return src, event.get("dest_port"), False


def describe(event, target, outbound, action):
    alert = event["alert"]
    direction = "outbound, check the internal host" if outbound else "inbound"
    return (f"{action}: {target}\n"
            f"From: {event.get('src_ip')}:{event.get('src_port')}\n"
            f"To: {event.get('dest_ip')}:{event.get('dest_port')}\n"
            f"Direction: {direction}\n"
            f"Severity: {alert.get('severity')}\n"
            f"Rule: [{alert.get('gid')}:{alert.get('signature_id')}] {alert.get('signature')}")


def handle(event):
    alert = event.get("alert") or {}
    settings = store.settings
    target = pick_target(event)
    country = geo.country(target[0]) if target else ""
    store.count_alert(event, target[0] if target else None, country)
    store.activity_add("alert", str(alert.get("signature", "")), severity=alert.get("severity"), sid=alert.get("signature_id"),
                       source=event.get("src_ip"), destination=event.get("dest_ip"), country=country, remote=target[0] if target else "",
                       source_name=store.name_of(event.get("src_ip")), destination_name=store.name_of(event.get("dest_ip")))
    if str(alert.get("severity")) not in settings["severities"] or str(alert.get("signature_id")) in settings["ignore_sids"]:
        return
    if target is None:
        return
    ip, port, outbound = target
    now = time.time()
    key = (ip, alert.get("signature_id"))
    if now - seen.get(key, 0) < settings["dedupe_seconds"]:
        return
    seen[key] = now
    if len(seen) > 10000:
        for k in [k for k, t in seen.items() if now - t >= settings["dedupe_seconds"]]:
            del seen[k]
    if settings["mode"] == "block" and ":" in ip and not settings["block_ipv6"]:
        action = "Not blocked, IPv6 blocking is off:"
    elif settings["mode"] == "block":
        comment = f"[{alert.get('gid')}:{alert.get('signature_id')}] {alert.get('signature')} port {port}"
        timeout = store.block_time_for(ip)
        if actions.block(ip, comment, timeout):
            store.note_strike(ip)
            action = f"Blocked for {timeout}"
        else:
            action = "BLOCK FAILED"
    else:
        action = "Would block"
    text = describe(event, ip, outbound, action)
    log(text.replace("\n", " | "))
    store.record_action(ip, alert, action, outbound)
    actions.export_alert(event, ip, action, outbound, geo.country(ip))
    store.activity_add("action", f"{action} {ip}", address=ip, sid=alert.get("signature_id"), rule=str(alert.get("signature", "")), country=geo.country(ip))
    actions.notify(text)


def watch_router():
    """Keep the block list and host names fresh, and put the blocks back if the router restarted."""
    turn = 0
    while True:
        if store.router_ready():
            try:
                if turn % 10 == 0:
                    actions.refresh_names()
                turn += 1
                actions.refresh_blocked()
                restored = actions.restore_after_restart()
                if restored:
                    log(f"router restarted, restored {restored} blocks")
                    store.activity_add("system", f"The router restarted. Restored {restored} blocks.")
                    actions.refresh_blocked()
            except Exception as error:
                log("router check failed:", error.__class__.__name__)
        time.sleep(30)


def newest():
    files = glob.glob(EVE_GLOB)
    return max(files, key=os.path.getmtime) if files else None


def clean_old():
    limit = time.time() - store.settings["retention_days"] * 86400
    current = newest()
    # Oldest first: remove what is past its days, then keep removing until the total fits the size limit.
    files = sorted(glob.glob(EVE_GLOB), key=os.path.getmtime)
    total = sum(os.path.getsize(path) for path in files)
    for path in files:
        if path != current and (os.path.getmtime(path) < limit or total > LOG_LIMIT_BYTES):
            total -= os.path.getsize(path)
            os.remove(path)
            log("removed old log", path)


def follow():
    """Yield eve records, moving to the next file when Suricata rotates."""
    path, source, partial = None, None, ""
    while True:
        current = newest()
        if current != path and current:
            if source:
                source.close()
            first = path is None
            path, source = current, open(current, encoding="utf-8", errors="replace")
            if first:
                source.seek(0, os.SEEK_END)
            log("following", path)
        chunk = source.readline() if source else ""
        if not chunk:
            yield None
            continue
        partial += chunk
        if partial.endswith("\n"):
            line, partial = partial, ""
            try:
                yield json.loads(line)
            except ValueError:
                continue


def main():
    store.load()
    geo.start()
    web.start()
    threading.Thread(target=watch_router, daemon=True).start()
    actions.start_delivery()
    health.start()
    log(f"mode={store.settings['mode']} severities={store.settings['severities']} channels={[n for n, (on, _) in actions.CHANNELS.items() if store.settings[on]]}")
    last_flush = last_clean = 0
    for record in follow():
        now = time.time()
        if now - last_flush > 5:
            store.flush()
            last_flush = now
        if record is None:
            time.sleep(0.5)
            if now - last_clean > 3600:
                clean_old()
                store.prune()
                last_clean = now
        elif record.get("event_type") == "alert":
            handle(record)


if __name__ == "__main__":
    main()
