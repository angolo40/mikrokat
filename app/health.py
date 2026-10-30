"""Background checks: a detector that stops working must not stay silent."""
import glob
import os
import shutil
import threading
import time

import actions
import store
import web

RULES_FILE = "/var/lib/suricata/rules/suricata.rules"
RULES_MAX_AGE_DAYS = 8
DISK_LIMIT = 0.90


def check():
    """Return {key: message} for everything that is wrong right now."""
    found = {}
    counters = web.suricata("dump-counters")
    if not isinstance(counters, dict):
        return {"suricata": "Suricata is not answering."}
    packets = (counters.get("capture") or {}).get("kernel_packets", 0)
    now = time.time()
    if packets != state["packets"]:
        state.update(packets=packets, changed=now)
    idle = now - state["changed"]
    if idle > store.settings["health_minutes"] * 60:
        found["traffic"] = f"No traffic has reached Suricata for {int(idle // 60)} minutes. Check the router rules and this host."
    if os.path.exists(RULES_FILE) and now - os.path.getmtime(RULES_FILE) > RULES_MAX_AGE_DAYS * 86400:
        found["rules"] = f"The rules are more than {RULES_MAX_AGE_DAYS} days old. Press Apply rules or turn on automatic updates."
    disk = shutil.disk_usage(store.DATA_DIR)
    if disk.used / disk.total > DISK_LIMIT:
        found["disk"] = f"The disk is {disk.used * 100 // disk.total}% full."
    if store.router_ready() and actions.copy_failed:
        found["router"] = "The router is not answering."
    return found


def report(found):
    for key in found.keys() - store.problems.keys():
        store.activity_add("error", found[key])
        actions.notify(f"Problem: {found[key]}")
    for key in store.problems.keys() - found.keys():
        store.activity_add("system", f"Solved: {store.problems[key]}")
        actions.notify(f"Solved: {store.problems[key]}")
    store.problems.clear()
    store.problems.update(found)


def due(hour, stamp_key, weekly=False):
    """True once per day, or per week, from the given hour on."""
    now = time.localtime()
    period = time.strftime("%G-%V" if weekly else "%Y-%m-%d", now)
    if now.tm_hour < hour or store.schedule.get(stamp_key) == period:
        return False
    store.mark_schedule(stamp_key, period)
    return True


def digest_text():
    series = store.hourly_series()
    important, info = sum(int(r[1]) for r in series), sum(int(r[2]) for r in series)
    lines = [f"Last 24 hours: {important} important alerts, {info} informational.",
             f"{'Blocked' if store.settings['mode'] == 'block' else 'Would block'}: {store.actions_today()}. On the block list now: {len(store.active_blocks())}."]
    countries = [web.WORLD.get(c, [c])[0] for c, _ in store.countries_today()[:3]]
    if countries:
        lines.append("Mostly from: " + ", ".join(countries) + ".")
    rules = [f"{r[2]} ({int(r[3])})" for r in store.top_rules(3) if r[1] <= 2]
    if rules:
        lines.append("Top rules: " + "; ".join(rules) + ".")
    lines.append("Problems: " + " ".join(store.problems.values()) if store.problems else "Everything is working.")
    return "\n".join(lines)


def loop():
    while True:
        time.sleep(60)
        try:
            report(check())
            s = store.settings
            if s["rules_auto"] != "off" and due(int(s["rules_hour"]), "rules", s["rules_auto"] == "weekly"):
                web.request_rule_update()
                store.activity_add("system", "Started the scheduled rule update")
            if s["digest_enabled"] and due(int(s["digest_hour"]), "digest"):
                actions.notify(digest_text())
        except Exception as error:
            print("[mikrokat] health check failed:", error.__class__.__name__, str(error)[:100], flush=True)


state = {"packets": -1, "changed": time.time()}


def start():
    threading.Thread(target=loop, daemon=True).start()
