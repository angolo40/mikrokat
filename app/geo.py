"""Country lookup from a local database, so no address ever leaves this box."""
import gzip
import os
import shutil
import threading
import time
import urllib.request

import maxminddb

import store

GEOIP_FILE = os.environ.get("GEOIP_FILE", os.path.join(store.DATA_DIR, "country.mmdb"))
GEOIP_URL = os.environ.get("GEOIP_URL", "https://download.db-ip.com/free/dbip-country-lite-{month}.mmdb.gz")
MAX_AGE_DAYS = 35
reader = None
cache = {}


def open_database():
    global reader
    try:
        reader = maxminddb.open_database(GEOIP_FILE)
        cache.clear()
    except (OSError, maxminddb.InvalidDatabaseError):
        reader = None


def country(ip):
    """Return the two-letter country code of an address, or an empty string."""
    if not reader or not ip:
        return ""
    if ip not in cache:
        if len(cache) > 20000:
            cache.clear()
        try:
            record = reader.get(ip) or {}
        except ValueError:
            record = {}
        cache[ip] = (record.get("country") or {}).get("iso_code", "")
    return cache[ip]


def download():
    """Fetch the free monthly database. The current month may not be out yet, so try the last one too."""
    now = time.time()
    for month in (time.strftime("%Y-%m", time.localtime(now)), time.strftime("%Y-%m", time.localtime(now - 32 * 86400))):
        temp = GEOIP_FILE + ".tmp"
        try:
            request = urllib.request.Request(GEOIP_URL.format(month=month), headers={"User-Agent": "Mozilla/5.0 (Mikrokat)"})
            with urllib.request.urlopen(request, timeout=60) as source, gzip.open(source) as data, open(temp, "wb") as target:
                shutil.copyfileobj(data, target)
            maxminddb.open_database(temp).close()
            os.replace(temp, GEOIP_FILE)
            return True
        except (OSError, EOFError, maxminddb.InvalidDatabaseError) as error:
            print(f"[mikrokat] country database {month}: {error.__class__.__name__} {str(error)[:80]}", flush=True)
            if os.path.exists(temp):
                os.remove(temp)
    return False


def keep_fresh():
    while True:
        stale = not os.path.exists(GEOIP_FILE) or time.time() - os.path.getmtime(GEOIP_FILE) > MAX_AGE_DAYS * 86400
        if stale and download():
            print("[mikrokat] country database updated", flush=True)
            open_database()
        time.sleep(86400)


def start():
    open_database()
    threading.Thread(target=keep_fresh, daemon=True).start()
