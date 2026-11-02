#!/bin/bash
# End-to-end test of HTTPS inspection, for a disposable host with the stack running.
# Run it as root. It recreates tlsproxy, restarts mikrokat and applies the rules, and it leaves the
# feature off and its own rules and CA gone, also when a check fails. It is safe to run again.
# It needs python3, curl, openssl and iproute2 on the host.
#
#   tests/e2e/run.sh           runs the checks and prints PASS, or the check that failed
#   tests/e2e/run.sh measure   prints RAM, CPU, throughput and frame numbers
set -u
cd "$(dirname "$0")/../.." || exit 1

SERVER=198.51.100.7
SOCKS=127.0.0.1:1080
APP=http://127.0.0.1:8088
TEST_CA="Mikrokat E2E test CA"
OWN_ROOT="Mikrokat E2E own root"
OWN_CA="Mikrokat E2E own CA"
ALARM="HTTPS inspection has stopped"
PORT_ALARM="The HTTPS inspection port is closed"
COOKIE=e2e-cookie-value
POST_BODY=e2e-body-value
URL_TOKEN=e2e-url-token
BURST=$((2**20))
FETCHES=200
SUSTAINED=$((2**30))
SETTLE=14 # dump-counters lagged by 10.6 seconds at most, and stats.json is written every 10
COMPOSE=(docker compose -f docker-compose.yml -f tests/e2e/docker-compose.e2e.yml)
# HTTPS inspection is a compose profile. The suite turns it on for itself, here and, through the override file, for the app.
export COMPOSE_PROFILES=https

export E2E_WORK=
E2E_SHOTS=${E2E_SHOTS:-}
CHECK=Setup
RESULT="FAIL: stopped early"
SERVER_PID=
HOLDER_PID=
BANK_PID=

check() {
  CHECK=$1
  echo "== $1"
}

fail() {
  RESULT="FAIL: $CHECK: $1"
  exit 1
}

# wait_for <seconds> <command...>: true as soon as the command succeeds.
wait_for() {
  local tries=$(($1 * 5))
  shift
  until "$@"; do
    tries=$((tries - 1))
    [ "$tries" -gt 0 ] || return 1
    sleep 0.2
  done
}

# Prints the value at a dotted path of the JSON on stdin, as JSON, or 0 when it is missing.
json_get() {
  python3 -c 'import json, sys
value = json.load(sys.stdin)
for key in sys.argv[1].split("."):
    value = value.get(key, 0) if isinstance(value, dict) else 0
print(json.dumps(value))' "$1"
}

counter() {
  json_get "$1" <data/tls/state/stats.json
}

counter_above() {
  [ "$(counter "$1")" -gt "$2" ]
}

# feature on|off|remove: on and off go through the settings file, the only way that also sets
# tls_enabled for the health check. Remove drops the keys, so the defaults apply again.
feature() {
  python3 - "$1" <<'EOF'
import json
import os
import sys

path, mode = "data/app/settings.json", sys.argv[1]
try:
    with open(path, encoding="utf-8") as source:
        settings = json.load(source)
except FileNotFoundError:
    settings = {}
if mode == "remove":
    for key in ("tls_enabled", "tls_socks", "tls_devices"):
        settings.pop(key, None)
else:
    settings.update(tls_enabled=mode == "on", tls_socks=True, tls_devices=["127.0.0.1"])
with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as target:
    json.dump(settings, target)
EOF
  docker restart -t 2 mikrokat-app </dev/null >/dev/null
}

control_says() {
  grep -q "\"enabled\": $1" data/tls/control/config.json 2>/dev/null
}

port_open() {
  (exec 3<>"/dev/tcp/${SOCKS%:*}/${SOCKS#*:}") 2>/dev/null
}

port_closed() {
  ! port_open
}

# The rules container applies rules/, the same way as the button on the Rules page.
apply_rules() {
  rm -f rules/.update-status
  touch rules/.update-request
  wait_for 300 grep -qsE '^(ok|failed)' rules/.update-status && grep -q '^ok' rules/.update-status
}

remove_rules() {
  sed -i '/sid:900000[123];/d' rules/local.rules
}

sign_in() {
  sed -n 's/^WEB_PASSWORD=//p' .env | tr -d '\n' >"$E2E_WORK/password"
  curl -sS -o /dev/null -c "$E2E_WORK/cookies" --data-urlencode username=admin --data-urlencode "password@$E2E_WORK/password" "$APP/login"
  rm -f "$E2E_WORK/password"
  grep -q mikrokat "$E2E_WORK/cookies" || fail "cannot sign in with WEB_PASSWORD from .env"
}

# through_proxy <name> <curl arguments...>: curl with the name pinned to the test server.
through_proxy() {
  local name=$1
  shift
  curl -sS --max-time 60 --socks5 "$SOCKS" --resolve "$name:443:$SERVER" "$@"
}

events() {
  cat data/logs/eve-*.json 2>/dev/null | tail -c +$((EVE_MARK + 1))
}

alerts() {
  events | grep "\"signature_id\":$1,"
}

alert_seen() {
  alerts "$1" >/dev/null
}

post_seen() {
  events | grep '"event_type":"http"' | grep -q '"url":"/mikrokat-e2e-post"'
}

badge_shown() {
  curl -s --max-time 2 -b "$E2E_WORK/cookies" "$APP/live/stream" | grep '"sid": 9000001' | grep -q '"decrypted": true'
}

# written <record> <text>: the text is in an alert, or an http event, about the redirect request.
written() {
  case $1 in
    alert) alerts 9000001 ;;
    http) events | grep '"event_type":"http"' ;;
  esac | grep -F "/mikrokat-e2e-redirect?token=$URL_TOKEN" | grep -qF "$2"
}

# alarm_shown <text>: the text is on the Overview page.
alarm_shown() {
  curl -s -b "$E2E_WORK/cookies" "$APP/" | grep -q "$1"
}

app_up() {
  curl -s -o /dev/null "$APP/tls.pac"
}

listening_says() {
  [ "$(counter listening)" = "$1" ]
}

own_says() {
  [ "$(counter ca_own)" = "$1" ]
}

import_error_says() {
  counter ca_import_error | grep -qF "$1"
}

incoming_empty() {
  [ -z "$(ls -A data/tls/incoming 2>/dev/null)" ]
}

tab() {
  curl -s -b "$E2E_WORK/cookies" "$APP/settings?tab=https"
}

form_token() {
  tab | grep -o 'name="token" value="[^"]*"' | head -1 | cut -d'"' -f4
}

# upload_ca <chain> <key>: what the Upload button sends. Prints where the page goes next.
upload_ca() {
  curl -sS -o /dev/null -w '%{redirect_url}' -b "$E2E_WORK/cookies" -F "token=$(form_token)" -F "chain=@$1" -F "key=@$2" "$APP/tls/own-ca"
}

# fetch_signed_by <CA file> <issuer>: a client that trusts only that file gets a leaf from that issuer.
fetch_signed_by() {
  local body
  body=$(through_proxy test.example.net -v --cacert "$1" https://test.example.net/mikrokat-e2e 2>"$E2E_WORK/curl.log")
  [ "$body" = "mikrokat-e2e-ok" ] || fail "no body: $(tail -1 "$E2E_WORK/curl.log")"
  grep -q "issuer: CN=$2" "$E2E_WORK/curl.log" || fail "the leaf is not from $2: $(grep issuer: "$E2E_WORK/curl.log")"
}

# A root that only the test client trusts, and the intermediate the proxy gets.
make_own_ca() {
  (
    cd "$E2E_WORK" || exit 1
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=$OWN_ROOT" \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -keyout own-root.key -out own-root.pem &&
      openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$OWN_CA" -keyout own.key -out own.csr &&
      openssl x509 -req -in own.csr -CA own-root.pem -CAkey own-root.key -CAcreateserial -days 2 \
        -extfile <(printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n') -out own.pem &&
      cat own.pem own-root.pem >own-chain.pem &&
      openssl genpkey -algorithm ed25519 -out other.key
  ) 2>/dev/null || fail "no private CA"
}

# upload_signed <certificate>: what the Upload signed certificate button sends, with no key.
upload_signed() {
  curl -sS -o /dev/null -w '%{redirect_url}' -b "$E2E_WORK/cookies" -F "token=$(form_token)" -F "chain=@$1" "$APP/tls/own-ca"
}

# A request, not a delete: the proxy also puts ca.pem back. What a failed run left waiting goes too.
# A pending key goes as well. Its counters in private stay, or a proxy that starts again would make a new one.
drop_own_ca() {
  rm -f data/tls/incoming/own-ca.* data/tls/private/own-ca-request.key data/tls/state/own-ca.csr 2>/dev/null
  touch data/tls/incoming/remove-own-ca 2>/dev/null
}

# The counters along the path of a copy, from the proxy to Suricata, one name=value per line.
frames() {
  local counters
  counters=$(docker exec mikrokat-suricata suricatasc -c dump-counters </dev/null)
  awk '/^Udp:/ && $2 ~ /^[0-9]+$/ { print "sent=" $5; print "udp_lost=" $4 }' /proc/net/snmp
  echo "tzsp=$(cat /sys/class/net/tzsp0/statistics/rx_packets)"
  echo "suricata=$(json_get message.capture.kernel_packets <<<"$counters")"
  echo "suricata_lost=$(json_get message.capture.kernel_drops <<<"$counters")"
  echo "suricata_bytes=$(json_get message.decoder.bytes <<<"$counters")"
  echo "gaps=$(json_get message.tcp.reassembly_gap <<<"$counters")"
  echo "copied=$(counter copied_bytes)"
  echo "dropped=$(counter copies_dropped)"
}

# counted <command...>: runs it, then sets one delta_<name> for each line of frames, and mbps for the
# speed of the whole run in $1 of the bytes it fetches. Both readings wait, or earlier traffic that
# has not reached the counters yet would be charged to this run.
counted() {
  local before after started bytes=$1
  shift
  sleep "$SETTLE"
  before=$(frames)
  started=$EPOCHREALTIME
  "$@" || fail "the download failed"
  mbps=$(awk -v n="$bytes" -v a="$started" -v b="$EPOCHREALTIME" 'BEGIN { printf "%.0f", n * 8 / (b - a) / 1000000 }')
  sleep "$SETTLE"
  after=$(frames)
  eval "$(printf '%s\n%s\n' "$before" "$after" | awk -F= '$1 in first { print "delta_" $1 "=" $2 - first[$1]; next } { first[$1] = $2 }')"
}

burst() {
  through_proxy test.example.net --cacert "$E2E_WORK/ca.pem" -o /dev/null "https://test.example.net/bytes/$BURST"
}

# Copies arrive faster than they can be paced out, so the emitter queue fills.
full_queue() {
  through_proxy test.example.net -Z --parallel-max 100 --cacert "$E2E_WORK/ca.pem" "https://test.example.net/bytes/$BURST/[1-$FETCHES]" >/dev/null
}

proxy_pid() {
  docker inspect -f '{{.State.Pid}}' mikrokat-tlsproxy </dev/null
}

ram() {
  docker stats --no-stream --format '{{.MemUsage}}' mikrokat-tlsproxy </dev/null
}

# The most RAM the proxy has used since it started, in MB.
peak_mb() {
  awk '/VmHWM/ { printf "%d", $2 * 1024 / 1000000 }' "/proc/$(proxy_pid)/status"
}

measure() {
  check "Measure"
  sleep 15
  echo "RAM off: $(ram), peak $(peak_mb) MB"
  feature on
  wait_for 30 port_open || fail "port 1080 did not open"
  cp data/tls/state/ca.pem "$E2E_WORK/ca.pem"
  sleep 3

  counted "$BURST" burst
  echo "Burst of $BURST bytes: frames sent $delta_sent, seen by tzsp $delta_tzsp, seen by Suricata $delta_suricata"
  echo "Lost: socket $delta_udp_lost, Suricata ring $delta_suricata_lost. Gaps: $delta_gaps. copies_dropped: $delta_dropped"
  # 54 bytes of headers per frame: Suricata does not count the VLAN tag.
  echo "Bytes: copied $delta_copied, seen by Suricata $((delta_suricata_bytes - 54 * delta_suricata))"
  alert_seen 9000002 && echo "Tail rule: fired" || echo "Tail rule: did not fire"

  local name=test.example.net url="https://test.example.net/bytes/$SUSTAINED" pid ticks speed
  speed=$(curl -sS --max-time 120 --resolve "$name:443:$SERVER" --cacert "$E2E_WORK/test-ca.pem" -o /dev/null -w '%{speed_download}' "$url")
  echo "Direct, no proxy: $(awk -v b="$speed" 'BEGIN { printf "%.0f", b * 8 / 1000000 }') Mbps"

  pid=$(proxy_pid)
  ticks=$(awk '{ print $14 + $15 }' "/proc/$pid/stat")
  local started=$EPOCHREALTIME
  (while sleep 1; do ram; done >"$E2E_WORK/ram") &
  local sampler=$!
  speed=$(through_proxy "$name" --max-time 120 --cacert "$E2E_WORK/ca.pem" -o /dev/null -w '%{speed_download}' "$url") || fail "the download failed"
  local ended=$EPOCHREALTIME
  kill "$sampler" 2>/dev/null
  wait "$sampler" 2>/dev/null
  ticks=$(($(awk '{ print $14 + $15 }' "/proc/$pid/stat") - ticks))
  sleep 11
  echo "Sustained $SUSTAINED bytes: $(awk -v b="$speed" 'BEGIN { printf "%.0f", b * 8 / 1000000 }') Mbps"
  echo "CPU of the proxy: $(awk -v t="$ticks" -v a="$started" -v b="$ended" 'BEGIN { printf "%.0f", t / (b - a) }')% of one core, over $(awk -v a="$started" -v b="$ended" 'BEGIN { printf "%.1f", b - a }') s"
  echo "RAM on: $(sort -k1 -h "$E2E_WORK/ram" | tail -1) at the highest sample, peak $(peak_mb) MB, $(ram) after"
  echo "copies_dropped: $(counter copies_dropped)"

  counted $((FETCHES * BURST)) full_queue
  echo "Full queue: $mbps Mbps, peak $(peak_mb) MB, $(ram) after. Frames sent $delta_sent, seen by tzsp $delta_tzsp, lost $delta_udp_lost, copies_dropped $delta_dropped"
}

# The request flow through the real routes: the proxy makes the key, the owner signs outside, the certificate
# arrives alone. A client that trusts only the root must then verify the leaves.
own_ca_request() {
  check "Own CA request"
  make_own_ca
  local next name="Mikrokat E2E request CA" page work="$E2E_WORK/request"
  mkdir -p "$work"
  page=$(tab)
  grep -q 'name="ca_request_name" form="own-ca-request"' <<<"$page" || fail "no name field for a request"
  # The app refuses it itself while the stats say nothing is pending, and writes nothing.
  curl -sS -b "$E2E_WORK/cookies" -F "token=$(form_token)" -F "chain=@$E2E_WORK/own-chain.pem" "$APP/tls/own-ca" | grep -q "No request is pending. Create a request, or upload the key too." || fail "a certificate with no request was not refused by the page"
  incoming_empty || fail "data/tls/incoming still holds $(ls -A data/tls/incoming)"
  next=$(curl -sS -o /dev/null -w '%{redirect_url}' -b "$E2E_WORK/cookies" --data-urlencode "token=$(form_token)" --data-urlencode "ca_request_name=$name" "$APP/tls/own-ca/request")
  [ "$next" = "$APP/settings?ok=ca-requested&tab=https" ] || fail "the request went to '$next'"
  wait_for 15 request_pending || fail "the proxy made no request"
  [ "$(stat -c %a data/tls/private/own-ca-request.key)" = 600 ] || fail "the pending key has mode $(stat -c %a data/tls/private/own-ca-request.key)"
  [ "$(counter ca_request_name)" = "\"$name\"" ] || fail "ca_request_name is $(counter ca_request_name)"
  curl -sf -b "$E2E_WORK/cookies" -o "$work/mikrokat-ca.csr" "$APP/tls/own-ca.csr" || fail "no request to download"
  curl -sf -b "$E2E_WORK/cookies" -o "$work/mikrokat-ca.ext" "$APP/tls/own-ca.ext" || fail "no extensions to download"
  curl -s -o /dev/null -w '%{http_code}' "$APP/tls/own-ca.csr" | grep -q 303 || fail "the request download needs no login"
  grep -q "openssl x509 -req -in mikrokat-ca.csr -CA root.crt -CAkey root.key -CAcreateserial -days 365 -sha256 -extfile mikrokat-ca.ext -out mikrokat-ca.pem" <(tab) || fail "the tab shows no signing command"
  cp "$E2E_WORK/own-root.pem" "$work/root.crt"
  cp "$E2E_WORK/own-root.key" "$work/root.key"
  (cd "$work" && openssl x509 -req -in mikrokat-ca.csr -CA root.crt -CAkey root.key -CAcreateserial -days 365 -sha256 -extfile mikrokat-ca.ext -out mikrokat-ca.pem) 2>/dev/null || fail "openssl could not sign the request"
  cat "$work/mikrokat-ca.pem" "$work/root.crt" >"$work/chain.pem"
  # A certificate for some other key is refused, and the pending key stays.
  next=$(upload_signed "$E2E_WORK/own-chain.pem")
  wait_for 15 import_error_says "not signed for the pending request" || fail "another certificate: '$(counter ca_import_error)'"
  request_pending || fail "the pending key went with a refused certificate"
  next=$(upload_signed "$work/chain.pem")
  [ "$next" = "$APP/settings?ok=ca-uploaded&tab=https" ] || fail "the upload went to '$next'"
  wait_for 15 own_says true || fail "the proxy did not take it: $(counter ca_import_error)"
  wait_for 15 request_gone || fail "the request stayed"
  incoming_empty || fail "data/tls/incoming still holds $(ls -A data/tls/incoming)"
  [ "$(counter ca_import_error)" = '""' ] || fail "an error stayed: $(counter ca_import_error)"
  fetch_signed_by "$work/root.crt" "$name"
  [ "$(counter ca_chain)" = 2 ] || fail "ca_chain is $(counter ca_chain)"
  [ ! -e data/tls/private/own-ca-request.key ] && [ ! -e data/tls/state/own-ca.csr ] || fail "the pending files stayed"
  grep -rl "PRIVATE KEY" data/tls/state >"$E2E_WORK/found" 2>/dev/null
  [ ! -s "$E2E_WORK/found" ] || fail "a private key is in $(tr '\n' ' ' <"$E2E_WORK/found")"
  docker logs mikrokat-tlsproxy 2>&1 </dev/null | grep -qF "PRIVATE KEY" && fail "the proxy logged a key"
  # Cancel: a new request, then it is dropped.
  curl -sS -o /dev/null -b "$E2E_WORK/cookies" --data-urlencode "token=$(form_token)" --data-urlencode "ca_request_name=$name" "$APP/tls/own-ca/request"
  wait_for 15 request_pending || fail "no second request"
  next=$(curl -sS -o /dev/null -w '%{redirect_url}' -b "$E2E_WORK/cookies" --data-urlencode "token=$(form_token)" "$APP/tls/own-ca/request/cancel")
  [ "$next" = "$APP/settings?ok=ca-request-cancelled&tab=https" ] || fail "cancel went to '$next'"
  wait_for 15 request_gone || fail "the request was not cancelled"
  [ ! -e data/tls/private/own-ca-request.key ] && [ ! -e data/tls/state/own-ca.csr ] || fail "the pending files stayed after cancel"
  next=$(curl -sS -o /dev/null -w '%{redirect_url}' -b "$E2E_WORK/cookies" --data-urlencode "token=$(form_token)" "$APP/tls/own-ca/remove")
  wait_for 15 own_says false || fail "ca_own stayed true"
  fetch_signed_by "$E2E_WORK/ca.pem" "Mikrokat local CA"
}

request_pending() {
  [ "$(counter ca_request_pending)" = True ] || [ "$(counter ca_request_pending)" = true ]
}

request_gone() {
  ! request_pending
}

# The real Chromium run of tests/e2e/browser.mjs, in the Playwright image. Playwright is installed by npm
# inside that container, into a folder of this run, and enters nothing the project ships.
BROWSER_IMAGE=${BROWSER_IMAGE:-mcr.microsoft.com/playwright:v1.56.1-jammy}

have_browser() {
  command -v docker >/dev/null && docker image inspect "$BROWSER_IMAGE" >/dev/null 2>&1 || docker pull -q "$BROWSER_IMAGE" </dev/null >/dev/null 2>&1
}

# browser <phase> [extra docker arguments...]
browser() {
  local phase=$1
  shift
  mkdir -p "$E2E_SHOTS"
  cp tests/e2e/browser.mjs "$E2E_WORK/pw/"
  docker run --rm --network host --ipc=host -e APP -e OUT=/out -e MK_PASSWORD -v "$E2E_WORK/pw:/w" -v "$E2E_SHOTS:/out" "$@" \
    -w /w "$BROWSER_IMAGE" sh -c '[ -d node_modules/playwright ] || { npm init -y >/dev/null && npm i --silent --no-audit --no-fund playwright@1.56.1; }; node browser.mjs '"$phase" </dev/null ||
    fail "the browser check $phase failed, see $E2E_SHOTS/failure-$phase.png"
}

# The Known devices list of a page rendered with 38 names, opened in the browser: the rendered page carries its CSS.
names_fixture() {
  docker exec mikrokat-app python3 -c '
import sys
sys.path.insert(0, "/app")
import store, web
store.settings["tls_enabled"] = True
store.names.update({"10.9.0.%d" % n: "device-%02d" % n for n in range(37)})
store.names["10.9.1.1"] = "Alpha-PC"
sys.stdout.write(web.settings_page("example.lan:8088", tab="https"))
' </dev/null >"$E2E_WORK/pw/names.html"
}

browser_checks() {
  check "Real browser"
  have_browser || { echo "no Docker image for the browser check, skipping it"; return 0; }
  mkdir -p "$E2E_WORK/pw"
  MK_PASSWORD=$(sed -n 's/^WEB_PASSWORD=//p' .env | tr -d '\n')
  export MK_PASSWORD
  browser request
  wait_for 30 port_open || fail "port 1080 did not open after the browser switched it on"
  cp "$E2E_SHOTS/root.crt" "$E2E_WORK/browser-root.pem"
  fetch_signed_by "$E2E_WORK/browser-root.pem" "Mikrokat E2E requested CA"
  grep -rl "PRIVATE KEY" data/tls/state >"$E2E_WORK/found" 2>/dev/null
  [ ! -s "$E2E_WORK/found" ] || fail "a private key is in $(tr '\n' ' ' <"$E2E_WORK/found")"
  browser pair
  wait_for 15 own_says false || fail "ca_own stayed true after Stop"
  names_fixture || fail "no page with many names"
  browser names -e NAMES_HTML=/w/names.html
  browser guide
  rm -f "$E2E_SHOTS"/*.key "$E2E_SHOTS"/*.srl
}

own_ca() {
  check "Own CA"
  make_own_ca
  local next page inspected key_line
  page=$(tab)
  grep -q '<form id="own-ca" method="post" action="/tls/own-ca" enctype="multipart/form-data">' <<<"$page" || fail "no upload form on the tab"
  grep -q 'type="file" name="chain" form="own-ca"' <<<"$page" || fail "no field for the chain"
  grep -q 'type="file" name="key" form="own-ca"' <<<"$page" || fail "no field for the key"
  next=$(upload_ca "$E2E_WORK/own-chain.pem" "$E2E_WORK/own.key")
  [ "$next" = "$APP/settings?ok=ca-uploaded&tab=https" ] || fail "the upload went to '$next'"
  wait_for 15 own_says true || fail "the proxy did not take it: $(counter ca_import_error)"
  incoming_empty || fail "data/tls/incoming still holds $(ls -A data/tls/incoming)"
  [ "$(stat -c %a data/tls/private/own-ca.key)" = 600 ] || fail "own-ca.key has mode $(stat -c %a data/tls/private/own-ca.key)"
  fetch_signed_by "$E2E_WORK/own-root.pem" "$OWN_CA"
  [ "$(counter ca_chain)" = 2 ] || fail "ca_chain is $(counter ca_chain)"
  curl -s -b "$E2E_WORK/cookies" "$APP/tls/ca.pem" | cmp -s - "$E2E_WORK/own-chain.pem" || fail "the download is not the chain"
  page=$(tab)
  grep -q "CN=$OWN_CA" <<<"$page" || fail "the tab does not show the subject"
  grep -q 'formaction="/tls/regenerate"' <<<"$page" && fail "the tab still offers Regenerate"
  grep -q 'formaction="/tls/own-ca/remove"' <<<"$page" || fail "the tab does not offer Stop using my CA"

  check "Broken upload"
  inspected=$(counter inspected)
  upload_ca "$E2E_WORK/own-chain.pem" "$E2E_WORK/other.key" >/dev/null
  wait_for 15 import_error_says "does not match the first certificate" || fail "the reason is '$(counter ca_import_error)'"
  incoming_empty || fail "data/tls/incoming still holds $(ls -A data/tls/incoming)"
  tab | grep -q "does not match the first certificate" || fail "the tab does not show the reason"
  own_says true || fail "the CA in use changed"
  fetch_signed_by "$E2E_WORK/own-root.pem" "$OWN_CA"
  wait_for 15 counter_above inspected "$inspected" || fail "inspected did not grow"

  check "Stop using my CA"
  next=$(curl -sS -o /dev/null -w '%{redirect_url}' -b "$E2E_WORK/cookies" --data-urlencode "token=$(form_token)" "$APP/tls/own-ca/remove")
  [ "$next" = "$APP/settings?ok=ca-removed&tab=https" ] || fail "the button went to '$next'"
  wait_for 15 own_says false || fail "ca_own stayed true"
  incoming_empty || fail "data/tls/incoming still holds $(ls -A data/tls/incoming)"
  [ ! -e data/tls/private/own-ca.key ] && [ ! -e data/tls/private/own-ca.pem ] || fail "the own files stayed"
  cmp -s data/tls/state/ca.pem "$E2E_WORK/ca.pem" || fail "this is not the generated CA of before"
  fetch_signed_by "$E2E_WORK/ca.pem" "Mikrokat local CA"
  tab | grep -q 'formaction="/tls/regenerate"' || fail "the tab does not offer Regenerate again"
  # By this point no copy may be left, and no log may ever have held it.
  key_line=$(sed -n 2p "$E2E_WORK/own.key")
  grep -rlF -e "$key_line" data/ >"$E2E_WORK/found"
  [ ! -s "$E2E_WORK/found" ] || fail "the key is still in $(tr '\n' ' ' <"$E2E_WORK/found")"
  docker logs mikrokat-tlsproxy 2>&1 </dev/null | grep -qF -e "$key_line" -e "PRIVATE KEY" && fail "the proxy logged the key"
  docker logs mikrokat-app 2>&1 </dev/null | grep -qF -e "$key_line" -e "PRIVATE KEY" && fail "the app logged the key"
  return 0
}

connections_page_has() {
  curl -s -b "$E2E_WORK/cookies" "$APP/connections" | grep -qE "$1"
}

log_has() {
  grep -qE "$1" data/tls/state/connections.jsonl 2>/dev/null
}

# The traffic of the checks above is in the log and on the Connections page, and the log holds no URL.
bank_list_loaded() {
  [ "$(json_get bank_list_names <data/tls/state/stats.json)" = 1101 ]
}

# bank_switch true|false: sets tls_bank_list in the settings file and waits for the control file to say so.
bank_switch() {
  python3 - "$1" <<'PY'
import json
import os
import sys

path = "data/app/settings.json"
with open(path, encoding="utf-8") as source:
    settings = json.load(source)
settings["tls_bank_list"] = sys.argv[1] == "true"
with open(os.open(path, os.O_WRONLY | os.O_TRUNC, 0o600), "w", encoding="utf-8") as target:
    json.dump(settings, target)
PY
  docker restart -t 2 mikrokat-app </dev/null >/dev/null
  wait_for 30 app_up || fail "the app did not come back"
  sign_in
  wait_for 30 grep -q "\"bank_list\": $1" data/tls/control/config.json || fail "the control file does not say bank_list $1"
}

# The proxy downloads the list from the local server, and skips a name on it for the reason bank_list.
bank_checks() {
  check "Bank list"
  local status=data/tls/state/stats.json before body
  wait_for 60 bank_list_loaded || fail "the proxy did not load the list: names $(json_get bank_list_names <$status), error $(json_get bank_list_error <$status)"
  [ "$(json_get bank_list_error <$status)" = '""' ] || fail "bank_list_error is $(json_get bank_list_error <$status)"
  [ -s data/tls/state/bank-list.txt ] || fail "no copy is stored"
  [ "$(wc -l <data/tls/state/bank-list.txt)" = 1101 ] || fail "the stored copy has $(wc -l <data/tls/state/bank-list.txt) names"
  before=$(counter relayed.bank_list)
  body=$(through_proxy banked.example.net --cacert "$E2E_WORK/test-ca.pem" https://banked.example.net/ 2>&1)
  [ "$body" = "mikrokat-e2e-ok" ] || fail "the bank name was not relayed with its own certificate: $body"
  wait_for 15 counter_above relayed.bank_list "$before" || fail "relayed.bank_list did not grow"
  log_has '"name":"banked.example.net".*"reason":"bank_list"' || fail "no bank_list line in the log"

  bank_switch false
  sleep 3
  body=$(through_proxy banked.example.net --cacert "$E2E_WORK/ca.pem" https://banked.example.net/ 2>&1)
  [ "$body" = "mikrokat-e2e-ok" ] || fail "no answer with the switch off: $body"
  [ "$(counter relayed.bank_list)" = "$((before + 1))" ] || fail "the bank list still applied with the switch off"
  bank_switch true
}

connections_checks() {
  check "Connection log"
  local log=data/tls/state/connections.jsonl
  [ -s "$log" ] || fail "the proxy wrote no $log"
  [ "$(stat -c %a "$log")" = 644 ] || fail "$log has mode $(stat -c %a "$log")"
  log_has '"name":"test.example.net".*"action":"inspected"' || fail "no inspected line for test.example.net"
  log_has '"name":"bad.example.net".*"action":"relayed","reason":"upstream"' || fail "no relayed line, reason upstream, for bad.example.net"
  log_has '"name":"pinned.example.net".*"reason":"auto_bypass"' || fail "no auto_bypass line for pinned.example.net"
  log_has '"action":"refused","reason":"destination"' || fail "no refused line, reason destination"
  log_has '"action":"refused","reason":"not_listed"' || fail "no refused line, reason not_listed"
  log_has '"name":"banked.example.net".*"reason":"bank_list"' || fail "no relayed line, reason bank_list, for banked.example.net"
  # The requests above had these in the path, the query, a header and a body.
  if grep -E "mikrokat-e2e|$URL_TOKEN|$COOKIE|$POST_BODY|GET |POST |Cookie|HTTP/1" "$log" >"$E2E_WORK/found"; then
    fail "the log holds request content: $(head -c 300 "$E2E_WORK/found")"
  fi
  [ "$(json_get log_dropped <data/tls/state/stats.json)" = 0 ] || fail "log_dropped is not 0"

  check "Connections page"
  # The app reads the log every 30 seconds.
  wait_for 90 connections_page_has '<b>[1-9][0-9 ]*</b><span>Connections, 24h' || fail "the page shows no connections after 90 seconds"
  local page
  page=$(curl -s -b "$E2E_WORK/cookies" "$APP/connections")
  for text in test.example.net bad.example.net "The certificate of the site failed the checks" "Skipped automatically after a refusal" \
              "Not on the device list" "Destination not allowed" "Name on the downloaded bank list" banked.example.net "Inspected" 'class="legend"'; do
    grep -qF "$text" <<<"$page" || fail "the page does not show: $text"
  done
  grep -q 'mikrokat-e2e' <<<"$page" && fail "the page shows a path"
  grep -qE '<a href="/connections"( class=on)?>Connections</a>' <<<"$page" || fail "no Connections item in the menu"
  curl -s -o /dev/null -w '%{redirect_url}' "$APP/connections" | grep -q /login || fail "the page needs no login"
  connections_browser
}

connections_browser() {
  have_browser || { echo "no Docker image for the browser check, skipping it"; return 0; }
  mkdir -p "$E2E_WORK/pw"
  MK_PASSWORD=$(sed -n 's/^WEB_PASSWORD=//p' .env | tr -d '\n')
  export MK_PASSWORD
  browser connections
}

checks() {
  check "Sign in"
  sign_in

  check "Fetch through the proxy"
  local inspected body code upstream before
  inspected=$(counter inspected)
  body=$(through_proxy test.example.net -v --cacert "$E2E_WORK/ca.pem" https://test.example.net/mikrokat-e2e 2>"$E2E_WORK/curl.log")
  [ "$body" = "mikrokat-e2e-ok" ] || fail "no body: $(tail -1 "$E2E_WORK/curl.log")"
  grep -q "issuer: CN=Mikrokat local CA" "$E2E_WORK/curl.log" || fail "the leaf is not from our CA"
  wait_for 15 counter_above inspected "$inspected" || fail "inspected did not grow"

  check "Suricata alert"
  wait_for 30 alert_seen 9000001 || fail "no alert with sid 9000001"
  alerts 9000001 | head -1 >"$E2E_WORK/alert.json"
  [ "$(json_get dest_ip <"$E2E_WORK/alert.json")" = "\"$SERVER\"" ] || fail "wrong dest_ip: $(cat "$E2E_WORK/alert.json")"
  [ "$(json_get src_ip <"$E2E_WORK/alert.json")" = '"127.0.0.1"' ] || fail "wrong src_ip: $(cat "$E2E_WORK/alert.json")"
  [ "$(json_get vlan <"$E2E_WORK/alert.json")" = "[3900]" ] || fail "no decrypted marker: $(cat "$E2E_WORK/alert.json")"
  wait_for 15 badge_shown || fail "the live feed does not mark the alert as decrypted"
  wait_for 15 alert_seen 9000003 || fail "no alert on the response"

  check "Wrong name"
  upstream=$(counter relayed.upstream)
  through_proxy bad.example.net --cacert "$E2E_WORK/ca.pem" -o /dev/null https://bad.example.net/ 2>/dev/null
  code=$?
  [ "$code" = 60 ] || fail "curl returned $code, not a certificate failure"
  through_proxy bad.example.net -k -v -o /dev/null https://bad.example.net/ 2>"$E2E_WORK/curl.log"
  grep -q "issuer: CN=$TEST_CA" "$E2E_WORK/curl.log" || fail "the certificate of the real server did not reach the client"
  wait_for 15 counter_above relayed.upstream "$upstream" || fail "relayed.upstream did not grow"

  # A name of its own: the automatic bypass would stop test.example.net from being inspected.
  check "Client without our CA"
  before=$(counter relayed.auto_bypass)
  local try
  for try in first second; do
    through_proxy pinned.example.net --cacert "$E2E_WORK/test-ca.pem" -o /dev/null https://pinned.example.net/ 2>/dev/null
    code=$?
    [ "$code" = 60 ] || fail "the $try try returned $code, not a certificate failure"
    sleep 1
  done
  body=$(through_proxy pinned.example.net --cacert "$E2E_WORK/test-ca.pem" https://pinned.example.net/ 2>&1)
  [ "$body" = "mikrokat-e2e-ok" ] || fail "the third try was not relayed: $body"
  wait_for 15 counter_above relayed.auto_bypass "$before" || fail "relayed.auto_bypass did not grow"
  counter auto_bypass | grep -q '"device": "127.0.0.1", "name": "pinned.example.net"' || fail "auto_bypass does not list the name: $(counter auto_bypass)"

  check "Cookies and bodies stay off the disk"
  through_proxy test.example.net --cacert "$E2E_WORK/ca.pem" -o /dev/null -H "Cookie: $COOKIE" -d "$POST_BODY" https://test.example.net/mikrokat-e2e-post || fail "the POST failed"
  wait_for 30 post_seen || fail "Suricata did not see the POST, so this check proves nothing"
  sleep 5 # let EveBox read it too
  grep -rlF -e "$COOKIE" -e "$POST_BODY" data/ >"$E2E_WORK/found"
  [ ! -s "$E2E_WORK/found" ] || fail "found in $(tr '\n' ' ' <"$E2E_WORK/found")"

  check "URLs are written"
  through_proxy test.example.net --cacert "$E2E_WORK/ca.pem" -o /dev/null -e "https://test.example.net/from?token=$URL_TOKEN" \
    "https://test.example.net/mikrokat-e2e-redirect?token=$URL_TOKEN" || fail "the request failed"
  wait_for 30 written http '"hostname":"test.example.net"' || fail "no http event with the token in the URL"
  wait_for 30 written alert "\"http_refer\":\"https://test.example.net/from?token=$URL_TOKEN\"" || fail "no referrer in the alert"
  written alert '"redirect":"/mikrokat-e2e-target"' || fail "no redirect target in the alert"
  written alert '"payload"' && fail "the alert carries a payload"
  echo "alert fields: $(alerts 9000001 | grep -F "$URL_TOKEN" | head -1 | python3 -c 'import json, sys; print(" ".join(sorted(json.load(sys.stdin)["http"])))')"
  echo "http event fields: $(events | grep '"event_type":"http"' | grep -F "$URL_TOKEN" | head -1 | python3 -c 'import json, sys; print(" ".join(sorted(json.load(sys.stdin)["http"])))')"

  check "Burst of 1 MiB"
  counted "$BURST" burst
  echo "frames sent $delta_sent, seen by tzsp $delta_tzsp, seen by Suricata $delta_suricata, gaps $delta_gaps, copies_dropped $delta_dropped"
  [ "$delta_sent" -gt $((2 * BURST / 1460)) ] || fail "only $delta_sent frames were sent"
  [ "$delta_tzsp" = "$delta_sent" ] || fail "$delta_sent frames sent, but tzsp saw $delta_tzsp"
  [ "$delta_suricata" = "$delta_sent" ] || fail "$delta_sent frames sent, but Suricata saw $delta_suricata"
  [ "$delta_udp_lost" = 0 ] || fail "$delta_udp_lost frames lost on the way to tzsp"
  [ "$delta_suricata_lost" = 0 ] || fail "$delta_suricata_lost frames lost on the way to Suricata"
  [ "$delta_gaps" = 0 ] || fail "$delta_gaps gaps in the stream"
  wait_for 30 alert_seen 9000002 || fail "no alert on the tail of the burst"

  check "Full queue"
  counted $((FETCHES * BURST)) full_queue
  echo "$mbps Mbps, peak $(peak_mb) MB, frames sent $delta_sent, seen by tzsp $delta_tzsp, lost $delta_udp_lost, copies_dropped $delta_dropped"
  [ "$delta_dropped" -gt 0 ] || fail "no copy was dropped, so the queue did not fill and this check proves nothing"
  # A deliberate overload on a host that also runs both ends: 2 of 18 runs lost 36 of 2.1 million
  # frames. Under 0.1% passes. The burst above stays exact.
  [ $((delta_udp_lost * 1000)) -lt "$delta_sent" ] || fail "$delta_udp_lost of $delta_sent frames lost on the way to tzsp"
  # Not the 100 MB of a normal download: this is a full 64 MiB queue and 100 connections at once.
  [ "$(peak_mb)" -lt 120 ] || fail "the proxy used $(peak_mb) MB"

  check "Local destinations"
  # (2) is the SOCKS reply for a refused destination, so a failed lookup does not count.
  curl -sS --max-time 10 --socks5-hostname "$SOCKS" -o /dev/null https://localhost/ 2>"$E2E_WORK/curl.log"
  grep -q "(2)" "$E2E_WORK/curl.log" || fail "localhost was not refused: $(cat "$E2E_WORK/curl.log")"
  local address
  for address in "$(hostname -I | cut -d' ' -f1)" "$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' mikrokat-evebox </dev/null)"; do
    curl -sS --max-time 10 --socks5 "$SOCKS" -o /dev/null "http://$address:5636/" 2>"$E2E_WORK/curl.log"
    grep -q "(2)" "$E2E_WORK/curl.log" || fail "$address was not refused: $(cat "$E2E_WORK/curl.log")"
  done

  check "Private destinations"
  for address in 10.255.255.1 172.31.255.1 192.168.255.1 100.64.255.1 '[fd00::1]'; do
    curl -sS --max-time 10 --socks5 "$SOCKS" -o /dev/null "https://$address/" 2>"$E2E_WORK/curl.log"
    grep -q "(2)" "$E2E_WORK/curl.log" || fail "$address was not refused: $(cat "$E2E_WORK/curl.log")"
  done

  check "Device outside the list"
  address=$(hostname -I | cut -d' ' -f1)
  before=$(counter refused)
  curl -sS --max-time 10 --socks5 "$address:1080" -o /dev/null "https://$SERVER/" 2>/dev/null
  code=$?
  [ "$code" != 0 ] || fail "the connection was served"
  wait_for 15 counter_above refused "$before" || fail "refused did not grow"

  bank_checks
  connections_checks

  own_ca_request
  own_ca

  check "Switching off"
  feature off
  wait_for 30 control_says false || fail "the control file still says on"
  wait_for 3 port_closed || fail "port 1080 still open 3 seconds after the control file changed"

  check "Port taken"
  python3 -m http.server --bind "${SOCKS%:*}" "${SOCKS#*:}" >/dev/null 2>&1 &
  HOLDER_PID=$!
  wait_for 10 port_open || fail "nothing is holding port 1080"
  feature on
  wait_for 30 app_up || fail "the app did not come back"
  sign_in
  local taken=$SECONDS
  wait_for 150 alarm_shown "$PORT_ALARM" || fail "no alarm on the Overview page after 150 seconds"
  echo "alarm after $((SECONDS - taken)) seconds"
  curl -s -b "$E2E_WORK/cookies" "$APP/" | grep -q "address already in use" || fail "the alarm does not give the reason"
  listening_says false || fail "stats.json says the port is open"
  kill "$HOLDER_PID"
  HOLDER_PID=
  wait_for 30 listening_says true || fail "the proxy did not open the port when it came free"

  check "Stopping the proxy"
  feature on
  wait_for 30 port_open || fail "port 1080 did not open again"
  wait_for 30 app_up || fail "the app did not come back"
  sign_in
  docker stop -t 2 mikrokat-tlsproxy </dev/null >/dev/null
  local stopped=$SECONDS
  wait_for 150 alarm_shown "$ALARM" || fail "no alarm on the Overview page after 150 seconds"
  echo "alarm after $((SECONDS - stopped)) seconds"
  curl -s "$APP/tls.pac" | grep -q '; DIRECT"' || fail "/tls.pac does not end in DIRECT: $(curl -s "$APP/tls.pac")"
}

finish() {
  local code=$?
  trap - EXIT
  trap '' INT TERM # a second signal must not leave the host half cleaned
  CHECK="Cleaning up"
  echo "== $CHECK"
  [ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null
  [ -z "$HOLDER_PID" ] || kill "$HOLDER_PID" 2>/dev/null
  [ -z "$BANK_PID" ] || kill "$BANK_PID" 2>/dev/null
  rm -f data/tls/state/bank-list.txt
  ip route del local "$SERVER/32" dev lo 2>/dev/null
  remove_rules
  feature remove
  drop_own_ca
  # Without the override, so the proxy trusts the public roots again and forgets the automatic bypass.
  # As the owner has it: the profile from .env decides whether the proxy exists, and the app drops the test's variable.
  unset COMPOSE_PROFILES
  if grep -qE '^COMPOSE_PROFILES=.*\bhttps\b' .env 2>/dev/null; then
    docker compose up -d --force-recreate --no-deps tlsproxy </dev/null >/dev/null 2>&1
  else
    docker compose --profile https rm -sf tlsproxy </dev/null >/dev/null 2>&1
    rm -f data/tls/incoming/remove-own-ca # no proxy is left to read it
  fi
  docker compose up -d --force-recreate --no-deps mikrokat </dev/null >/dev/null 2>&1
  wait_for 15 incoming_empty || echo "warning: data/tls/incoming is not empty"
  apply_rules || echo "warning: the rules could not be applied, run tools/update-rules.sh"
  [ -z "$E2E_WORK" ] || rm -rf "$E2E_WORK"
  echo "$RESULT"
  exit "$code"
}

setup() {
  # What a killed run may have left.
  ip route del local "$SERVER/32" dev lo 2>/dev/null
  remove_rules
  drop_own_ca

  E2E_WORK=$(mktemp -d)
  # This suite runs again after every review, so a PASS must be for the code in this folder.
  docker compose build tzsp mikrokat tlsproxy </dev/null >"$E2E_WORK/build.log" 2>&1 || fail "the build failed: $(tail -3 "$E2E_WORK/build.log")"
  "${COMPOSE[@]}" up -d --no-deps tzsp mikrokat </dev/null >"$E2E_WORK/build.log" 2>&1 || fail "cannot start: $(tail -3 "$E2E_WORK/build.log")"

  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=$TEST_CA" \
    -keyout "$E2E_WORK/test-ca.key" -out "$E2E_WORK/test-ca.pem" 2>/dev/null || fail "no test CA"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=test.example.net \
    -keyout "$E2E_WORK/server.key" -out "$E2E_WORK/server.csr" 2>/dev/null || fail "no server key"
  openssl x509 -req -in "$E2E_WORK/server.csr" -CA "$E2E_WORK/test-ca.pem" -CAkey "$E2E_WORK/test-ca.key" -CAcreateserial -days 2 \
    -extfile <(echo "subjectAltName=DNS:test.example.net,DNS:pinned.example.net,DNS:banked.example.net") -out "$E2E_WORK/server.pem" 2>/dev/null || fail "no server certificate"

  # The bank list the proxy downloads: 1100 made-up names and one the test server answers to.
  mkdir -p "$E2E_WORK/bank"
  python3 - "$E2E_WORK/bank/bank.tar.gz" <<'PY'
import io
import sys
import tarfile

names = [f"n{i:04d}.bank-e2e.example" for i in range(1100)] + ["banked.example.net"]
data = ("\n".join(names) + "\n").encode()
with tarfile.open(sys.argv[1], "w:gz") as tar:
    info = tarfile.TarInfo("bank/domains")
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))
PY
  python3 -m http.server 8099 --bind 127.0.0.1 --directory "$E2E_WORK/bank" >/dev/null 2>&1 &
  BANK_PID=$!
  rm -f data/tls/state/bank-list.txt

  # A local route, not an address on lo: the proxy refuses the addresses of the host's interfaces.
  ip route add local "$SERVER/32" dev lo || fail "no route to $SERVER"
  python3 tests/e2e/server.py "$SERVER" "$E2E_WORK/server.pem" "$E2E_WORK/server.key" &
  SERVER_PID=$!

  cat >>rules/local.rules <<'EOF'
alert http any any -> any any (msg:"MIKROKAT E2E"; http.uri; content:"/mikrokat-e2e"; sid:9000001; rev:1;)
alert tcp any any -> any any (msg:"MIKROKAT E2E TAIL"; flow:to_client; content:"mikrokat-e2e-tail"; sid:9000002; rev:1;)
alert http any any -> any any (msg:"MIKROKAT E2E RESPONSE"; flow:to_client; file.data; content:"mikrokat-e2e-ok"; sid:9000003; rev:1;)
EOF
  apply_rules || fail "the rules could not be applied: $(tail -3 rules/.update.log)"

  "${COMPOSE[@]}" up -d --force-recreate --no-deps tlsproxy </dev/null >/dev/null 2>&1 || fail "cannot start tlsproxy with the override"
  EVE_MARK=$(cat data/logs/eve-*.json 2>/dev/null | wc -c)
}

# A clean install has no HTTPS inspection: without the profile the stack is five containers, and the proxy, its port, its tab and its routes are not there.
profile_off_check() {
  check "HTTPS inspection off without the profile"
  local names
  COMPOSE_PROFILES= docker compose --profile https rm -sf tlsproxy </dev/null >/dev/null 2>&1
  COMPOSE_PROFILES= docker compose up -d --force-recreate --no-deps mikrokat </dev/null >"$E2E_WORK/build.log" 2>&1 || fail "cannot start without the profile: $(tail -3 "$E2E_WORK/build.log")"
  COMPOSE_PROFILES= docker compose up -d </dev/null >"$E2E_WORK/build.log" 2>&1 || fail "cannot start the stack without the profile: $(tail -3 "$E2E_WORK/build.log")"
  wait_for 60 app_up || fail "the app did not answer without the profile"
  names=$(docker ps --filter name=mikrokat- --format '{{.Names}}' </dev/null | sort | tr '\n' ' ')
  [ "$(echo "$names" | wc -w)" = 5 ] || fail "expected five containers, got: $names"
  case "$names" in *tlsproxy*) fail "the proxy is running without the profile: $names" ;; esac
  port_closed || fail "port 1080 is open without the profile"
  sign_in
  local settings
  settings=$(curl -s -b "$E2E_WORK/cookies" "$APP/settings")
  case "$settings" in *'id="pane-https"'* | *'id="tab-https"'*) fail "the HTTPS inspection tab is on the Settings page" ;; esac
  case "$settings" in *'id="pane-account"'*) ;; *) fail "the Settings page did not load" ;; esac
  curl -s -b "$E2E_WORK/cookies" "$APP/connections" | grep -q "COMPOSE_PROFILES=https" || fail "/connections does not say how to enable it"
  [ "$(curl -s -o /dev/null -w '%{http_code}' -b "$E2E_WORK/cookies" "$APP/tls/ca.pem")" = 404 ] || fail "/tls/ca.pem is not a 404"
  curl -s "$APP/tls.pac" | grep -q 'return "DIRECT"' || fail "/tls.pac does not answer direct"
  curl -s -b "$E2E_WORK/cookies" "$APP/" | grep -q 'href="/connections"' && fail "the Overview links to Connections"
  echo "five containers, no proxy, no tab"
  if have_browser; then
    mkdir -p "$E2E_WORK/pw"
    MK_PASSWORD=$(sed -n 's/^WEB_PASSWORD=//p' .env | tr -d '\n')
    export MK_PASSWORD APP
    browser off
  fi
  "${COMPOSE[@]}" up -d --force-recreate --no-deps mikrokat tlsproxy </dev/null >"$E2E_WORK/build.log" 2>&1 || fail "cannot start again with the profile: $(tail -3 "$E2E_WORK/build.log")"
  wait_for 60 app_up || fail "the app did not come back with the profile"
}

# Compose leaves a running container alone when its profile goes, and the tab to stop the proxy goes with the profile. So the app has to stop it, or it would go on decrypting.
profile_removed_check() {
  check "A running proxy stops inspecting when the profile goes"
  port_open || fail "port 1080 is not open before this check"
  COMPOSE_PROFILES= docker compose up -d --force-recreate --no-deps mikrokat </dev/null >"$E2E_WORK/build.log" 2>&1 || fail "cannot start without the profile: $(tail -3 "$E2E_WORK/build.log")"
  wait_for 60 app_up || fail "the app did not answer without the profile"
  [ -n "$(docker ps -q --filter name=mikrokat-tlsproxy </dev/null)" ] || fail "the proxy is gone, so this check proves nothing"
  control_says false || fail "the control file still switches the proxy on"
  wait_for 30 port_closed || fail "port 1080 stayed open after the profile went"
  "${COMPOSE[@]}" up -d --force-recreate --no-deps mikrokat tlsproxy </dev/null >"$E2E_WORK/build.log" 2>&1 || fail "cannot start again with the profile: $(tail -3 "$E2E_WORK/build.log")"
  wait_for 60 app_up || fail "the app did not come back with the profile"
  wait_for 30 port_open || fail "port 1080 did not open again with the saved switch"
  echo "port 1080 closed with the container still running, and opened again with the profile"
}

trap 'fail interrupted' INT TERM
trap finish EXIT
setup
if [ "${1:-}" = measure ]; then
  measure
  RESULT="Measured"
else
  [ -n "$E2E_SHOTS" ] || E2E_SHOTS=$E2E_WORK/shots
  profile_off_check
  # With the feature still off, because the browser switches it on through the page.
  browser_checks
  feature on
  wait_for 30 app_up || fail "the app did not come back"
  wait_for 30 port_open || fail "port 1080 did not open"
  cp data/tls/state/ca.pem "$E2E_WORK/ca.pem"
  profile_removed_check
  checks
  RESULT=PASS
fi
