#!/bin/bash
# End-to-end test of HTTPS inspection, for a disposable host with the stack running.
# Run it as root. It recreates tlsproxy, restarts mikrokat and applies the rules, and it leaves the
# feature off and its own rules gone, also when a check fails. It is safe to run again.
#
#   tests/e2e/run.sh           runs the checks and prints PASS, or the check that failed
#   tests/e2e/run.sh measure   prints RAM, CPU, throughput and frame numbers
set -u
cd "$(dirname "$0")/../.." || exit 1

SERVER=198.51.100.7
SOCKS=127.0.0.1:1080
APP=http://127.0.0.1:8088
TEST_CA="Mikrokat E2E test CA"
ALARM="HTTPS inspection has stopped"
COOKIE=e2e-cookie-value
POST_BODY=e2e-body-value
BURST=$((2**20))
FETCHES=200
SUSTAINED=$((2**30))
SETTLE=14 # dump-counters lagged by 10.6 seconds at most, and stats.json is written every 10
COMPOSE=(docker compose -f docker-compose.yml -f tests/e2e/docker-compose.e2e.yml)

export E2E_WORK=
CHECK=Setup
RESULT="FAIL: stopped early"
SERVER_PID=

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

alarm_shown() {
  curl -s -b "$E2E_WORK/cookies" "$APP/" | grep -q "$ALARM"
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
  through_proxy pinned.example.net --cacert "$E2E_WORK/test-ca.pem" -o /dev/null https://pinned.example.net/ 2>/dev/null
  code=$?
  [ "$code" = 60 ] || fail "the first try returned $code, not a certificate failure"
  sleep 1
  body=$(through_proxy pinned.example.net --cacert "$E2E_WORK/test-ca.pem" https://pinned.example.net/ 2>&1)
  [ "$body" = "mikrokat-e2e-ok" ] || fail "the second try was not relayed: $body"
  wait_for 15 counter_above relayed.auto_bypass "$before" || fail "relayed.auto_bypass did not grow"
  counter auto_bypass | grep -q '"device": "127.0.0.1", "name": "pinned.example.net"' || fail "auto_bypass does not list the name: $(counter auto_bypass)"

  check "Cookies and bodies stay off the disk"
  through_proxy test.example.net --cacert "$E2E_WORK/ca.pem" -o /dev/null -H "Cookie: $COOKIE" -d "$POST_BODY" https://test.example.net/mikrokat-e2e-post || fail "the POST failed"
  wait_for 30 post_seen || fail "Suricata did not see the POST, so this check proves nothing"
  sleep 5 # let EveBox read it too
  grep -rlF -e "$COOKIE" -e "$POST_BODY" data/ >"$E2E_WORK/found"
  [ ! -s "$E2E_WORK/found" ] || fail "found in $(tr '\n' ' ' <"$E2E_WORK/found")"

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
  [ "$delta_udp_lost" = 0 ] || fail "$delta_udp_lost frames lost on the way to tzsp"
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

  check "Device outside the list"
  address=$(hostname -I | cut -d' ' -f1)
  before=$(counter refused)
  curl -sS --max-time 10 --socks5 "$address:1080" -o /dev/null "https://$SERVER/" 2>/dev/null
  code=$?
  [ "$code" != 0 ] || fail "the connection was served"
  wait_for 15 counter_above refused "$before" || fail "refused did not grow"

  check "Switching off"
  feature off
  wait_for 30 control_says false || fail "the control file still says on"
  wait_for 3 port_closed || fail "port 1080 still open 3 seconds after the control file changed"

  check "Stopping the proxy"
  feature on
  wait_for 30 port_open || fail "port 1080 did not open again"
  sign_in
  docker stop -t 2 mikrokat-tlsproxy </dev/null >/dev/null
  local stopped=$SECONDS
  wait_for 150 alarm_shown || fail "no alarm on the Overview page after 150 seconds"
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
  ip route del local "$SERVER/32" dev lo 2>/dev/null
  remove_rules
  feature remove
  # Without the override, so the proxy trusts the public roots again and forgets the automatic bypass.
  docker compose up -d --force-recreate --no-deps tlsproxy </dev/null >/dev/null 2>&1
  apply_rules || echo "warning: the rules could not be applied, run tools/update-rules.sh"
  [ -z "$E2E_WORK" ] || rm -rf "$E2E_WORK"
  echo "$RESULT"
  exit "$code"
}

setup() {
  # What a killed run may have left.
  ip route del local "$SERVER/32" dev lo 2>/dev/null
  remove_rules

  E2E_WORK=$(mktemp -d)
  # This suite runs again after every review, so a PASS must be for the code in this folder.
  docker compose build tzsp mikrokat tlsproxy </dev/null >"$E2E_WORK/build.log" 2>&1 || fail "the build failed: $(tail -3 "$E2E_WORK/build.log")"
  docker compose up -d --no-deps tzsp mikrokat </dev/null >"$E2E_WORK/build.log" 2>&1 || fail "cannot start: $(tail -3 "$E2E_WORK/build.log")"

  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=$TEST_CA" \
    -keyout "$E2E_WORK/test-ca.key" -out "$E2E_WORK/test-ca.pem" 2>/dev/null || fail "no test CA"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=test.example.net \
    -keyout "$E2E_WORK/server.key" -out "$E2E_WORK/server.csr" 2>/dev/null || fail "no server key"
  openssl x509 -req -in "$E2E_WORK/server.csr" -CA "$E2E_WORK/test-ca.pem" -CAkey "$E2E_WORK/test-ca.key" -CAcreateserial -days 2 \
    -extfile <(echo "subjectAltName=DNS:test.example.net,DNS:pinned.example.net") -out "$E2E_WORK/server.pem" 2>/dev/null || fail "no server certificate"

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

trap 'fail interrupted' INT TERM
trap finish EXIT
setup
if [ "${1:-}" = measure ]; then
  measure
  RESULT="Measured"
else
  feature on
  wait_for 30 port_open || fail "port 1080 did not open"
  cp data/tls/state/ca.pem "$E2E_WORK/ca.pem"
  checks
  RESULT=PASS
fi
