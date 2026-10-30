#!/bin/sh
# Download the rulesets, apply rules/ and reload Suricata without stopping it.
set -e
cd "$(dirname "$0")/.."
docker compose run --rm -T --no-deps suricata suricata-update \
  --disable-conf /rules/disable.conf --enable-conf /rules/enable.conf --local /rules/local.rules --no-reload
docker exec mikrokat-suricata suricatasc -c reload-rules
