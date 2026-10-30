#!/bin/sh
# Run by the rules container: applies rules/ when the web page asks for it.
cd /rules || exit 1
while :; do
  if [ -f .update-request ]; then
    rm -f .update-request
    started=$(date '+%Y-%m-%d %H:%M')
    echo "running $started" > .update-status
    if suricata-update --disable-conf /rules/disable.conf --enable-conf /rules/enable.conf --local /rules/local.rules --no-reload > .update.log 2>&1 \
      && suricatasc -c reload-rules /var/run/suricata/suricata-command.socket >> .update.log 2>&1; then
      echo "ok $started" > .update-status
    else
      echo "failed $started" > .update-status
    fi
  fi
  sleep 3
done
