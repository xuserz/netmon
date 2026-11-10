#!/bin/sh
# Run from an extracted netmon release. No database copy or ownership rewrite.
set -eu
fail() { printf 'netmon migration: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail 'Run as root.'
[ "$#" -le 1 ] || fail 'Usage: migrate-dnsmon.sh [path/to/netmon]'
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary=${1:-"$project_dir/bin/netmon"}
[ -x "$binary" ] || fail 'Build or extract the netmon binary first.'
[ -f /etc/dnsmon/config.yaml ] || fail 'No /etc/dnsmon/config.yaml exists.'
[ -x /usr/local/bin/dnsmon ] || fail 'Existing dnsmon binary not found.'
[ -f /etc/systemd/system/dnsmon.service ] || fail 'Existing dnsmon unit not found.'
[ ! -e /etc/netmon/config.yaml ] || fail 'netmon config already exists; refusing to overwrite it.'
[ ! -e /etc/systemd/system/netmon.service ] || fail 'netmon unit already exists; migrate manually.'
[ ! -e /etc/systemd/system/netmon.service.d ] || fail 'netmon overrides already exist; migrate manually.'
[ ! -e /usr/local/bin/netmon ] || fail 'netmon binary already exists; migrate manually.'
getent passwd dnsmon >/dev/null || fail 'Existing dnsmon service account not found.'
# Preserve customized units for manual review instead of guessing their behavior.
awk '$0=="User=dnsmon" {found=1} END {exit !found}' /etc/systemd/system/dnsmon.service || fail 'Custom service user: migrate manually.'
awk '$0=="ExecStart=/usr/local/bin/dnsmon --config /etc/dnsmon/config.yaml run" {found=1} END {exit !found}' /etc/systemd/system/dnsmon.service || fail 'Custom ExecStart: migrate manually.'
if [ -d /etc/systemd/system/dnsmon.service.d ]; then
  for override in /etc/systemd/system/dnsmon.service.d/*.conf; do
    [ -f "$override" ] || continue
    if awk '/^[[:space:]]*(ExecStart|ExecStartPre|User|Group|DynamicUser)[[:space:]]*=/ {found=1} END {exit !found}' "$override"; then
      fail 'Service command/account overrides require manual migration; nothing changed.'
    fi
  done
fi
install -d -o root -g dnsmon -m 0750 /etc/netmon
config_temp=$(mktemp /etc/netmon/.migration.XXXXXX)
was_active=0
was_enabled=0
stopped=0
success=0
cleanup() {
  result=$?
  trap - EXIT HUP INT TERM
  rm -f -- "$config_temp"
  if [ "$success" -eq 0 ]; then
    if [ "$stopped" -eq 1 ]; then
      systemctl stop netmon.service >/dev/null 2>&1 || true
      systemctl disable netmon.service >/dev/null 2>&1 || true
      rm -f /etc/systemd/system/netmon.service /usr/local/bin/netmon
      rm -rf /etc/systemd/system/netmon.service.d
      systemctl daemon-reload || true
      if [ "$was_enabled" -eq 1 ]; then systemctl enable dnsmon.service || true; fi
      if [ "$was_active" -eq 1 ]; then systemctl reset-failed dnsmon.service || true; systemctl start dnsmon.service || true; fi
    fi
    rm -f /etc/netmon/config.yaml
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
# The old implicit paths become explicit; original config/key/data stay intact.
"$binary" migrate-config --from /etc/dnsmon/config.yaml > "$config_temp"
install -o root -g dnsmon -m 0640 "$config_temp" /etc/netmon/config.yaml
NETMON_SERVICE_USER=dnsmon "$binary" --config /etc/netmon/config.yaml check --startup
if systemctl is-active --quiet dnsmon.service; then was_active=1; fi
if systemctl is-enabled --quiet dnsmon.service; then was_enabled=1; fi
if [ "$was_active" -eq 1 ]; then systemctl stop dnsmon.service; fi
stopped=1
# Let the regular installer recognize the retained service account.
awk '
  /^User=/ {$0="User=dnsmon"}
  /^Group=/ {$0="Group=dnsmon"}
  /^StateDirectory=/ {$0="StateDirectory=dnsmon"}
  /^RuntimeDirectory=/ {$0="RuntimeDirectory=dnsmon"}
  {print}
' "$project_dir/packaging/netmon.service" > /etc/systemd/system/netmon.service
if [ -d /etc/systemd/system/dnsmon.service.d ]; then
  cp -pR /etc/systemd/system/dnsmon.service.d /etc/systemd/system/netmon.service.d
fi
# The installer keeps an inactive service inactive; migration restores the state.
sh "$project_dir/scripts/install.sh" "$binary"
if [ "$was_active" -eq 1 ]; then
  systemctl daemon-reload
  systemctl reset-failed netmon.service
  systemctl start netmon.service
  attempts=0
  healthy=0
  while [ "$attempts" -lt 60 ]; do
    if systemctl is-active --quiet netmon.service && /usr/local/bin/netmon --config /etc/netmon/config.yaml status >/dev/null 2>&1; then
      healthy=$((healthy+1))
      [ "$healthy" -lt 2 ] || break
    else
      healthy=0
    fi
    attempts=$((attempts+1))
    sleep 1
  done
  [ "$healthy" -ge 2 ] || fail 'New service did not become healthy; restoring dnsmon.'
fi
systemctl disable dnsmon.service
if [ "$was_enabled" -eq 1 ]; then systemctl enable netmon.service; fi
success=1
printf '%s\n' 'Migrated to netmon.service. Original config, binary, unit, account and all data were retained.' \
  'Use: netmon top; netmon status; journalctl -u netmon' \
  'The old dnsmon service is disabled. Do not start both services.'
