#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root: sudo ./scripts/install.sh [--release | path/to/netmon]' >&2
  exit 1
fi
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -gt 1 ]; then echo 'Usage: install.sh [--release | path/to/netmon]' >&2; exit 1; fi
if [ "${1:-}" = --release ]; then exec sh "$project_dir/scripts/install-release.sh"; fi
binary=${1:-"$project_dir/bin/netmon"}
if [ ! -x "$binary" ]; then
  if [ "$#" -eq 0 ]; then exec sh "$project_dir/scripts/install-release.sh"; fi
  echo "Binary is not executable: $binary" >&2
  exit 1
fi
"$binary" version
if [ -f /etc/dnsmon/config.yaml ] && [ ! -e /etc/netmon/config.yaml ]; then
  exec sh "$project_dir/scripts/migrate-dnsmon.sh" "$binary"
fi
if systemctl is-active --quiet dnsmon.service; then
  echo 'dnsmon.service is still active. Complete the migration before installing a second monitor.' >&2
  exit 1
fi
# Migrated installations retain the old account and data ownership.
service_user=netmon
state_directory=netmon
if [ -f /etc/systemd/system/netmon.service ] && awk '$0=="User=dnsmon" {found=1} END {exit !found}' /etc/systemd/system/netmon.service; then
  service_user=dnsmon
  state_directory=dnsmon
fi
if ! getent group "$service_user" >/dev/null; then groupadd --system "$service_user"; fi
if ! getent passwd "$service_user" >/dev/null; then
  useradd --system --gid "$service_user" --home-dir "/var/lib/$state_directory" --no-create-home --shell /usr/sbin/nologin "$service_user"
fi
install -d -m 0755 /usr/local/bin
install -d -o root -g "$service_user" -m 0750 /etc/netmon
install -d -o "$service_user" -g "$service_user" -m 0750 /var/lib/netmon
new_config=0
if [ ! -e /etc/netmon/config.yaml ]; then
  install -o root -g "$service_user" -m 0640 "$project_dir/netmon.yaml" /etc/netmon/config.yaml
  new_config=1
  # Suggest the one ingress interface selected by the default IPv4 route.
  # Never alter an existing configuration or combine bridge/veth observations.
  if command -v ip >/dev/null 2>&1; then
    ingress=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") {print $(i+1);exit}}') || ingress=
    case "$ingress" in ''|*[!a-zA-Z0-9_.:-]*|lo|docker*|veth*|br-*) ingress= ;; esac
    if [ -n "$ingress" ]; then
      config_temp=$(mktemp /etc/netmon/.config.XXXXXX)
      awk -v iface="$ingress" '$1=="interface:" {$0="interface: " iface} {print}' /etc/netmon/config.yaml > "$config_temp"
      install -o root -g "$service_user" -m 0640 "$config_temp" /etc/netmon/config.yaml
      rm -f -- "$config_temp"
    fi
  fi
fi
# Perform read-only preflight before disturbing a running installation.
preflight() {
  if [ "$service_user" = dnsmon ]; then
    NETMON_SERVICE_USER=dnsmon "$binary" --config /etc/netmon/config.yaml check --startup
  else
    "$binary" --config /etc/netmon/config.yaml check --startup
  fi
}
if ! preflight; then
  if [ "$new_config" -eq 0 ]; then
    echo 'Preflight failed. Existing service and binary were left in place.' >&2
    exit 1
  fi
  echo 'Review /etc/netmon/config.yaml before enabling the new service.' >&2
fi
binary_temp=$(mktemp /usr/local/bin/.netmon.XXXXXX)
binary_previous=
unit_previous=
was_active=0
service_stopped=0
succeeded=0
cleanup() {
  result=$?
  trap - EXIT HUP INT TERM
  if [ "$succeeded" -eq 0 ] && [ "$service_stopped" -eq 1 ]; then
    echo 'Update failed; restoring the previous executable and service unit.' >&2
    systemctl stop netmon.service >/dev/null 2>&1 || true
    if [ -n "$binary_previous" ] && [ -f "$binary_previous" ]; then
      mv -f -- "$binary_previous" /usr/local/bin/netmon
    fi
    if [ -n "$unit_previous" ] && [ -f "$unit_previous" ]; then
      mv -f -- "$unit_previous" /etc/systemd/system/netmon.service
    fi
    systemctl daemon-reload || true
    systemctl reset-failed netmon.service || true
    if ! systemctl start netmon.service; then echo 'Previous service could not be restarted; inspect journalctl -u netmon.' >&2; fi
  fi
  rm -f -- "$binary_temp"
  if [ -n "$binary_previous" ]; then rm -f -- "$binary_previous"; fi
  if [ -n "$unit_previous" ]; then rm -f -- "$unit_previous"; fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
install -m 0755 "$binary" "$binary_temp"
if [ -f /usr/local/bin/netmon ]; then
  binary_previous=$(mktemp /usr/local/bin/.netmon.previous.XXXXXX)
  cp -p /usr/local/bin/netmon "$binary_previous"
fi
if [ -f /etc/systemd/system/netmon.service ]; then
  unit_previous=$(mktemp /etc/systemd/system/.netmon.previous.XXXXXX)
  cp -p /etc/systemd/system/netmon.service "$unit_previous"
fi
if systemctl is-active --quiet netmon.service; then
  was_active=1
  systemctl stop netmon.service
  service_stopped=1
fi
mv -f -- "$binary_temp" /usr/local/bin/netmon
unit_temp=$(mktemp /etc/systemd/system/.netmon.unit.XXXXXX)
awk -v account="$service_user" -v state="$state_directory" '
  /^User=/ {$0="User=" account}
  /^Group=/ {$0="Group=" account}
  /^StateDirectory=/ {$0="StateDirectory=" state}
  /^RuntimeDirectory=/ {$0="RuntimeDirectory=" state}
  {print}
' "$project_dir/packaging/netmon.service" > "$unit_temp"
install -m 0644 "$unit_temp" /etc/systemd/system/netmon.service
rm -f -- "$unit_temp"
install -d -m 0755 /usr/share/doc/netmon
for document in README.md LICENSE THIRD_PARTY_NOTICES.md CHANGELOG.md CONTRIBUTING.md; do
  install -m 0644 "$project_dir/$document" "/usr/share/doc/netmon/$document"
done
install -m 0644 "$project_dir/netmon.yaml" /usr/share/doc/netmon/netmon.yaml
if [ -d "$project_dir/docs" ]; then
  install -d -m 0755 /usr/share/doc/netmon/docs
  for guide in "$project_dir"/docs/*.md; do
    [ -f "$guide" ] || continue
    install -m 0644 "$guide" "/usr/share/doc/netmon/docs/$(basename -- "$guide")"
  done
fi
install -d -m 0755 /usr/local/libexec/netmon
# Also rename helper scripts atomically: an update may be running the old one.
for helper in install-release.sh uninstall.sh; do
  helper_temp=$(mktemp /usr/local/libexec/netmon/.helper.XXXXXX)
  install -m 0755 "$project_dir/scripts/$helper" "$helper_temp"
  mv -f -- "$helper_temp" "/usr/local/libexec/netmon/$helper"
done
systemctl daemon-reload
if [ "$was_active" -eq 1 ]; then
  systemctl reset-failed netmon.service
  systemctl start netmon.service
  attempts=0
  healthy=0
  # A live diagnostic response confirms that DB initialization, BPF attachment
  # and interface binding completed, rather than just trusting Type=simple.
  while [ "$attempts" -lt 60 ]; do
    if systemctl is-active --quiet netmon.service && /usr/local/bin/netmon --config /etc/netmon/config.yaml status >/dev/null 2>&1; then
      healthy=$((healthy + 1))
      if [ "$healthy" -ge 2 ]; then break; fi
    else
      healthy=0
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  if [ "$healthy" -lt 2 ]; then
    echo 'The new monitor did not become healthy; rolling back.' >&2
    exit 1
  fi
fi
succeeded=1
cat <<'MESSAGE'
Installed. Existing configuration and database have been preserved.
Update later without Go:
  sudo /usr/local/libexec/netmon/install-release.sh
For a new installation, review the selected interface before enabling:
  sudoedit /etc/netmon/config.yaml
  sudo netmon check --startup
  sudo systemctl enable --now netmon
  sudo netmon status
  sudo netmon top
MESSAGE
