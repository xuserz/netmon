#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root: sudo ./scripts/install.sh [--release | path/to/dnsmon]' >&2
  exit 1
fi
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -gt 1 ]; then echo 'Usage: install.sh [--release | path/to/dnsmon]' >&2; exit 1; fi
if [ "${1:-}" = --release ]; then exec sh "$project_dir/scripts/install-release.sh"; fi
binary=${1:-"$project_dir/bin/dnsmon"}
if [ ! -x "$binary" ]; then
  if [ "$#" -eq 0 ]; then exec sh "$project_dir/scripts/install-release.sh"; fi
  echo "Binary is not executable: $binary" >&2
  exit 1
fi
"$binary" version
if ! getent group dnsmon >/dev/null; then groupadd --system dnsmon; fi
if ! getent passwd dnsmon >/dev/null; then
  useradd --system --gid dnsmon --home-dir /var/lib/dnsmon --no-create-home --shell /usr/sbin/nologin dnsmon
fi
install -d -m 0755 /usr/local/bin
install -d -o root -g dnsmon -m 0750 /etc/dnsmon
install -d -o dnsmon -g dnsmon -m 0750 /var/lib/dnsmon
new_config=0
if [ ! -e /etc/dnsmon/config.yaml ]; then
  install -o root -g dnsmon -m 0640 "$project_dir/dnsmon.yaml" /etc/dnsmon/config.yaml
  new_config=1
  # Suggest the one ingress interface selected by the default IPv4 route.
  # Never alter an existing configuration or combine bridge/veth observations.
  if command -v ip >/dev/null 2>&1; then
    ingress=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") {print $(i+1);exit}}') || ingress=
    case "$ingress" in ''|*[!a-zA-Z0-9_.:-]*|lo|docker*|veth*|br-*) ingress= ;; esac
    if [ -n "$ingress" ]; then
      config_temp=$(mktemp /etc/dnsmon/.config.XXXXXX)
      awk -v iface="$ingress" '$1=="interface:" {$0="interface: " iface} {print}' /etc/dnsmon/config.yaml > "$config_temp"
      install -o root -g dnsmon -m 0640 "$config_temp" /etc/dnsmon/config.yaml
      rm -f -- "$config_temp"
    fi
  fi
fi
# Perform read-only preflight before disturbing a running installation.
if ! "$binary" --config /etc/dnsmon/config.yaml check --startup; then
  if [ "$new_config" -eq 0 ]; then
    echo 'Preflight failed. Existing service and binary were left in place.' >&2
    exit 1
  fi
  echo 'Review /etc/dnsmon/config.yaml before enabling the new service.' >&2
fi
binary_temp=$(mktemp /usr/local/bin/.dnsmon.XXXXXX)
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
    systemctl stop dnsmon.service >/dev/null 2>&1 || true
    if [ -n "$binary_previous" ] && [ -f "$binary_previous" ]; then
      mv -f -- "$binary_previous" /usr/local/bin/dnsmon
    fi
    if [ -n "$unit_previous" ] && [ -f "$unit_previous" ]; then
      mv -f -- "$unit_previous" /etc/systemd/system/dnsmon.service
    fi
    systemctl daemon-reload || true
    systemctl reset-failed dnsmon.service || true
    if ! systemctl start dnsmon.service; then echo 'Previous service could not be restarted; inspect journalctl -u dnsmon.' >&2; fi
  fi
  rm -f -- "$binary_temp"
  if [ -n "$binary_previous" ]; then rm -f -- "$binary_previous"; fi
  if [ -n "$unit_previous" ]; then rm -f -- "$unit_previous"; fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
install -m 0755 "$binary" "$binary_temp"
if [ -f /usr/local/bin/dnsmon ]; then
  binary_previous=$(mktemp /usr/local/bin/.dnsmon.previous.XXXXXX)
  cp -p /usr/local/bin/dnsmon "$binary_previous"
fi
if [ -f /etc/systemd/system/dnsmon.service ]; then
  unit_previous=$(mktemp /etc/systemd/system/.dnsmon.previous.XXXXXX)
  cp -p /etc/systemd/system/dnsmon.service "$unit_previous"
fi
if systemctl is-active --quiet dnsmon.service; then
  was_active=1
  systemctl stop dnsmon.service
  service_stopped=1
fi
mv -f -- "$binary_temp" /usr/local/bin/dnsmon
install -m 0644 "$project_dir/packaging/dnsmon.service" /etc/systemd/system/dnsmon.service
install -d -m 0755 /usr/share/doc/dnsmon
for document in README.md LICENSE THIRD_PARTY_NOTICES.md CHANGELOG.md CONTRIBUTING.md; do
  install -m 0644 "$project_dir/$document" "/usr/share/doc/dnsmon/$document"
done
install -m 0644 "$project_dir/dnsmon.yaml" /usr/share/doc/dnsmon/dnsmon.yaml
if [ -d "$project_dir/docs" ]; then
  install -d -m 0755 /usr/share/doc/dnsmon/docs
  for guide in "$project_dir"/docs/*.md; do
    [ -f "$guide" ] || continue
    install -m 0644 "$guide" "/usr/share/doc/dnsmon/docs/$(basename -- "$guide")"
  done
fi
install -d -m 0755 /usr/local/libexec/dnsmon
# Also rename helper scripts atomically: an update may be running the old one.
for helper in install-release.sh uninstall.sh; do
  helper_temp=$(mktemp /usr/local/libexec/dnsmon/.helper.XXXXXX)
  install -m 0755 "$project_dir/scripts/$helper" "$helper_temp"
  mv -f -- "$helper_temp" "/usr/local/libexec/dnsmon/$helper"
done
systemctl daemon-reload
if [ "$was_active" -eq 1 ]; then
  systemctl reset-failed dnsmon.service
  systemctl start dnsmon.service
  attempts=0
  healthy=0
  # A live diagnostic response confirms that DB initialization, BPF attachment
  # and interface binding completed, rather than just trusting Type=simple.
  while [ "$attempts" -lt 60 ]; do
    if systemctl is-active --quiet dnsmon.service && /usr/local/bin/dnsmon --config /etc/dnsmon/config.yaml status >/dev/null 2>&1; then
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
  sudo /usr/local/libexec/dnsmon/install-release.sh
For a new installation, review the selected interface before enabling:
  sudoedit /etc/dnsmon/config.yaml
  sudo dnsmon check --startup
  sudo systemctl enable --now dnsmon
  sudo dnsmon status
  sudo dnsmon top
MESSAGE
