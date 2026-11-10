#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root: sudo ./scripts/install.sh [--release | path/to/dnsmon]' >&2
  exit 1
fi
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -gt 1 ]; then
  echo 'Usage: install.sh [--release | path/to/dnsmon]' >&2
  exit 1
fi
if [ "${1:-}" = --release ]; then
  exec sh "$project_dir/scripts/install-release.sh"
fi
binary=${1:-"$project_dir/bin/dnsmon"}
if [ ! -x "$binary" ]; then
  if [ "$#" -eq 0 ]; then exec sh "$project_dir/scripts/install-release.sh"; fi
  echo "Binary is not executable: $binary" >&2
  exit 1
fi
# Validate the downloaded/local executable before stopping an existing service.
"$binary" version
# Rename within the destination filesystem to avoid leaving a partial executable.
binary_temp=$(mktemp /usr/local/bin/.dnsmon.XXXXXX)
trap 'rm -f -- "$binary_temp"' EXIT
trap 'exit 1' HUP INT TERM
install -m 0755 "$binary" "$binary_temp"

if ! getent group dnsmon >/dev/null; then groupadd --system dnsmon; fi
if ! getent passwd dnsmon >/dev/null; then
  useradd --system --gid dnsmon --home-dir /var/lib/dnsmon --no-create-home --shell /usr/sbin/nologin dnsmon
fi
# Stop a running service before replacing its binary; preserve enablement.
was_active=0
if systemctl is-active --quiet dnsmon.service; then
  was_active=1
  systemctl stop dnsmon.service
fi
mv -f -- "$binary_temp" /usr/local/bin/dnsmon
install -d -o root -g dnsmon -m 0750 /etc/dnsmon
install -d -o dnsmon -g dnsmon -m 0750 /var/lib/dnsmon
if [ ! -e /etc/dnsmon/config.yaml ]; then
  install -o root -g dnsmon -m 0640 "$project_dir/dnsmon.yaml" /etc/dnsmon/config.yaml
fi
install -m 0644 "$project_dir/packaging/dnsmon.service" /etc/systemd/system/dnsmon.service
install -d -m 0755 /usr/share/doc/dnsmon
install -m 0644 "$project_dir/README.md" /usr/share/doc/dnsmon/README.md
install -d -m 0755 /usr/local/libexec/dnsmon
install -m 0755 "$project_dir/scripts/install-release.sh" /usr/local/libexec/dnsmon/install-release.sh
install -m 0755 "$project_dir/scripts/uninstall.sh" /usr/local/libexec/dnsmon/uninstall.sh
systemctl daemon-reload
if [ "$was_active" -eq 1 ]; then systemctl start dnsmon.service; fi
cat <<'MESSAGE'
Installed. Existing configuration and database have been preserved.
Update later without Go:
  sudo /usr/local/libexec/dnsmon/install-release.sh
For a new installation:
  sudoedit /etc/dnsmon/config.yaml   # select the actual ingress interface/IP/port
  sudo systemctl enable --now dnsmon
  sudo dnsmon status
  sudo dnsmon top
MESSAGE
