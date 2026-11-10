#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then echo 'Run as root: sudo ./scripts/uninstall.sh' >&2; exit 1; fi
if [ "$#" -ne 0 ]; then echo 'Usage: uninstall.sh (data is always preserved)' >&2; exit 1; fi
systemctl disable --now netmon.service
rm -f /etc/systemd/system/netmon.service /usr/local/bin/netmon
systemctl daemon-reload
rm -f /usr/local/libexec/netmon/install-release.sh /usr/local/libexec/netmon/uninstall.sh
rmdir /usr/local/libexec/netmon 2>/dev/null || true
rm -f /usr/share/doc/netmon/THIRD_PARTY_NOTICES.md /usr/share/doc/netmon/LICENSE /usr/share/doc/netmon/CHANGELOG.md /usr/share/doc/netmon/CONTRIBUTING.md /usr/share/doc/netmon/README.md /usr/share/doc/netmon/netmon.yaml /usr/share/doc/netmon/ip-labels.yaml
rm -f /usr/share/doc/netmon/docs/public-dns.md /usr/share/doc/netmon/docs/network.md /usr/share/doc/netmon/docs/cluster.md /usr/share/doc/netmon/docs/configuration.md /usr/share/doc/netmon/docs/operations.md /usr/share/doc/netmon/docs/development.md
rmdir /usr/share/doc/netmon/docs 2>/dev/null || true
rmdir /usr/share/doc/netmon 2>/dev/null || true
printf '%s\n' 'Uninstalled. Configuration, statistics and service accounts are preserved.' 'Paths: /etc/netmon and /var/lib/netmon (or your configured database path).'
