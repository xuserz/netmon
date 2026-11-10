#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then echo 'Run as root: sudo ./scripts/uninstall.sh' >&2; exit 1; fi
if [ "$#" -ne 0 ]; then echo 'Usage: uninstall.sh (data is always preserved)' >&2; exit 1; fi
systemctl disable --now dnsmon.service
rm -f /etc/systemd/system/dnsmon.service /usr/local/bin/dnsmon
systemctl daemon-reload
rm -f /usr/local/libexec/dnsmon/install-release.sh /usr/local/libexec/dnsmon/uninstall.sh
rmdir /usr/local/libexec/dnsmon 2>/dev/null || true
rm -f /usr/share/doc/dnsmon/README.md
rmdir /usr/share/doc/dnsmon 2>/dev/null || true
printf '%s\n' 'Uninstalled. Configuration, statistics and the dnsmon system account are preserved.' 'Paths: /etc/dnsmon and /var/lib/dnsmon (or your configured database path).'
