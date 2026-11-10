#!/bin/sh
# Build first with make static. This script only packages existing files.
set -eu
if [ "$#" -ne 2 ]; then
  echo 'Usage: package-release.sh amd64|arm64 OUTPUT_DIRECTORY' >&2
  exit 1
fi
arch=$1
case "$arch" in amd64|arm64) ;; *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; esac
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ ! -x "$project_dir/bin/netmon" ]; then
  echo 'Build the binary first: make static' >&2
  exit 1
fi
mkdir -p -- "$2"
output_dir=$(CDPATH= cd -- "$2" && pwd)
archive="$output_dir/netmon_linux_$arch.tar.gz"
tar -C "$project_dir" -czf "$archive" \
  bin/netmon netmon.yaml ip-labels.yaml packaging/netmon.service README.md LICENSE THIRD_PARTY_NOTICES.md CHANGELOG.md CONTRIBUTING.md \
  scripts/install.sh scripts/migrate-dnsmon.sh scripts/uninstall.sh scripts/install-release.sh scripts/build-provider-catalog.py \
  data/providers/catalog.json.gz data/providers/manifest.json data/providers/LICENSE \
  packaging/update-public-key packaging/update-policy.json packaging/netmon-update.service packaging/netmon-update.timer \
  docs/forensics.md docs/updates.md docs/providers.md docs/public-dns.md docs/configuration.md docs/operations.md docs/development.md docs/network.md docs/cluster.md
printf '%s\n' "$archive"
