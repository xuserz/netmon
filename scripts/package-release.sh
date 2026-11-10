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
if [ ! -x "$project_dir/bin/dnsmon" ]; then
  echo 'Build the binary first: make static' >&2
  exit 1
fi
mkdir -p -- "$2"
output_dir=$(CDPATH= cd -- "$2" && pwd)
archive="$output_dir/dnsmon_linux_$arch.tar.gz"
tar -C "$project_dir" -czf "$archive" \
  bin/dnsmon dnsmon.yaml packaging/dnsmon.service README.md \
  scripts/install.sh scripts/uninstall.sh scripts/install-release.sh \
  docs/configuration.md docs/operations.md docs/development.md
printf '%s\n' "$archive"
