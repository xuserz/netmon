#!/bin/sh
# Standalone bootstrap: no checkout, Go, Python, jq or GitHub CLI required.
set -eu
fail() { printf 'dnsmon: %s\n' "$*" >&2; exit 1; }
if [ "$(id -u)" -ne 0 ]; then fail 'Run as root, or pipe this script into sudo sh.'; fi
if [ "$#" -ne 0 ]; then fail 'No arguments expected. Use DNSMON_VERSION=TAG to select a release.'; fi
for tool in curl tar sha256sum awk mktemp uname; do
  command -v "$tool" >/dev/null 2>&1 || fail "Missing $tool. On Debian/Ubuntu: apt install curl ca-certificates tar coreutils"
done
[ "$(uname -s)" = Linux ] || fail 'Only Linux is supported.'
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) fail "Unsupported architecture: $(uname -m) (available: amd64, arm64)" ;;
esac
repository=${DNSMON_REPOSITORY:-xuserz/dnsmon}
case "$repository" in
  ''|*[!A-Za-z0-9_./-]*|/*|*/|*/*/*|*..*) fail 'DNSMON_REPOSITORY must be OWNER/REPO.' ;;
  */*) ;;
  *) fail 'DNSMON_REPOSITORY must be OWNER/REPO.' ;;
esac
version=${DNSMON_VERSION:-latest}
# Pin the redirect once: a new release during download cannot mix bundles and checksums.
if [ "$version" = latest ]; then
  release_url=$(curl --fail --silent --show-error --location --head --retry 3 \
    --connect-timeout 15 --max-time 120 --proto '=https' --proto-redir '=https' \
    --output /dev/null --write-out '%{url_effective}' \
    "https://github.com/$repository/releases/latest") || fail 'No release found. Wait for the GitHub Actions workflow to publish one, then retry.'
  case "$release_url" in
    "https://github.com/$repository/releases/tag/"*) version=${release_url##*/} ;;
    *) fail 'GitHub did not return a release URL. Is the repository public and does it have a published release?' ;;
  esac
fi
case "$version" in ''|*[!A-Za-z0-9._+-]*|.|..) fail 'Invalid release tag.' ;; esac
asset="dnsmon_linux_$arch.tar.gz"
base_url="https://github.com/$repository/releases/download/$version"
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
trap 'exit 1' HUP INT TERM
printf 'Downloading dnsmon %s for Linux %s...\n' "$version" "$arch"
for file in "$asset" SHA256SUMS; do
  curl --fail --silent --show-error --location --retry 3 \
    --connect-timeout 15 --max-time 300 --proto '=https' --proto-redir '=https' \
    --output "$work_dir/$file" "$base_url/$file" || fail "Could not download $file from release $version."
done
# Verify only the selected archive, never arbitrary paths from a remote manifest.
awk -v filename="$asset" '$2 == filename && NF == 2 { print; found++ } END { if (found != 1) exit 1 }' \
  "$work_dir/SHA256SUMS" > "$work_dir/selected.sha256" || fail "Missing or duplicate checksum for $asset."
(cd "$work_dir" && sha256sum --check --status selected.sha256) || fail 'SHA-256 mismatch; nothing was installed. Retry the download.'
mkdir "$work_dir/bundle"
tar -xzf "$work_dir/$asset" -C "$work_dir/bundle" --no-same-owner
sh "$work_dir/bundle/scripts/install.sh" "$work_dir/bundle/bin/dnsmon"
printf 'Installed release: %s\n' "$version"
