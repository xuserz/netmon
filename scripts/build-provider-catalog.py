#!/usr/bin/env python3
"""Build an offline catalog from a local upstream checkout. No network access."""
import argparse
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEFINITIONS = ROOT / "data/providers/manifest.json"
if not DEFINITIONS.exists():
    DEFINITIONS = Path("/usr/share/doc/netmon/provider-data-manifest.json")
REPOSITORY = "https://github.com/rezmoss/cloud-provider-ip-addresses"
KINDS = {"cloud", "cdn", "bot", "monitoring", "service", "relay", "vpn", "tor"}


def read_json(path):
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError(f"metadata too large: {path}")
    return json.loads(path.read_text())


def text(value, limit):
    return (isinstance(value, str) and 0 < len(value.encode()) <= limit
            and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value))


def build(source, definitions, revision):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("revision must be the upstream 40-character Git commit")
    if "CC0" not in (source / "LICENSE").read_text():
        raise ValueError("upstream CC0 license missing")
    summary = read_json(source / "summary.json")
    date = summary["generated"][:10]
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise ValueError("invalid snapshot date")
    ids = sorted(summary["providers"])
    if not ids or len(ids) > 128 or len(ids) != summary["provider_count"]:
        raise ValueError("invalid provider count")
    known = {p["id"]: p for p in read_json(definitions)["providers"]}
    providers, count = [], 0
    for ident in ids:
        if not re.fullmatch(r"[a-z0-9_]{1,64}", ident):
            raise ValueError("invalid provider ID")
        if ident not in known:
            raise ValueError(f"review new provider {ident}: add name/category to --definitions")
        definition = known[ident]
        meta = read_json(source / ident / f"{ident}_meta.json")
        if (meta["provider"] != ident or meta["generated_date"] != date
                or meta["license"] != "CC0-1.0"):
            raise ValueError(f"inconsistent metadata: {ident}")
        if (not text(definition["name"], 128) or definition["category"] not in KINDS
                or not isinstance(meta["sources"], list) or len(meta["sources"]) > 32
                or not all(text(s, 2048) for s in meta["sources"])):
            raise ValueError(f"invalid provider definition: {ident}")
        ranges = source / ident / f"{ident}_ips_merged.txt"
        if ranges.stat().st_size > 8 * 1024 * 1024:
            raise ValueError(f"range file too large: {ident}")
        prefixes = []
        for line in ranges.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            prefix = ipaddress.ip_network(line, strict=True)
            if prefix.prefixlen == 0 or "%" in line or getattr(prefix.network_address, "ipv4_mapped", None):
                raise ValueError(f"invalid prefix: {line}")
            prefixes.append(str(prefix))
        expected = meta["ipv4"]["merged_cidrs"] + meta["ipv6"]["merged_cidrs"]
        if len(prefixes) != expected or len(set(prefixes)) != len(prefixes):
            raise ValueError(f"missing/duplicate ranges: {ident}")
        count += len(prefixes)
        if count > 250000:
            raise ValueError("prefix limit exceeded")
        providers.append(dict(id=ident, name=definition["name"], category=definition["category"],
                              generated=date, sources=meta["sources"], prefixes=prefixes))
    catalog = dict(format=1, repository=REPOSITORY, revision=revision, generated=date,
                   license="CC0-1.0", providers=providers)
    raw = json.dumps(catalog, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError("expanded catalog limit exceeded")
    packed = bytearray(gzip.compress(raw, compresslevel=9, mtime=0))
    packed[9] = 255  # Portable gzip OS byte, including Python 3.11/3.12.
    if len(packed) > 8 * 1024 * 1024:
        raise ValueError("compressed catalog limit exceeded")
    manifest = {k: v for k, v in catalog.items() if k != "providers"}
    manifest.update(prefix_count=count, catalog_sha256=hashlib.sha256(packed).hexdigest(),
                    providers=[{k: v for k, v in p.items() if k != "prefixes"}
                               | {"prefix_count": len(p["prefixes"])} for p in providers])
    return packed, manifest


def atomic_write(path, data):
    # Root-managed distribution asset. Keep custom catalogs outside this path.
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".providers-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), 0o644)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--definitions", type=Path, default=DEFINITIONS)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    try:
        # Validate all inputs before replacing either output.
        packed, manifest = build(args.source_dir, args.definitions, args.revision)
        if args.manifest and args.output.resolve() == args.manifest.resolve():
            raise ValueError("catalog and manifest output paths must differ")
        atomic_write(args.output, packed)
        if args.manifest:
            atomic_write(args.manifest, (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode())
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(1, f"provider catalog: {exc}\n")
    print(f"{len(manifest['providers'])} providers; {manifest['prefix_count']} prefixes; {len(packed)} bytes")


if __name__ == "__main__":
    main()
