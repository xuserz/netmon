"""Offline provider catalog builds: reproducibility, validation and packaging data."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
REVISION = "a" * 40


class ProviderCatalogBuildTests(unittest.TestCase):
    def test_reproducible_local_build_keeps_categories_and_rejects_partial_data(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            source = work / "upstream"
            source.mkdir()
            (source / "LICENSE").write_text("CC0 fixture")
            (source / "summary.json").write_text(json.dumps(dict(
                generated="2026-11-10T02:00:00", provider_count=2,
                providers={"cloudflare": {}, "tor": {}})))
            for ident, ranges in {"cloudflare": ["104.16.0.0/13", "2606:4700::/32"],
                                  "tor": ["104.16.1.2/32"]}.items():
                dest = source / ident
                dest.mkdir()
                (dest / f"{ident}_ips_merged.txt").write_text("\n".join(ranges) + "\n")
                (dest / f"{ident}_meta.json").write_text(json.dumps(dict(
                    provider=ident, generated_date="2026-11-10", license="CC0-1.0",
                    sources=["https://example.com/ranges"],
                    ipv4={"merged_cidrs": 1}, ipv6={"merged_cidrs": len(ranges) - 1})))
            output, manifest = work / "catalog.gz", work / "manifest.json"
            args = ["python3", str(ROOT / "scripts/build-provider-catalog.py"),
                    "--source-dir", str(source), "--revision", REVISION,
                    "--output", str(output), "--manifest", str(manifest)]
            first = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            packed = output.read_bytes()
            second = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(output.read_bytes(), packed)
            catalog = json.loads(gzip.decompress(packed))
            self.assertEqual([p["category"] for p in catalog["providers"]], ["cdn", "tor"])
            self.assertEqual(catalog["revision"], REVISION)
            meta = json.loads(manifest.read_text())
            self.assertEqual(meta["prefix_count"], 3)
            self.assertEqual(meta["catalog_sha256"], hashlib.sha256(packed).hexdigest())
            (source / "tor/tor_ips_merged.txt").unlink()
            failed = subprocess.run(args, capture_output=True, text=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(output.read_bytes(), packed)


if __name__ == "__main__":
    unittest.main()
