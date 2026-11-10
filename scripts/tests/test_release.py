"""Exercise release downloads without root, networking, or host installation."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReleaseInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.fake_bin = self.work / "commands"
        self.fake_bin.mkdir()
        self.assets = self.work / "assets"
        self.assets.mkdir()
        self.marker = self.work / "installed"
        self.log = self.work / "downloads.jsonl"
        self.env = dict(os.environ, PATH=f"{self.fake_bin}:{os.environ['PATH']}",
                        NETMON_REPOSITORY="test-owner/netmon", NETMON_VERSION="latest",
                        NETMON_TEST_MACHINE="x86_64", NETMON_TEST_OS="Linux",
                        NETMON_TEST_UID="0", NETMON_TEST_ASSETS=str(self.assets),
                        NETMON_TEST_MARKER=str(self.marker), NETMON_TEST_LOG=str(self.log))
        self.command("id", '#!/bin/sh\nprintf "%s\\n" "$NETMON_TEST_UID"\n')
        self.command("uname", '#!/bin/sh\ncase "$1" in -s) echo "$NETMON_TEST_OS";; -m) echo "$NETMON_TEST_MACHINE";; esac\n')
        self.command("curl", """#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
args = sys.argv[1:]
url = args[-1]
with open(os.environ['NETMON_TEST_LOG'], 'a') as f:
    f.write(json.dumps(args) + '\\n')
if '--head' in args:
    print('https://github.com/test-owner/netmon/releases/tag/build-12-1-abcdef12', end='')
else:
    output = pathlib.Path(args[args.index('--output') + 1])
    source = pathlib.Path(os.environ['NETMON_TEST_ASSETS']) / url.rsplit('/', 1)[1]
    if not source.exists():
        sys.exit(22)
    shutil.copyfile(source, output)
""")
        self.bundle("amd64")
        self.bundle("arm64")
        self.checksums()

    def command(self, name, content):
        path = self.fake_bin / name
        path.write_text(content)
        path.chmod(0o755)

    def bundle(self, arch):
        with tarfile.open(self.assets / f"netmon_linux_{arch}.tar.gz", "w:gz") as archive:
            files = {
                "bin/netmon": b"bundled executable fixture\n",
                "scripts/install.sh": b'#!/bin/sh\nset -eu\n[ -f "$1" ]\nprintf "%s\\n" "$1" > "$NETMON_TEST_MARKER"\n',
            }
            for name, content in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mode = 0o755
                archive.addfile(info, io.BytesIO(content))

    def checksums(self):
        lines = []
        for path in sorted(self.assets.glob("*.tar.gz")):
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
        (self.assets / "SHA256SUMS").write_text("".join(lines))

    def run_installer(self, env=None, script=None, args=(), success=True):
        result = subprocess.run(["sh", str(script or ROOT / "scripts/install-release.sh"), *args],
                                env=self.env | (env or {}), capture_output=True, text=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(self.marker.exists(), result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertFalse(self.marker.exists())
        return result

    def test_latest_resolves_once_and_pins_all_downloads(self):
        self.run_installer()
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(len(calls), 3)
        self.assertTrue(calls[0][-1].endswith("/releases/latest"))
        self.assertTrue(all("/download/build-12-1-abcdef12/" in call[-1] for call in calls[1:]))
        self.assertIn("netmon_linux_amd64.tar.gz", calls[1][-1])

    def test_explicit_release_and_arm64(self):
        self.run_installer({"NETMON_VERSION": "build-9-1-12345678", "NETMON_TEST_MACHINE": "aarch64"})
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(len(calls), 2)
        self.assertIn("/build-9-1-12345678/netmon_linux_arm64.tar.gz", calls[0][-1])

    def test_checksum_failure_never_runs_install(self):
        with (self.assets / "netmon_linux_amd64.tar.gz").open("ab") as file:
            file.write(b"corruption")
        result = self.run_installer(success=False)
        self.assertIn("SHA-256 mismatch", result.stderr)

    def test_duplicate_or_missing_checksum_is_rejected(self):
        manifest = self.assets / "SHA256SUMS"
        original = manifest.read_text()
        for content in ("", original + original):
            with self.subTest(content=content):
                manifest.write_text(content)
                self.run_installer(success=False)

    def test_unrelated_checksum_paths_are_ignored(self):
        with (self.assets / "SHA256SUMS").open("a") as file:
            file.write("0" * 64 + "  /this/path/must/never/be/read\n")
        self.run_installer()

    def test_download_failure_never_runs_install(self):
        (self.assets / "netmon_linux_amd64.tar.gz").unlink()
        result = self.run_installer(success=False)
        self.assertIn("Could not download", result.stderr)

    def test_invalid_platform_repository_or_version(self):
        for env in ({"NETMON_TEST_MACHINE": "i686"}, {"NETMON_TEST_OS": "Darwin"},
                    {"NETMON_REPOSITORY": "../repo"}, {"NETMON_REPOSITORY": "owner/repo/extra"},
                    {"NETMON_VERSION": "../bad"}, {"NETMON_TEST_UID": "1000"}):
            with self.subTest(env=env):
                self.run_installer(env, success=False)
        self.assertFalse(self.log.exists())

    def test_source_installer_without_binary_downloads_release(self):
        project = self.work / "checkout"
        scripts = project / "scripts"
        scripts.mkdir(parents=True)
        for name in ("install.sh", "install-release.sh"):
            shutil.copyfile(ROOT / "scripts" / name, scripts / name)
        self.run_installer(script=scripts / "install.sh")

    def test_release_flag_ignores_local_binary(self):
        project = self.work / "checkout"
        scripts = project / "scripts"
        scripts.mkdir(parents=True)
        for name in ("install.sh", "install-release.sh"):
            shutil.copyfile(ROOT / "scripts" / name, scripts / name)
        (project / "bin").mkdir()
        binary = project / "bin/netmon"
        binary.write_text("#!/bin/sh\nexit 99\n")
        binary.chmod(0o755)
        self.run_installer(script=scripts / "install.sh", args=("--release",))

    def test_missing_explicit_binary_does_not_download(self):
        result = self.run_installer(script=ROOT / "scripts/install.sh",
                                    args=(str(self.work / "missing-binary"),), success=False)
        self.assertIn("not executable", result.stderr)
        self.assertFalse(self.log.exists())


class PackagingTests(unittest.TestCase):
    def test_bundle_contains_all_installer_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scripts = root / "scripts"
            scripts.mkdir()
            shutil.copyfile(ROOT / "scripts/package-release.sh", scripts / "package-release.sh")
            inputs = ["bin/netmon", "netmon.yaml", "packaging/netmon.service", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "CHANGELOG.md", "CONTRIBUTING.md",
                      "scripts/install.sh", "scripts/migrate-dnsmon.sh", "scripts/uninstall.sh", "scripts/install-release.sh",
                      "docs/configuration.md", "docs/operations.md", "docs/development.md", "docs/cluster.md", "docs/network.md"]
            for name in inputs:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n")
                path.chmod(0o755)
            result = subprocess.run(["sh", str(scripts / "package-release.sh"), "amd64", str(root / "dist")],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            with tarfile.open(root / "dist/netmon_linux_amd64.tar.gz") as archive:
                self.assertEqual(sorted(archive.getnames()), sorted(inputs))


if __name__ == "__main__":
    unittest.main()
