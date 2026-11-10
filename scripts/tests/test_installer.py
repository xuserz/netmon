"""Run the real install/rollback logic against a redirected temporary filesystem."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fake_bin = self.root / "commands"
        self.fake_bin.mkdir()
        self.state = self.root / "state"
        self.state.write_text("active")
        self.env = dict(os.environ, PATH=f"{self.fake_bin}:{os.environ['PATH']}",
                        TEST_ROOT=str(self.root), TEST_STATE=str(self.state))
        self.command("id", "#!/bin/sh\necho 0\n")
        self.command("getent", "#!/bin/sh\nexit 0\n")
        # Filesystem permissions are exercised by install itself; fake only the
        # account lookup so no host users/groups are needed or modified.
        self.command("install", """#!/usr/bin/env python3
import os, sys
args=sys.argv[1:]
for flag in ('-o','-g'):
 while flag in args:
  i=args.index(flag);del args[i:i+2]
os.execv('/usr/bin/install',['install']+args)
""")
        self.command("sleep", "#!/bin/sh\nexit 0\n")
        self.command("systemctl", """#!/bin/sh
case "$1" in
 is-active) [ "$(cat "$TEST_STATE")" = active ] ;;
 stop) echo stopped > "$TEST_STATE" ;;
 start)
  if grep -q 'new-bad' "$TEST_ROOT/usr/local/bin/dnsmon"; then
   echo failed > "$TEST_STATE"
   exit 1
  fi
  echo active > "$TEST_STATE" ;;
 *) exit 0 ;;
esac
""")
        for rel in ("usr/local/bin", "etc/dnsmon", "etc/systemd/system", "var/lib/dnsmon"):
            (self.root / rel).mkdir(parents=True)
        self.config = self.root / "etc/dnsmon/config.yaml"
        self.config.write_text("interface: ens3\nmax_database_mb: 20480\n")
        self.database = self.root / "var/lib/dnsmon/stats.db"
        self.database.write_bytes(b"statistics must be preserved")
        self.installed = self.root / "usr/local/bin/dnsmon"
        self.installed.write_text("#!/bin/sh\n# old-good\nexit 0\n")
        self.installed.chmod(0o755)
        self.unit = self.root / "etc/systemd/system/dnsmon.service"
        self.unit.write_text("old unit\n")
        project = self.root / "checkout"
        (project / "scripts").mkdir(parents=True)
        (project / "packaging").mkdir()
        for name in ("README.md", "dnsmon.yaml", "scripts/uninstall.sh", "scripts/install-release.sh", "packaging/dnsmon.service", "docs/configuration.md", "docs/operations.md", "docs/development.md"):
            (project / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, project / name)
        content = (ROOT / "scripts/install.sh").read_text()
        # Redirect only installation destinations, preserving all production
        # branching, preflight, health-check and rollback code.
        for prefix in ("/usr/local", "/usr/share", "/etc/dnsmon", "/etc/systemd", "/var/lib/dnsmon"):
            content = content.replace(prefix, str(self.root) + prefix)
        self.script = project / "scripts/install.sh"
        self.script.write_text(content)
        self.candidate = self.root / "candidate"

    def command(self, name, content):
        path = self.fake_bin / name
        path.write_text(content)
        path.chmod(0o755)

    def run_install(self, marker, preflight_ok=True):
        body = '#!/bin/sh\n# ' + marker + '\n'
        if not preflight_ok:
            body += 'case "$*" in *check*) exit 1;; esac\n'
        body += 'exit 0\n'
        self.candidate.write_text(body)
        self.candidate.chmod(0o755)
        return subprocess.run(["sh", str(self.script), str(self.candidate)], env=self.env,
                              capture_output=True, text=True)

    def assert_data_preserved(self):
        self.assertEqual(self.config.read_text(), "interface: ens3\nmax_database_mb: 20480\n")
        self.assertEqual(self.database.read_bytes(), b"statistics must be preserved")

    def test_successful_update_restarts_and_preserves_data(self):
        result = self.run_install("new-good")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("new-good", self.installed.read_text())
        self.assertTrue((self.root / "usr/share/doc/dnsmon/docs/configuration.md").is_file())
        self.assertTrue((self.root / "usr/share/doc/dnsmon/dnsmon.yaml").is_file())
        self.assertEqual(self.state.read_text().strip(), "active")
        self.assert_data_preserved()

    def test_failed_new_service_rolls_back_binary_and_unit(self):
        result = self.run_install("new-bad")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("old-good", self.installed.read_text())
        self.assertEqual(self.unit.read_text(), "old unit\n")
        self.assertEqual(self.state.read_text().strip(), "active")
        self.assert_data_preserved()
        self.assertIn("restoring", result.stderr)

    def test_failed_preflight_leaves_running_service_untouched(self):
        result = self.run_install("new-bad", preflight_ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("old-good", self.installed.read_text())
        self.assertEqual(self.state.read_text().strip(), "active")
        self.assert_data_preserved()

    def test_inactive_service_is_not_automatically_enabled(self):
        self.state.write_text("stopped")
        result = self.run_install("new-good")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.state.read_text(), "stopped")
        self.assert_data_preserved()

    def test_fresh_config_selects_route_interface_and_keeps_database(self):
        self.config.unlink()
        self.state.write_text("stopped")
        self.command("ip", "#!/bin/sh\necho '1.1.1.1 dev ens3 src 192.0.2.1'\n")
        result = self.run_install("new-good")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("interface: ens3", self.config.read_text())
        self.assertEqual(self.database.read_bytes(), b"statistics must be preserved")
        self.assertEqual(self.state.read_text(), "stopped")
