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
case "$*" in *dnsmon.service*) exit 3;; esac
case "$1" in
 is-active) [ "$(cat "$TEST_STATE")" = active ] ;;
 stop) echo stopped > "$TEST_STATE" ;;
 reset-failed)
  if [ "$(cat "$TEST_STATE")" = stopped ]; then
   echo 'Failed to reset failed state of unit netmon.service: Unit netmon.service not loaded.' >&2
   exit 1
  fi ;;
 start)
  if grep -q 'new-bad' "$TEST_ROOT/usr/local/bin/netmon"; then
   echo failed > "$TEST_STATE"
   exit 1
  fi
  echo active > "$TEST_STATE" ;;
 *) exit 0 ;;
esac
""")
        for rel in ("usr/local/bin", "etc/netmon", "etc/systemd/system", "var/lib/netmon"):
            (self.root / rel).mkdir(parents=True)
        self.config = self.root / "etc/netmon/config.yaml"
        self.config.write_text("interface: ens3\nmax_database_mb: 20480\n")
        self.database = self.root / "var/lib/netmon/stats.db"
        self.database.write_bytes(b"statistics must be preserved")
        self.installed = self.root / "usr/local/bin/netmon"
        self.installed.write_text("#!/bin/sh\n# old-good\nexit 0\n")
        self.installed.chmod(0o755)
        self.unit = self.root / "etc/systemd/system/netmon.service"
        self.unit.write_text("old unit\n")
        project = self.root / "checkout"
        (project / "scripts").mkdir(parents=True)
        (project / "packaging").mkdir()
        for name in ("README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "CHANGELOG.md", "CONTRIBUTING.md", "netmon.yaml", "ip-labels.yaml", "scripts/migrate-dnsmon.sh", "scripts/uninstall.sh", "scripts/install-release.sh", "packaging/netmon.service", "docs/configuration.md", "docs/operations.md", "docs/development.md", "docs/cluster.md", "docs/network.md", "docs/public-dns.md"):
            (project / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, project / name)
        content = (ROOT / "scripts/install.sh").read_text()
        # Redirect only installation destinations, preserving all production
        # branching, preflight, health-check and rollback code.
        for prefix in ("/usr/local", "/usr/share", "/etc/netmon", "/etc/dnsmon", "/etc/systemd", "/var/lib/netmon", "/var/lib/dnsmon"):
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
        self.assertTrue((self.root / "usr/share/doc/netmon/docs/configuration.md").is_file())
        self.assertTrue((self.root / "usr/share/doc/netmon/docs/public-dns.md").is_file())
        self.assertEqual((self.root / "etc/netmon/ip-labels.yaml").read_bytes(), (ROOT / "ip-labels.yaml").read_bytes())
        self.assertTrue((self.root / "usr/share/doc/netmon/netmon.yaml").is_file())
        self.assertEqual((self.root / "usr/share/doc/netmon/LICENSE").read_text(), (ROOT / "LICENSE").read_text())
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

    def prepare_legacy(self, active=True, enabled=True):
        self.config.unlink()
        self.unit.unlink()
        self.installed.unlink()
        self.state.write_text("stopped")
        self.legacy_state = self.root / "legacy-state"
        self.legacy_state.write_text("active" if active else "stopped")
        self.legacy_enabled = self.root / "legacy-enabled"
        self.legacy_enabled.write_text("1" if enabled else "0")
        self.new_enabled = self.root / "netmon-enabled"
        self.new_enabled.write_text("0")
        self.command("systemctl", """#!/bin/sh
legacy=0
case "$*" in *dnsmon.service*) legacy=1;; esac
state="$TEST_STATE"
enabled="$TEST_ROOT/netmon-enabled"
if [ "$legacy" -eq 1 ]; then state="$TEST_ROOT/legacy-state"; enabled="$TEST_ROOT/legacy-enabled"; fi
case "$1" in
 is-active) [ "$(cat "$state")" = active ];;
 is-enabled) [ "$(cat "$enabled")" = 1 ];;
 stop) echo stopped > "$state";;
 reset-failed)
  if [ "$(cat "$state")" = stopped ]; then
   echo 'Failed to reset failed state of unit: Unit not loaded.' >&2
   exit 1
  fi;;
 start)
  if [ "$legacy" -eq 0 ] && grep -q new-bad "$TEST_ROOT/usr/local/bin/netmon"; then echo failed > "$state"; exit 1; fi
  echo active > "$state";;
 enable) echo 1 > "$enabled";;
 disable) echo 0 > "$enabled";;
 *) exit 0;;
esac
""")
        (self.root / "etc/dnsmon").mkdir()
        (self.root / "var/lib/dnsmon").mkdir()
        self.old_config = self.root / "etc/dnsmon/config.yaml"
        self.old_config.write_text("interface: ens3\nmax_database_mb: 20480\n")
        self.old_database = self.root / "var/lib/dnsmon/stats.db.network.db"
        self.old_database.write_bytes(b"old network database and identity")
        self.old_key = self.root / "etc/dnsmon/cluster.key"
        self.old_key.write_bytes(b"existing cluster key")
        self.old_binary = self.root / "usr/local/bin/dnsmon"
        self.old_binary.write_text("#!/bin/sh\n# old-good\nexit 0\n")
        self.old_binary.chmod(0o755)
        self.old_unit = self.root / "etc/systemd/system/dnsmon.service"
        unit = (ROOT / "packaging/netmon.service").read_text().replace("netmon", "dnsmon")
        unit = unit.replace("/usr/local", str(self.root) + "/usr/local").replace("/etc/dnsmon", str(self.root) + "/etc/dnsmon")
        self.old_unit.write_text(unit)
        project = self.script.parents[1]
        for name in ("install.sh", "migrate-dnsmon.sh"):
            content = (ROOT / "scripts" / name).read_text()
            for prefix in ("/usr/local", "/usr/share", "/etc/netmon", "/etc/dnsmon", "/etc/systemd", "/var/lib/netmon", "/var/lib/dnsmon"):
                content = content.replace(prefix, str(self.root) + prefix)
            (project / "scripts" / name).write_text(content)

    def run_migration(self, bad=False, invalid=False):
        body = '#!/bin/sh\n# ' + ('new-bad' if bad else 'new-good') + '\n'
        body += 'if [ "$1" = migrate-config ]; then\n'
        if invalid:
            body += 'exit 1\n'
        else:
            text = f"interface: ens3\ndatabase: {self.root}/var/lib/dnsmon/stats.db\nnetwork:\n  runtime_directory: /run/dnsmon\n"
            body += "cat <<'CONFIG'\n" + text + "CONFIG\nexit 0\n"
        body += 'fi\nexit 0\n'
        self.candidate.write_text(body)
        self.candidate.chmod(0o755)
        return subprocess.run(["sh", str(self.script), str(self.candidate)], env=self.env, capture_output=True, text=True)

    def assert_legacy_data_untouched(self):
        self.assertEqual(self.old_config.read_text(), "interface: ens3\nmax_database_mb: 20480\n")
        self.assertEqual(self.old_database.read_bytes(), b"old network database and identity")
        self.assertEqual(self.old_key.read_bytes(), b"existing cluster key")
        self.assertIn("old-good", self.old_binary.read_text())

    def test_legacy_migration_transfers_service_and_preserves_data_and_account(self):
        self.prepare_legacy()
        original_unit = self.old_unit.read_bytes()
        result = self.run_migration()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.legacy_state.read_text().strip(), "stopped")
        self.assertEqual(self.state.read_text().strip(), "active")
        self.assertEqual(self.legacy_enabled.read_text().strip(), "0")
        self.assertEqual(self.new_enabled.read_text().strip(), "1")
        self.assertIn("User=dnsmon", self.unit.read_text())
        self.assertIn("RuntimeDirectory=dnsmon", self.unit.read_text())
        self.assertNotIn("For a new installation", result.stdout)
        self.assertIn("/var/lib/dnsmon/stats.db", self.config.read_text())
        self.assertEqual(self.old_unit.read_bytes(), original_unit)
        self.assert_legacy_data_untouched()
        # A subsequent normal update must retain permissions on the old data.
        result = self.run_install("new-good-update")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("User=dnsmon", self.unit.read_text())
        self.assert_legacy_data_untouched()

    def test_legacy_migration_failure_restarts_original_service(self):
        self.prepare_legacy()
        result = self.run_migration(bad=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("restoring the previous dnsmon.service", result.stderr)
        self.assertEqual(self.legacy_state.read_text().strip(), "active")
        self.assertEqual(self.legacy_enabled.read_text().strip(), "1")
        for path in (self.unit, self.config, self.installed):
            self.assertFalse(path.exists(), str(path))
        self.assert_legacy_data_untouched()

    def test_legacy_migration_invalid_config_does_not_stop_old_service(self):
        self.prepare_legacy()
        result = self.run_migration(invalid=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.legacy_state.read_text().strip(), "active")
        self.assertFalse(self.config.exists())
        self.assert_legacy_data_untouched()

    def test_legacy_inactive_service_stays_inactive_after_migration(self):
        self.prepare_legacy(active=False, enabled=True)
        result = self.run_migration()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.state.read_text().strip(), "stopped")
        self.assertEqual(self.new_enabled.read_text().strip(), "1")
        self.assert_legacy_data_untouched()

    def test_existing_config_and_active_legacy_service_cannot_start_two_monitors(self):
        self.prepare_legacy()
        self.config.write_text("interface: lo\n")
        result = self.run_migration()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("still active", result.stderr)
        self.assertEqual(self.legacy_state.read_text().strip(), "active")
        self.assertFalse(self.installed.exists())
        self.assert_legacy_data_untouched()

    def test_custom_legacy_command_requires_manual_migration(self):
        self.prepare_legacy()
        overrides = self.old_unit.parent / "dnsmon.service.d"
        overrides.mkdir()
        (overrides / "command.conf").write_text("[Service]\nExecStart=custom-command\n")
        result = self.run_migration()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manual migration", result.stderr)
        self.assertFalse(self.config.exists())
        self.assertEqual(self.legacy_state.read_text().strip(), "active")
        self.assert_legacy_data_untouched()

    def test_failed_migration_can_be_retried_without_deleting_recovery_artifacts(self):
        self.prepare_legacy()
        failed = self.run_migration(bad=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(self.legacy_state.read_text().strip(), "active")
        self.assert_legacy_data_untouched()
        retried = self.run_migration()
        self.assertEqual(retried.returncode, 0, retried.stdout + retried.stderr)
        self.assertEqual(self.state.read_text().strip(), "active")
        self.assertEqual(self.legacy_state.read_text().strip(), "stopped")
        self.assert_legacy_data_untouched()

    def test_existing_ip_labels_are_preserved_during_update(self):
        labels = self.root / "etc/netmon/ip-labels.yaml"
        original = "whitelist:\n  - ip: 192.0.2.1\n    description: My monitor\nservers: []\n"
        labels.write_text(original)
        result = self.run_install("new-good")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(labels.read_text(), original)
