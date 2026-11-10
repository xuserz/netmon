# Cluster updates

[Back to README](../README.md)

Updating one node can announce that exact signed release to the rest of a network
cluster. Nodes with automatic application enabled download their architecture's
archive directly from `xuserz/netmon`, verify its publisher signature and SHA-256,
then install it. No SSH access between servers or Go installation is required.
There is no periodic poll of GitHub's latest release: the trigger is a verified
release offer received through authenticated cluster traffic.

## First-time setup

**Install a release containing this feature manually on every participating
server once.** Older binaries do not contain the update service or verifier.
The release installer installs the public key, update units and any verified
release metadata. Existing configs, keys, identities and databases are retained.

Choose one reachable **full** node as the update coordinator. Its configured
`cluster.advertise` URL must match `updates.coordinator`. Set the same coordinator
URL on all nodes, including the coordinator itself:

```yaml
updates:
  automatic: true
  propagate: true
  coordinator: https://192.0.2.10:9845
  public_key: /etc/netmon/update-public-key
```

Use your actual coordinator address. On each server:

```sh
sudo netmon check --startup
sudo systemctl restart netmon
sudo systemctl enable --now netmon-update.timer
netmon updates status
```

`automatic` defaults to **false**; `propagate` defaults to true. A node may announce
updates without applying them. The timer is installed but not enabled by the
installer. Editing update settings requires restarting the monitor; the timer
reads them on every run. A disabled automatic flag makes the timer a no-op.

Now update any seed node normally:

```sh
sudo /usr/local/libexec/netmon/install-release.sh
```

Its signed manifest is advertised after restart. Other updated-capable nodes
relay the newest valid offer and check for application about once a minute,
with up to 20 seconds of jitter. CI run/attempt identifiers order builds. Replayed older releases and arbitrary
version strings cannot cause automatic downgrades.

## Installation order and failure behavior

The coordinator grants one installation lease at a time, serializing automatic
updates of both full and forward nodes. Downloads and verification happen before
taking the lease, while capture continues. The monitor retains its restricted
service account; a separate root oneshot performs installation.

An update waits for a fresh live monitor snapshot, a drained delivery queue and
healthy synchronization. A full node also needs another online full peer with
no known synchronization error and a caught-up pull cursor. This is an operational
readiness check, not proof that every last packet has reached every replica.
**A single full node is updated manually**; its forward sensors can still update
automatically. A coordinator without automatic application can remain a manual
seed while permitting the other nodes to update.

The coordinator refuses new leases for **15 minutes after any restart**. This
protects a lease that might have existed before its process restarted. A crashed
updater's lease expires after 15 minutes. If the coordinator is unreachable,
automatic installation waits. This is a bounded lease protocol for ordinary
crashes/outages, not a consensus system with external fencing for arbitrarily
long VM suspension. Manual installations do not acquire a cluster lease; avoid
starting several manual storage-node updates during an automatic rollout.

The helper has a 10-minute overall budget and a 5-minute installer budget;
systemd terminates its process group after 12 minutes. The installer checks
preflight before stopping a service and requires ten successful live health
checks after an automatic restart. Failed startup attempts restore the previous
executable and main unit and attempt to restart them. Interrupted installations
may still need operator recovery; inspect the journal and service state.

Failed/interrupted target versions are recorded **before** invoking the installer
and are not retried on each timer tick. After investigating a failure:

```sh
sudo netmon updates apply --retry
```

Downloads, signature failures and unavailable coordinators remain in a waiting
state and may retry on the next timer tick. To pause local automatic updates:

```sh
sudo systemctl disable --now netmon-update.timer
```

`systemctl stop netmon-update.service` also cancels an active helper. Emergency
cluster-wide installation pause: clear `updates.coordinator` and disable
`updates.automatic` on the coordinator, then restart its monitor. It will refuse
new lease grants; an already granted installation may finish.

## Diagnostics and storage

```sh
netmon updates status
netmon nodes
netmon nodes --json
netmon top --nodes
systemctl list-timers netmon-update.timer
journalctl -u netmon-update.service --no-pager
```

Node diagnostics include binary versions and the last reported update target,
state and error. Presence/version observations remain local and expire with
contacts; offline nodes cannot be commanded remotely.

The updater uses `/var/lib/netmon-updater` for a small root-owned status record
and temporary staging files. Staging is removed when a normal run exits; a hard
crash can leave `.download-*` directories to remove after stopping the helper.
This applies to forward nodes too: their **monitor still opens no statistics DB
or observation spool**, but optional administrative updates need temporary disk
space. Allow several hundred MiB of free staging space plus the installed binary.
The updater's state, public key and installed manifest are administrative files,
not replicated statistics. Uninstall preserves keys/config and updater state.

## Publisher setup and compatibility

Releases contain `update.json` and `update.json.sig`, with an Ed25519 signature
over the exact manifest bytes and a netmon-specific domain prefix. The manifest
pins repository, version, compatibility, both architecture hashes and sizes,
and permission for automatic application. A shared cluster key cannot sign a
release. The root helper builds its download URL itself; peers cannot provide
shell commands, repository names or arbitrary download URLs.

The initial private seed was generated locally at `.netmon-signing/release.seed`
and is ignored by Git. Add its **contents** as the repository Actions secret
`NETMON_UPDATE_SIGNING_KEY`; only `packaging/update-public-key` is committed.
GitHub's [secret setup instructions](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets)
describe the Settings → Secrets and variables → Actions UI. Never place the seed
in YAML, a commit, an issue or a build log. Keep a private backup.

Without that secret, CI still publishes ordinary manual-install releases and
emits a warning; these releases cannot seed an automatic rollout. When configured,
`cmd/release-sign` checks that the signing seed matches the committed public key
and signs the actual built archives. A mismatched key fails publication.

The maintainer declares compatibility in `packaging/update-policy.json` and
`internal/release.Compatibility`. Incompatible storage/protocol migrations must
use `automatic: false` and a new compatibility identifier. This is an explicit
maintainer contract; the updater cannot infer whether arbitrary future code
changes or migrations are reversible. Such releases remain visible as offers
but require manual installation. Trust-key rotation likewise requires an
explicit update of the trusted key on each host; installers preserve an existing
`/etc/netmon/update-public-key`.

The first manual installation bootstraps trust from the chosen GitHub release.
Later automatic installations require the locally pinned public key. Config/key
files and their parent directories must be owned by root and not writable by
group/others. Custom setups outside those constraints require manual updates.
