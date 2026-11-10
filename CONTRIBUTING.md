# Contributing to netmon

Bug reports and pull requests are welcome. For bugs, include `netmon version`,
your Linux architecture, relevant configuration and logs, and reproduction steps.
Remove real client IPs and other sensitive information before sharing output.

For changes:

1. Describe the problem and keep the pull request focused.
2. Use `gofmt` and add regression tests for counting, concurrency, or lifecycle changes.
3. Run `make check`, `make build`, and `python3 -m unittest discover -s scripts/tests -v`.
   Report skipped integration tests and the commands you ran.
4. Update relevant documentation and the **Unreleased** section of [CHANGELOG.md](CHANGELOG.md).

Preserve bounded memory, replay-safe counters, and bounded synchronization work.
Network mode must keep forward nodes free of SQLite/disk spools and expose
overflow failures. Rating changes need deterministic evidence/decay tests. Keep
the legacy DNS `clients` table at exactly four fields. Do not persist domains,
individual queries, payloads, or packet captures.
Avoid additional runtime dependencies unless the change justifies them.

See the [development guide](docs/development.md) for network tests, fuzzing,
static builds, load tests, and the automatic release process. Changes must pass
CI before release. Contributions are provided under the project's [MIT License](LICENSE).
