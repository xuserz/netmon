# Project constraints

- Keep netmon self-contained and lightweight for small Linux servers.
- The user explicitly excludes Grafana, Prometheus and similar external
  monitoring stacks. Implement inspection, correlation and incident history
  inside netmon; do not add those integrations or dependencies.
- Do not introduce alerts or notification delivery without a separate request.
- Preserve existing statistics and make incomplete observations explicit.
