# Architecture documentation

Reading order for understanding how Secrets is put together:

1. [Overview](overview.md) — layers, crates, and the daemon/backend
   diagram.
2. [`secret://` URI scheme](../secret-uri.md) — the resource reference
   (distinct from the D-Bus transport).
3. [D-Bus protocol](../dbus/README.md) — the stable IPC contract between
   `secretsd` and every client, native and Secret Service compatibility
   alike.
4. [External clients](external-clients.md) — GD Secrets, `secrets-tui`,
   and browser extensions: separate repositories that consume
   `secrets-client` or the D-Bus protocol directly, not workspace members
   of this repository.
5. [1Password Desktop integration](1password-integration.md) and
   [POC results](1password-poc-results.md) — the investigation and
   validation behind the 1Password backend ([ADR-012](../adr/012-1password-desktop-backend.md)).
6. [1Password Desktop-free cloud transport feasibility](1password-cloud-transport-feasibility.md)
   — a separate investigation into whether `secretsd` could authenticate
   as the user directly against 1Password's cloud, without the Desktop
   app. Research only; nothing here has been implemented.
</content>
