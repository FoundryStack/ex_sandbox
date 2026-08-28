# Changelog

## 1.0.0 — 2026-08-28

### Extracted from the Axonn umbrella; first public release

This library was an application inside a larger umbrella project. It is now its own repository and
its own Hex package, with its own lockfile, config, CI and isolation harness. The extraction
preserved history (`git subtree split`, 143 commits) rather than re-creating the tree.

What changed for a consumer, as opposed to for the umbrella:

- **`storage_root` now defaults to `/var/lib/ex_sandbox/sandboxes`**, was `/var/lib/axonn/sandboxes`.
  ⚠️ For an existing deployment this is a data migration, not a cosmetic rename — sandbox storage
  moves. Set `config :ex_sandbox, :beam, storage_root: "/var/lib/axonn/sandboxes"` to keep the old
  path.
- **The verdict socket's default prefix is `ex-sandbox-`**, was `axonn-`.
- The dependency tree is `:telemetry` and nothing else, enforced by
  `test/dependency_tree_test.exs`, and the Elixir floor is `~> 1.14` rather than the platform's
  version.
- The conformance suite's credentials group reports `capability_unavailable` here rather than
  passing, because this package has no data store to probe (`012-FR-001`). A consumer with a
  database instantiates the same suite with its own probe. The identifiers are explained in
  [docs/requirement-ids.md](docs/requirement-ids.md).

No public function, callback, struct field or telemetry event changed in the move.

### `ExSandbox.Mechanism` gained an optional callback, and the gate changed shape

`c:ExSandbox.Mechanism.constructed_capabilities/0` declares the capabilities a
mechanism **builds for whatever it runs** — the opposite claim from
`c:ExSandbox.Mechanism.required_capabilities/0`, which says what it needs from
the host. `ExSandbox`'s private `ensure_capable/2` now subtracts the second list from the
first and asks the host probe only about the remainder.

⚠️ **This is a change to a refusal, which is why it is a major version.** The
callback is optional and a mechanism that omits it is gated exactly as before,
so nothing in the tree breaks — but a mechanism that declares one is now
admitted on a host where it was previously refused, and a gate that admits more
than it used to is a behavioural change to the thing this library exists to do.
It is stated here rather than in the additive column.

The claim is **not verified by the behaviour**. `ExSandbox.Conformance` is what
establishes it, by observing a breach being stopped; until a mechanism is run
through the suite, what backs its list is whatever tests accompany it.

### `ExSandbox.Mechanism.Docker`

A mechanism backed by a container runtime, for hosts whose own kernel cannot
construct the confinement `ExSandbox.Mechanism.Beam` requires — every macOS
host, where all five gating capabilities report unavailable and `Beam` is
therefore refused before it is reached.

It declares `:resource_limits`, `:filesystem_confinement` and
`:network_restriction` as constructed, each backed by an observed breach in
`test/mechanism/`. It deliberately claims neither
`:disk_quota` — MEASURED accepted-and-ignored on overlayfs — nor
`:privilege_separation`; both omissions are stated reductions and are documented
on the module.

### `ExSandbox.Sandbox` gained `workspace_path`

An absolute host directory the sandbox's contents live in, supplied by the host
and made reachable from inside by whatever means the mechanism has. Additive:
`nil` means "no workspace", which a mechanism must read as *mount nothing*
rather than as *mount somewhere sensible*.
