# ExSandbox

Isolated execution sandboxes with no host-application concepts.

`ex_sandbox` is a **composition and evidence layer over operating-system
facilities**, not a new isolation mechanism. Nothing here invents containment:
cgroup v2, user and mount namespaces, `setpriv` and `bwrap` do the confining.
What this library adds is composing them correctly, **refusing to run when it
cannot**, and producing evidence that the boundary is real.

```elixir
def deps do
  [{:ex_sandbox, "~> 1.3"}]
end
```

⚠️ **Linux is where this library does its job.** It installs, compiles and runs
its unit suite on macOS, but `ExSandbox.capabilities/0` reports every gating
capability unavailable there and `ExSandbox.Mechanism.Beam` refuses to
provision — deliberately. `ExSandbox.Mechanism.Docker` exists for exactly that
host.

## Documentation

| | |
|---|---|
| **[Getting started](docs/getting-started.md)** | Provision, start, execute and destroy a real sandbox, end to end. Start here. |
| **[How to implement a mechanism](docs/how-to/implement-a-mechanism.md)** | The 11 callbacks, in the order to build them, and what each one must not do. |
| **[How to read a refusal](docs/how-to/read-a-refusal.md)** | The three shapes a refusal takes and the decision each one implies. |
| **[Why refusal is the design](docs/explanation/refusal.md)** | The argument, and the four times this repository shipped the opposite defect. |
| **[What `005-FR-011` means](docs/requirement-ids.md)** | The citation scheme in the source, and the name `Axonn`. |
| **[Provenance](docs/provenance.md)** | Where this library was extracted from, and what did not come with it. |
| **[Public interface](priv/boundary.md)** | The boundary, shipped inside the package and readable at runtime. |

## The interface

`ExSandbox` is the facade: `provision/2`, `start/2`, `stop/2`, `destroy/2`,
`status/2`, `list_running/1`, `usage/2`, `capabilities/0`. Each takes a mechanism
module implementing the `ExSandbox.Mechanism` behaviour.

```elixir
{:ok, sandbox}   = ExSandbox.provision(ExSandbox.Mechanism.Docker, %ExSandbox.Sandbox{...})
{:ok, running}   = ExSandbox.start(ExSandbox.Mechanism.Docker, sandbox)
{:ok, :running}  = ExSandbox.status(ExSandbox.Mechanism.Docker, running)
{:ok, stopped}   = ExSandbox.stop(ExSandbox.Mechanism.Docker, running)
:ok              = ExSandbox.destroy(ExSandbox.Mechanism.Docker, stopped)
```

**A module not named in `priv/boundary.md` is private, whether or not it is
namespaced `Internal`** (`012-FR-014`). That document ships inside the package
and resolves at runtime through `Application.app_dir(:ex_sandbox,
"priv/boundary.md")`, so a consumer's own test can read the public-interface
table from the installed dependency rather than restating it. The authoritative
list lives in `ExSandbox`'s `@moduledoc`; if the two disagree, the moduledoc is
right.

## Dependencies

`:telemetry`, and nothing else. The Elixir floor is `~> 1.14` deliberately, so
consumers are not forced onto the platform's version. Both properties are
enforced by `dependency_tree_test.exs` and `boundary_enforcement_test.exs`
rather than by convention.

The direction matters more than it looks. Research R2 established that a
wrong-direction reference inside this library **compiles cleanly, exits 0,
passes `mix deps.tree`, and fails only at runtime inside a third-party
consumer's application**. `--warnings-as-errors` is the only build-time check
that catches it, which is why the gate is load-bearing rather than stylistic.

## Conformance

`ExSandbox.Conformance` is the contract's enforcement, usable by any mechanism
implementation:

```elixir
defmodule MyMechanismTest do
  use ExSandbox.Conformance, mechanism: MyMechanism
end
```

It scores three outcomes, not two: **pass**, **guarantee failure**, and
**capability unavailable** — because "this host cannot demonstrate the
guarantee" and "this mechanism breached the guarantee" lead to opposite actions.

## Tests

```
mix test                                   # unit + contract; isolation excluded off Linux
docker compose -f docker/compose.isolation.yml up --build \
  --abort-on-container-exit --exit-code-from isolation isolation
```

⚠️ **A green `mix test` on macOS says nothing about whether tenant code is
contained.** Six of `005`'s ten success criteria rest on Linux kernel facilities
with no macOS equivalent, so the `:isolation` and `:reclamation` tags are
excluded there — visibly not run, rather than passing vacuously. The container
is a real Linux host with systemd as PID 1 and all five capabilities genuinely
constructed; it has found more than a dozen defects in code that passed
everything locally, including a launch path that failed on _every_ Linux host.

## Contributing

⚠️ Read the isolation-harness warning above first. A pull request whose
`mix test` is green on macOS has verified nothing about containment, and the
container is not optional for any change touching `ExSandbox.Hardening.*`,
`ExSandbox.Egress.*` or the mechanisms.

`mix precommit` is the gate: `compile --warnings-as-errors --force`,
`format --check-formatted`, `deps.unlock --check-unused`,
`docs --warnings-as-errors`, `test`.

## License

Apache-2.0. See [LICENSE](https://github.com/FoundryStack/ex_sandbox/blob/main/LICENSE).
