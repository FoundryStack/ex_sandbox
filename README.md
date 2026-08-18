# ExSandbox

Isolated execution sandboxes, as a library with no host-application concepts.

`ex_sandbox` is a **composition and evidence layer over operating-system facilities**, not a new
isolation mechanism. Nothing here invents containment: cgroup v2, user and mount namespaces,
`setpriv` and `bwrap` do the confining. What this library adds is composing them correctly,
refusing to run when it cannot, and **producing evidence** that the boundary is real.

> ⚠️ **Not published.** `012-FR-013` (release as a versioned package) is deferred until after the
> first working sandbox, which is now done — but publication has not happened. There is no Hex
> package; the `mix.exs` snippet the scaffold used to show here would not resolve.

## Dependencies

`:telemetry`, and nothing else. `012-FR-001` forbids Ash, any web framework, and Axonn itself; the
Elixir floor is `~> 1.14` deliberately, so consumers are not forced onto the platform's version.
Both properties are enforced by tests rather than by convention — see `dependency_tree_test.exs`
and `boundary_enforcement_test.exs`.

The direction matters more than it looks. Research R2 established that a wrong-direction reference
inside this library **compiles cleanly, exits 0, passes `mix deps.tree`, and fails only at runtime
inside a third-party consumer's application**. `--warnings-as-errors` is the only build-time check
that catches it, which is why the gate is load-bearing rather than stylistic.

## The interface

`ExSandbox` is the facade: `provision/2`, `start/2`, `stop/2`, `destroy/2`, `status/2`,
`list_running/1`, `usage/2`, `capabilities/0`. Each takes a mechanism module implementing the
`ExSandbox.Mechanism` behaviour.

```elixir
{:ok, sandbox}   = ExSandbox.provision(ExSandbox.Mechanism.Beam, %ExSandbox.Sandbox{...})
{:ok, running}   = ExSandbox.start(ExSandbox.Mechanism.Beam, sandbox)
{:ok, :running}  = ExSandbox.status(ExSandbox.Mechanism.Beam, running)
{:ok, stopped}   = ExSandbox.stop(ExSandbox.Mechanism.Beam, running)
:ok              = ExSandbox.destroy(ExSandbox.Mechanism.Beam, stopped)
```

### What is public

`ExSandbox`, `ExSandbox.Mechanism`, `ExSandbox.Sandbox`, `ExSandbox.Capability`,
`ExSandbox.Hardening`, `ExSandbox.Conformance`, `ExSandbox.Proxy`, `ExSandbox.Telemetry`, and
`ExSandbox.Conformance.{Lifecycle, Isolation, ResourceLimits, Helpers, Group}` — the last group
public *by consequence*, since `use ExSandbox.Conformance` expands into calls on them inside the
consumer's own module.

**A module not on that list is private, whether or not it is namespaced `Internal`**
(`012-FR-014`). The `ExSandbox.Internal.*` prefix makes the common case obvious, but the list is
what defines the boundary — lacking the prefix does not make a module public. There is no
compatibility promise for private modules; calling one from a consuming application is the
coupling `012-FR-004` forbids, and `Axonn.LibraryBoundaryTest` checks for it mechanically.

The authoritative list lives in `ExSandbox`'s own `@moduledoc`. This README summarises it; if the
two disagree, the moduledoc is right.

## Refusal is the design

A host that cannot enforce confinement gets a **refusal**, not a weaker sandbox. `capabilities/0`
probes five things — resource limits, privilege separation, filesystem confinement, network
restriction, disk quota — and the BEAM mechanism refuses to provision when any it requires is
missing. A partially confined tenant is worse than none, because it looks contained.

⚠️ **Probes must attempt what the launch actually does.** This library has shipped the opposite
defect four times: a probe testing an easier operation than the real one reports a capability the
host does not have, and every launch then dies — or worse, succeeds unconfined. Privilege is what
hides it, since the easy and the hard form agree until privilege is removed.
`CapabilityBuildParityTest` pins this by asserting on the probe's *source* rather than by running
it, because running it on a privileged host returns `true` either way.

## The conformance suite

`ExSandbox.Conformance` is the contract's enforcement, usable by any mechanism implementation, not
just the BEAM one:

```elixir
defmodule MyMechanismTest do
  use ExSandbox.Conformance, mechanism: MyMechanism
end
```

It scores three outcomes, not two: **pass**, **guarantee failure**, and **capability
unavailable**. The third exists because "this host cannot demonstrate the guarantee" and "this
mechanism breached the guarantee" lead to opposite actions, and collapsing them into a failure
produces breach reports for boundaries that were never tested.

## Tests

```
mix test                                   # unit + contract; isolation excluded off Linux
docker compose -f docker/compose.isolation.yml up --build \
  --abort-on-container-exit --exit-code-from isolation isolation
```

⚠️ **A green `mix test` on macOS says nothing about whether tenant code is contained.** Six of
`005`'s ten success criteria rest on Linux kernel facilities with no macOS equivalent, so the
`:isolation` and `:reclamation` tags are excluded there — visibly not run, rather than passing
vacuously. The container is a real Linux host with systemd as PID 1 and all five capabilities
genuinely constructed; it has found more than a dozen defects in code that passed everything
locally, including a launch path that failed on *every* Linux host.
