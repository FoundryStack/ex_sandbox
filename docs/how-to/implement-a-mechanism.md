# How to implement a mechanism

A mechanism is the thing that actually confines: a BEAM node under OS hardening,
a container, a VM, something a third party writes. `ExSandbox` dispatches to one;
`ExSandbox.Conformance` holds all of them to the same bar.

This page is the order to build one in. The reasoning behind the shape is in
`ExSandbox.Mechanism`'s own moduledoc — read it before deciding you disagree
with a callback.

## 0. Know the size of the job

`ExSandbox.Mechanism` declares **13 callbacks**, 5 of them optional
(`required_capabilities/0`, `constructed_capabilities/0`, `address/1`,
`address/2`, `update_egress/2`).

⚠️ Do not trust that count either — including this one. That moduledoc said
"seven" while the file declared eight. Count `@callback` in
`lib/ex_sandbox/mechanism.ex`.

Every callback takes an `ExSandbox.Sandbox.t()`, a plain struct. Nothing in this
library knows about your host application's tenancy, routing, persistence or run
policy, and a mechanism must not reintroduce them (`FR-001`, `FR-003`,
`FR-008`).

## 1. Declare what you need and what you build

These two are the gate, and confusing them inverts it.

```elixir
@impl true
def required_capabilities, do: [:resource_limits, :filesystem_confinement, :network_restriction]

@impl true
def constructed_capabilities, do: [:resource_limits, :filesystem_confinement, :network_restriction]
```

  * `required_capabilities/0` — what you need **the host** to already provide.
    Omit it and you are treated as requiring every gating name. That default is
    deliberate: under-declaring must not be a route around the check
    (`FR-012b`).
  * `constructed_capabilities/0` — what **you** build, whether or not the host
    can. Omit it and you construct nothing. Both defaults lean the same way, so
    silence always produces the *stricter* gate.

`ExSandbox` gates on `required -- constructed`. `Mechanism.Docker` declares the
same three in both lists, so the host is asked nothing — which is the point on
macOS, where all five gating names report unavailable and a mechanism carrying
its own kernel would otherwise be refused for lacking a facility it never uses.

⚠️ **Nothing verifies a `constructed_capabilities/0` claim.** The compiler
cannot tell, and `ExSandbox` will not. Only conformance can, by observing a
breach being stopped. Until then a name on that list is a promise backed by your
own tests.

⚠️ **Use names from `ExSandbox.Capability.known/0`.** `Mechanism.Beam` once
declared `:process_isolation`, `:filesystem_isolation`, `:memory_limit` and
`:cpu_limit` — none of which that module recognises — so every caller checking
capabilities crashed with a `FunctionClauseError` instead of receiving the
"capability unavailable" report `FR-012b` requires.

### Claim less than you can, never more

`Mechanism.Docker` deliberately omits two names `Mechanism.Beam` requires, and
each omission is a stated reduction:

  * **No `:disk_quota`.** MEASURED 2026-08-28, engine 27.4.0, `linux/arm64`,
    overlayfs: `docker run --storage-opt size=16M` wrote 64 MB and exited 0. The
    option is accepted and ignored. So a sandbox under that mechanism can fill
    the host filesystem, and that is stated rather than hidden — requiring the
    name instead would refuse on every Docker Desktop for Mac, and a mechanism
    that refuses everywhere is no mechanism.
  * **No `:privilege_separation`.** A default container's process is root in the
    container, and under rootful Docker that root maps to host root. The name
    means a dropped uid composed with a mount namespace and default-deny
    filesystem; a container supplies the middle term only.

## 2. The lifecycle four

`provision/1` creates resources without starting them and returns the sandbox
with `mechanism_ref` set — the opaque handle you will recognise it by later.
`start/1`, `stop/1` (resources intact), `destroy/1` (resources released).

⚠️ **`mechanism_ref` must round-trip exactly.** MEASURED 2026-09-10: `docker ps
--format '{{.ID}}'` prints 12 characters while `docker create` returns 64, so
`list_running/0` returned ids that matched nothing recorded, and every live
sandbox looked gone to a reconciliation sweep. The fix is `--no-trunc`, not
prefix-matching in the host — a host that prefix-matches has taken on your
mechanism's id format (`FR-004`).

## 3. `status/1` — three answers, not two

`:absent | :provisioned | :starting | :running | :stopping | :stopped |
:unknown`.

⚠️ `:absent` ("it is definitely not there") and `:unknown` ("we could not
determine") must not collapse into each other. They lead to different actions:
one is a sandbox to recreate, the other is a mechanism you cannot see through.
`003-FR-024`.

## 4. `list_running/0` — the one you will be tempted to skip

Nothing in the happy path calls it, which is exactly why it goes missing. It is
what makes post-restart reconciliation possible at all (`003-FR-015`): without
it a sandbox that crashed while the host was down stays recorded as running
forever, and `003-SC-008` — recorded status matches reality within 60 seconds —
is unsatisfiable by construction.

Return the full refs, and return only sandboxes **this mechanism** owns. Docker
labels its containers and filters on that label; an unlabelled container the
operator started by hand must not appear.

## 5. `execute/3` — three returns, and they are three different facts

```elixir
{:ok, %{exit_status: 0, stdout: "", stderr: "", truncated?: false}}
{:error, {:could_not_run, reason}}
{:error, {:limit_exceeded, :wall_clock | :memory | :cpu}}
```

  * A non-zero `exit_status` is a **result**, not an error.
  * `{:could_not_run, _}` is **never** an exit status. Classifying by stderr
    alone is not enough: Docker writes `OCI runtime exec failed: … executable
    file not found in $PATH` to **stdout** with an empty stderr and exit 126.
  * `stdout` and `stderr` stay **separate** — a merged stream cannot attribute a
    failure — and `truncated?` is explicit, because silent truncation of a build
    log is how a real error disappears from a diagnosis.
  * `opts[:on_output]` receives `{:stdout | :stderr, binary()}` chunks.
    ⚠️ **A chunk is a chunk, not a line.** `015` R17 measured `MuonTrap`'s
    `:logger_fun` corrupting lines past a 256-byte buffer; a caller wanting
    lines assembles them, where a long line is late rather than mangled.

### Do not apply limits here

Read no limit in `execute/3` and enforce nothing around the command. `005` R9b
measured a cap silently lost across an intervening exec, allocating 300 MB under
a nominal 100 MB cap and **exiting 0**. A limit re-applied at execution time is a
limit applied after the process it governs already exists — the shape that fails
open. Confinement belongs to the launch; what runs inside inherits it or you
have none.

## 6. Optional: `address/1`

`{:ok, "host:port"}` reachable from the machine running the platform and nowhere
else, or `{:ok, nil}`.

`nil` is not an error — "not reachable" is an ordinary state of a sandbox, and a
caller forced to rescue an error to render a stopped one will eventually render
something else instead. ⚠️ Never answer with a handle that merely identifies the
sandbox: `Mechanism.Beam` returns `nil` rather than its `"peer:<id>"` reference,
because a caller putting that in an `iframe` gets a broken frame instead of a
clear absence.

## 7. Optional: `update_egress/2`

Implement it only if your sandboxes' egress is decided per connection, so a new
list can take effect on the next connection without a restart. It receives the
list already parsed by `ExSandbox.Egress.Allowlist.parse/2`.

⚠️ A mechanism whose sandboxes reach every host must **not** implement it.
`ExSandbox.update_egress/4` answers `{:error, :egress_not_enforced}` when the
callback is absent, and that answer is how a caller learns the list is not in
force. Accepting the list and doing nothing would tell it the opposite.

## 8. There is no `compile` callback, and there will not be one

Building a tenant's application is per-stack work, owned by `009-stack-adapters`
and run *inside* an already-provisioned sandbox (`007-FR-041`, `013-FR-021`). A
`compile` callback would require every mechanism to know how to build every
stack — the coupling Principle VI exists to prevent. A mechanism provisions a
place to run things; what gets built there is not its business.

## 9. Run conformance, in your own project

```elixir
defmodule MyMechanismConformanceTest do
  use ExSandbox.Conformance, mechanism: MyMechanism
end
```

It runs under **your** ExUnit, in **your** project — a suite runnable only inside
this repository could never be run against a third-party mechanism at all
(`SC-004`).

  * **There are no exclusions** (`FR-011`). No skip flag, no tag, no allowlist.
    `ExSandbox.ConformanceExclusionsTest` greps the suite's source to keep it
    that way.
  * **The suite is authoritative.** If your mechanism needs the suite edited to
    pass, that is evidence the *contract* leaked a mechanism assumption — fix
    the contract. A suite that bends per mechanism measures nothing.
  * Every resource-limit check **breaches** the cap. Asserting the limiter was
    invoked with the right arguments passes `005` R9b's defect; so does
    asserting the wrapper appears in the process tree. Every formulation short
    of "trigger a breach and observe it stopped" accepts the defect as
    conformant (`FR-012a`).

⚠️ Off Linux, several checks report ⚠️ capability unavailable rather than
passing. See [How to read a refusal](read-a-refusal.md) — a report of all ⚠️ is a
report that nothing was verified.

## 10. Probe what the launch actually does

If your mechanism contributes a capability probe, the probe must attempt the
operation the launch attempts. A probe testing an easier operation reports a
capability the host does not have, and every launch then dies — or worse,
succeeds unconfined. ⚠️ Privilege is what hides it, since the easy and the hard
form agree until privilege is removed, so this defect is invisible on your
machine. Four instances are recorded in
[Why refusal is the design](../explanation/refusal.md). `CapabilityBuildParityTest` pins this by asserting on the
probe's *source* rather than by running it, because running it on a privileged
host returns `true` either way.

## See also

  * [Getting started](../getting-started.md) — the lifecycle end to end against a real Docker daemon
  * [How to read a refusal](read-a-refusal.md)
  * [Why refusal is the design](../explanation/refusal.md)
  * `ExSandbox.Mechanism` — the callbacks and the reasoning per callback
  * `ExSandbox.Conformance` — what each check breaches and why
