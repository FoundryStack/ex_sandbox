# Refusal is the design

A host that cannot enforce confinement gets a **refusal**, not a weaker sandbox.

That is the single decision this library is organised around, and it is the one
most likely to look like over-engineering until the alternative is seen working.
This page is the argument for it.

## The claim

> A partially confined tenant is worse than none, because it looks contained.

Both halves matter. "Worse" is not rhetoric: an unconfined tenant is a known
unconfined tenant — nothing is running there that the operator has not accepted.
A tenant behind a boundary that does not hold is one the operator has *already
decided* is safe to run, on the strength of a guarantee that is not there.

So the failure mode this library designs against is not "isolation is hard". It
is **isolation that reports success**.

## The shape of the defect: reported ≠ built

Every incident below is the same shape wearing a different disguise. What the
library *reports* about confinement and what the launch *builds* drift apart,
and nothing in a normal build, test or review notices, because the reporting
side is self-consistent and the building side is self-consistent.

Four instances are recorded in this repository:

1. **A cap invoked and silently lost** (`005` R9b). `taskpolicy -m 100
   sandbox-exec … ./hog 300` allocates 300 MB under a nominal 100 MB cap and
   **exits 0**. macOS `taskpolicy -m` applies to its immediate child only and
   does not survive an intervening exec. No error, no warning, nothing
   observably different from a correct invocation except that the cap does not
   exist.

2. **A contract relegating three capabilities to "deployment"** (`005` T012).
   `capabilities/0` probed five things; `build_command/2` constructed cgroups,
   the uid drop and `env -i`. On a correctly configured Linux host every probe
   passed and the sandbox launched **reported fully hardened with three of five
   boundaries absent**. `verify_applied/1` as originally scoped inspected uid,
   cgroup and memory/CPU, so it could not catch it either — and every other test
   in the suite passed in that state.

3. **A required capability that was never declared** (`005` T060c).
   `Mechanism.Beam` omitted `:network_restriction` for as long as its list had
   existed, while `build_command/2` composed `--unshare-net` unconditionally. On
   a host that cannot create a network namespace the launch either failed for an
   unexplained reason or — worse — succeeded without one, and `005-SC-002`
   (cluster isolation) rests entirely on that namespace. A sandbox launched
   there was reachable by distribution from every other sandbox on the host.

4. **A quota accepted and ignored** (MEASURED 2026-08-28, engine 27.4.0,
   overlayfs). `docker run --rm --storage-opt size=16M alpine sh -c 'dd
   if=/dev/zero of=/big bs=1M count=64'` wrote 64 MB, exit 0. `docker create
   --storage-opt size=1G` also returns success. The option is accepted and
   ignored — R9b's shape again, one layer up.

None of these is exotic. Each is what happens when a confinement API is asked
politely and answers politely.

## Why probes must attempt what the launch attempts

⚠️ **Privilege is what hides a probe defect.** A probe testing an easier
operation than the real one agrees with the hard form on a privileged host and
disagrees exactly where it matters — which means the defect is invisible on the
developer's machine and on any CI runner generous enough to be convenient.

`CapabilityBuildParityTest` therefore asserts on the probe's **source** rather
than by running it: running it on a privileged host returns `true` either way.
And it asserts a *relationship* rather than a list of expected flags — a
capability that is probed is a capability that is built — so a sixth capability
added to the probe with no matching construction fails automatically. A fixed
list of flags would pin today's construction and miss precisely that case.

## Why the gate defaults lean toward refusing

`ExSandbox` gates on `required_capabilities/0 -- constructed_capabilities/0`.
The two callbacks are optional, and their defaults are deliberately *opposite*:

| Callback omitted | Assumed |
|---|---|
| `required_capabilities/0` | requires **every** gating capability |
| `constructed_capabilities/0` | constructs **nothing** |

Each choice makes silence produce the **stricter** gate, so omitting a callback
can never be a route to a weaker check (`FR-012b`). A mechanism that
under-declares must not thereby escape the check — otherwise the easiest way to
pass the gate is to say nothing, which is the incentive gradient a security
default must never have.

The check is repeated at `start/2` rather than trusted from `provision/2`, for
the same reason: a sandbox may be provisioned on one host and started on
another, and a cap that was enforceable then is not thereby enforceable now.

## Refusal must be loud, and it must be a value

Two properties, and both were learned rather than assumed:

  * **It is a return value, not an exception.** `{:error,
    {:capability_unavailable, reports}}` carries the `ExSandbox.Capability`
    structs, each with a `detail` saying why *on this host*. A caller decides;
    the library does not decide for it by raising.
  * **It emits telemetry from inside the gate**, not from the caller. A
    mechanism refusing to start is correct behaviour but *invisible* behaviour,
    and an operator watching no sandboxes appear needs to know it was a
    capability decision rather than a crash.

## Where refusal is *not* the answer

Refusal is not a way to avoid stating a weakness. `Mechanism.Docker` cannot
enforce a disk quota on overlayfs (instance 4 above). Requiring `:disk_quota`
would refuse on every Docker Desktop for Mac — the host that mechanism exists to
serve — and a mechanism that refuses everywhere is not a safer mechanism, it is
no mechanism.

So the rule is narrower than "refuse when unsure":

> **Claim less than you enforce; refuse when what you claimed is unavailable.**

Docker's moduledoc therefore states, in the mechanism itself, that a sandbox
under it **can fill the host filesystem**. That is a documented reduction in the
guarantee, not a silent one, and it is the honest form of the same discipline: a
consumer reading the capability report learns the truth before a launch rather
than after an incident.

## The same discipline, applied to evidence

Refusal governs what the library will *run*. The conformance suite's third
outcome governs what it will *claim to have verified*:

| Suite observes | Verdict |
|---|---|
| Breach attempted, stopped | ✅ guarantee holds |
| Breach attempted, **not** stopped | ❌ mechanism failed |
| Breach cannot be attempted on this host | ⚠️ capability unavailable |
| Mechanism present, breach **never attempted** | ❌ not evidence — unavailable |

The fourth row is the one that matters, and it is `FR-012b`. A suite asserting
*the limiter was invoked with the right arguments* passes R9b's defect. So would
one asserting the wrapper appears in the process tree, or that configuration
names the cap. **Every formulation short of "trigger a breach and observe it
stopped" accepts the defect as conformant.**

That is why `mix test` on macOS prints its own disclaimer instead of a green
tick:

```
005: skipping isolation, reclamation tests on darwin.
Six of ten success criteria are NOT verified by this run.
```

A vacuous pass is the testing-shaped version of a partially confined tenant: it
looks contained.

## See also

  * [How to read a refusal](../how-to/read-a-refusal.md) — the three shapes and what to do about each
  * [How to implement a mechanism](../how-to/implement-a-mechanism.md) — declaring capabilities without over-claiming
  * `ExSandbox.Capability` — what each name means, per platform
  * `ExSandbox.Conformance` — the suite, and why it has no exclusions
