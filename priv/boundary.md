# The public interface of `ex_sandbox`

This document owns the **package** contract: what this library promises its consumers, and what a
consumer may rely on. It is the artifact `FR-014` requires — the statement of what is public.

**The list below is the boundary.** A module not named here is private, whether or not it is
namespaced `Internal` (`012-FR-014`). The `ExSandbox.Internal.*` prefix makes the common case
obvious, but the list is what defines the boundary — lacking the prefix does not make a module
public. There is no compatibility promise for a private module, and calling one from a consuming
application is the coupling `012-FR-004` forbids.

⚠️ **This file ships inside the package and is read at runtime**, via
`Application.app_dir(:ex_sandbox, "priv/boundary.md")`. A consumer can therefore check its own
usage against the real list mechanically instead of trusting a copy: parse the table below and
fail on any reference to a module it does not name. Removing this file from `package/0`'s `files:`
would silently remove every consumer's ability to run that check.

⚠️ `priv/`, not `docs/`, and 1.0.0 had it under `docs/`. Mix links only `ebin` and `priv` into an
application's build directory, so a file shipped anywhere else is present in the tarball and
absent from `Application.app_dir/2` -- which is the only path a consumer has at runtime. Moving
this file is therefore a breaking change to anything that read the 1.0.0 location, and 1.0.1 is
the release that makes the documented call actually resolve.

⚠️ Parse it, do not copy it. The consumer this document was written against kept a hand-maintained
copy of the list for three revisions, and every drift recorded further down was found *because*
the copy was replaced by a parse — including one where the copy was **wider** than the contract, so
the boundary being enforced was not the boundary described here and nothing could have noticed.

If this document and `ExSandbox`'s own `@moduledoc` ever disagree, the moduledoc is right; open
an issue, because one of them has drifted.

For the numbering scheme in the requirement IDs cited throughout — and for what `Axonn` means where
this document names it — see [requirement-ids.md](requirement-ids.md). The short version: Axonn is
the application this library was extracted from, named here as the concrete consumer a rule was
measured against, never as a dependency.

---


## Public interface of `ex_sandbox`

| Module | Purpose | Stability |
|---|---|---|
| `ExSandbox` | The top-level API — dispatches the seven mechanism callbacks, and gates each on `Capability` before it reaches the mechanism | Public |
| `ExSandbox.Mechanism` | The behaviour every mechanism implements | Public — breaking change ⇒ major |
| `ExSandbox.Sandbox` | The struct passed to every callback | Public |
| `ExSandbox.Capability` | Host capability report (`FR-016`) | Public |
| `ExSandbox.Hardening` | OS hardening behaviour (from `005`'s `contracts/hardening.md`) | Public |
| `ExSandbox.Hardening.Confinement` | Confines a **control-plane** process to one filesystem path (`015` T107, R16/R30). Public because the host is what knows *which* path a run may reach — that is tenancy, which `FR-008` keeps out of this library, so the decision must be callable from outside. ⚠️ Deliberately **not** an `ExSandbox.Hardening` implementation: the posture is inverted (environment passes through, egress permitted), and a flag on the tenant profile would put unstripping a sandbox one argument away | Public |
| `ExSandbox.Conformance` | The suite, included via `use` | Public |
| `ExSandbox.LoopFormatter` | ExUnit formatter emitting the machine-readable run report `mix verify.change` grades. Public because the gate must be able to name it, and it lives here rather than in `axonn` because `ex_sandbox` is the umbrella's universal ancestor -- every app's suite has to be able to emit the report, and only a module every app already depends on can do that | Public |
| `ExSandbox.Mechanism.Beam` | The reference mechanism (`005-sandbox-beam`) | Public — see mechanism-specific surface below |
| `ExSandbox.Mechanism.Docker` | Confines a sandbox inside a container instead of the host kernel (`host-sandbox-and-agent-workspace`) | Public — see mechanism-specific surface below |
| `ExSandbox.Proxy` | Forwards a request to a running sandbox's address | Public |
| `ExSandbox.Telemetry` | The events both libraries emit, and their metadata | Public |
| `ExSandbox.Conformance.{Lifecycle,Reachability,Reconciliation,Credentials,Isolation,Network,ResourceLimits,Execution,Helpers,Group,CapabilityUnavailable}` | Reached by the suite `use` generates | Public by consequence |
| `ExSandbox.Conformance.Credentials.Probe` | The behaviour a host implements so the credentials group can attempt real connections | Public |
| `ExSandbox.Egress.Allowlist` | Parses a project's configured destinations into the form the mechanism enforces (`005-FR-011a`, `013-FR-014b`) | Public — the host resolves the allowlist |
| `ExSandbox.Egress.HostAliases` | Discovers every address that **is this host**, for the `029-FR-015` exclusion `Allowlist.parse/2` takes as data | Public — the host supplies the alias set |
| `ExSandbox.Application`, anything under `ExSandbox.Internal.*` | Implementation | **Private — no compatibility promise** |

**Mechanism-specific functions are public but not portable.** `ExSandbox.Mechanism.Beam` exports
`provision_failure_reason/1` (`005`'s hardening contract -- see
[requirement-ids.md](requirement-ids.md)),
which is **not** an `ExSandbox.Mechanism` callback and has no equivalent on other mechanisms. It
answers *why* a sandbox stopped — which `status/1`, returning a lifecycle atom, structurally cannot —
and it does so by reading cgroup v2 counters that only this mechanism has.

The behaviour was deliberately not widened to absorb it. A callback there is a promise every present
and future mechanism must keep, and this is a question most cannot answer except by returning
`:mechanism_error`, which is no answer. Better one mechanism with a documented extra function than
seven callbacks where one is honest.

The rule this creates: **orchestration calls only behaviour callbacks.** A caller that invokes
`Beam.provision_failure_reason/1` directly has coupled to one isolation model and broken Principle
VI — `009-FR-004` ("adding a stack does not modify orchestration") is false the moment it does. The
host reaches this detail through the recorded operation, never by branching on `record.mechanism`.

`ExSandbox.Mechanism.Docker` exports `runtime_available?/0` and `workspace_mountpoint/0` the same
way — neither is a `Mechanism` callback, and neither has an equivalent on `Beam`. Unlike
`provision_failure_reason/1`, though, `runtime_available?/0` is not a diagnostic read on a sandbox
that already exists — it answers "is a container runtime reachable on this host, right now", which
only makes sense asked of *this* mechanism, before one has been provisioned. Its documented caller
is exactly the mechanism-specific advice Axonn's refusal message gives an operator (`Axonn.Studio`,
`registerable_mechanism_advice/0`): what to install and which env var to set depends on which
mechanism could run here, so that advice is inherently coupled to one isolation model already —
calling `Docker.runtime_available?/0` from it names the coupling rather than hiding it behind a
callback that would have to lie about being generic.

**`ExSandbox` itself was missing from this table until 2026-08-23, and that is the fourth drift.**
It is the module Axonn actually calls — `provision/2`, `start/2`, `stop/2`, `destroy/2`, `status/2`,
`list_running/1` — from five files under `apps/axonn/lib/axonn/sandbox/`, and `ex_sandbox.ex`'s own
moduledoc heads its public list with it. The table simply began one row too late.

⚠️ It surfaced only because `Axonn.LibraryBoundaryTest` stopped restating this table and started
**parsing** it. The three drifts recorded before this one all ran the same direction — a module
public here and absent from the test's hand-kept copy, which showed up as a legitimate reference
reported as a violation. This one ran the other way: the copy was **wider** than the contract, so
the boundary the test enforced was not the boundary this document describes, and nothing could
have noticed while the copy existed. `ExSandbox.Conformance.CapabilityUnavailable` was the same
shape — in the copy, absent from the brace expansion above — and is added with it; it is reached
by consequence like the rest, because `Conformance.Group.check/2` expands a
`rescue ... in ExSandbox.Conformance.CapabilityUnavailable` clause into the consumer's own module.

**`ExSandbox.Conformance`'s submodules are public by consequence, not by choice.** `use
ExSandbox.Conformance` expands into calls on them inside the consumer's own module, so they are
part of the compiled surface whether or not anyone means them to be. Recorded rather than hidden:
a module a consumer's code calls is public under `FR-014` regardless of intent, and pretending
otherwise would make the first rename a silent breaking change.

**`ExSandbox.Conformance.Credentials.Probe` is public because the host implements it.** The
credentials group has to attempt a real connection against a real store, and this library has no
database concept to do it with (`FR-001`). So the host supplies a probe, which makes the behaviour's
callbacks interface in the strongest sense — a host's module is written against them.

Its absence is the **third outcome**, not a pass: a host that supplies no probe sees `host
capability unavailable` on every credentials check. That keeps `credential_probe:` from being the
exclusion `FR-011` forbids — a consumer cannot omit it to silence a check they would otherwise
fail, because omitting it never produces green. `ExSandbox.ConformanceExclusionsTest` asserts both
halves: that the option is on a justified allowlist, and that its `nil` clause reaches
`capability_unavailable` rather than `:ok`.

**`ExSandbox.Egress.Allowlist` is public because the host owns the settings.** The destinations a
sandbox may reach come from the tenant project's configuration (`013-FR-014b`), which lives in the
host's schema -- this library has no project concept (`FR-001`). So the host reads the setting and
the library supplies the parser, which makes `parse/1` interface: the host's provisioning path calls
it directly.

⚠️ It is public **as the parser, not as a validator**. `parse/1` refuses a configuration it cannot
read rather than filtering the entries it can, and a host that reimplemented the parse would
reintroduce exactly that choice. A filtering parser drops the entries it does not understand and
returns a shorter allowlist that enforces correctly and silently grants less than was configured --
or, when nothing parses, returns `[]`, which is indistinguishable from default-deny and so passes
every denial check while the operator's configuration was never applied. That failure is invisible
from outside, which is why the parse belongs to the library that enforces the result.

**`ExSandbox.Egress.HostAliases` is public because the alias set crosses the seam as data.**
`029-FR-015` excludes every address that *is the host* from what an allowlist may express, and
`Allowlist.parse/2` applies that exclusion -- but it takes the alias set as an argument rather than
discovering one. That is deliberate and is what keeps `Allowlist` transferable: knowing about
interfaces, routing tables and `pasta`'s gateway mapping is mechanism knowledge, and a capability
query from inside the parser would re-couple the module that must stay mechanism-neutral (`D27`).

So the discovery has to live somewhere the coupling is allowed, and the host is what calls it --
`Axonn.Sandbox.Provision` reads it at provision time and passes the result in. That call is
interface, so the module is public.

⚠️ It is public **as a discovery, not as a configuration**. `detect/0` reads the running kernel at
the moment it is called. A host that substituted a configured constant would be right in the config
file and wrong in the namespace, and every parse-time test would stay green while the address
actually in use is one no entry is refused for -- the same shape as the filtering parser above, in
the alias set instead of the entry list.

**`ExSandbox.Telemetry` is public because handlers are.** A host attaching a `:telemetry` handler
depends on the event names and metadata keys, which makes them interface. Its moduledoc carries two
recorded mismatches with `010-observability` that this library cannot resolve — see `FR-007`.

### The seven mechanism callbacks, and why the obvious four are not enough

A natural first cut of this API is `compile` / `start` / `stop` / `proxy`. `003`'s contract requires
**seven**, and the three additions each exist because of a specific requirement rather than for
symmetry:

| Callback | Why it exists |
|---|---|
| `provision`, `start`, `stop`, `destroy` | Lifecycle — the obvious four |
| `status` | `003-FR-024` requires distinguishing "starting" from "not running"; `:absent` and `:unknown` must not collapse |
| **`list_running`** | **`003-FR-015`** — reconciling recorded against actual state after a restart. Without it a crashed sandbox stays recorded as running indefinitely, and `003-SC-008` (status matches reality within 60s) is unsatisfiable |
| **`usage`** | **`010-`** Story 3 and `003-FR-026` — per-sandbox CPU, memory, and disk, attributable to the owner |

`list_running` is the one most easily omitted, because nothing in the happy path calls it. It is
what makes reconciliation possible at all.

**Compilation is not a mechanism callback.** Building a tenant's application is per-stack work
belonging to `009-stack-adapters`, invoked *inside* an already-provisioned sandbox (`007-FR-041`,
`013-FR-021`). A `compile` callback on the mechanism would make every mechanism know how to build
every stack — the coupling Principle VI exists to prevent.


## What a consumer must supply

| Consumer supplies | Why the library cannot | Requirement |
|---|---|---|
| `owner_ref` value | It has no owner concept | `FR-007` |
| Run policy | It has no lifecycle concept | `FR-008` |
| Data layer, repo, storage placement | It has no database layout | `FR-009` |
| Scope/context value, or `nil` | It has no request-scoping type | `FR-003` |
| Mechanism selection and configuration | The host decides what it can run | `003` R1 |

A consumer supplying none of these beyond a mechanism gets a working sandbox — that is Story 1's
claim, and `SC-001` is its test.

---

## What the libraries promise

1. **No upward dependency.** Neither library references any module it does not declare or depend
   on. Enforced by `--warnings-as-errors`, not by convention — see below.
2. **No interpretation of opaque values.** `owner_ref`, `mechanism_ref`, and `context` are stored,
   compared, and propagated; never parsed, and never used to make a decision.
3. **Capability honesty** (`FR-016`). A library states what it needs from the host and reports when
   it is missing, rather than assuming it. A mechanism whose required capability is unavailable
   **refuses to start sandboxes** rather than starting them unconfined — the spec's Edge Cases
   entry, and the same rule `005-` R9 applies to macOS.
4. **Versioned breakage** (`FR-015`). A change to anything listed public above is a major version.

---

## How the boundary is enforced

**This section is normative, not advisory.** Research R2 verified that the obvious enforcement does
not work:

| Mechanism | Catches an upward reference? |
|---|---|
| `mix.exs` deps declaration | ❌ No — controls fetching, not referencing |
| `mix deps.tree` assertion | ❌ No — passed with a violation present |
| `mix compile` (normal) | ❌ No — **warning only, exit 0** |
| `mix compile --warnings-as-errors` | ✅ **Yes** |
| Runtime in a third-party app | ✅ Yes — as `UndefinedFunctionError`, too late |

Therefore:

- **`--warnings-as-errors` is a required CI gate for both library apps.** It is not a style
  preference here; it is the only build-time check that fails on a boundary violation.
- `mix deps.tree` assertions remain required by `SC-002`/`SC-003`, but are understood as proving
  *nothing was fetched* — a weaker claim than *nothing was referenced*.

Without the first gate, a violation compiles cleanly, passes tests, publishes to Hex, and fails
only inside the consumer's application — where the library's author never sees it and the person
who does cannot fix it.

---

## Conformance suite contract (`FR-010` – `FR-012`)

**Inclusion**: `use ExSandbox.Conformance, mechanism: MyMechanism` in the consumer's own test file,
run by the consumer's own ExUnit.

**Guarantees**:
- Every `003` guarantee is exercised (`FR-010`).
- No skip flag, exclusion tag, or mechanism allowlist exists (`FR-011`).
- A failure names the violated guarantee, not just the failed assertion (`SC-004`, Story 2 AS 2).
- Axonn's mechanisms run the published suite unmodified, as ordinary consumers (`FR-012`).

**The one legitimate non-run**: a check requiring a host capability that is absent reports
**`host capability unavailable`**, distinct from both pass and fail. This is not an exclusion —
the consumer cannot request it, it is determined by `ExSandbox.Capability` at runtime, and it is
reported rather than hidden. `005`'s finding that six of ten criteria require Linux, and `013`'s
Finding V2 that a capability can be absent under some container configurations, make this
unavoidable. Research R7 flags it as the boundary most likely to be argued about later.
