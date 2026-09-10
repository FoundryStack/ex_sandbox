# How to read a refusal

`ExSandbox` declines work it cannot do honestly. A refusal is a *result*, not a
crash, and it names what was missing. This page is how to turn one into a
decision.

There are three shapes, and telling them apart is the whole skill: a refusal
before the mechanism was asked, a command that did not run, and a conformance
check that could not be attempted.

## 1. `{:error, {:capability_unavailable, reports}}`

Returned by `ExSandbox.provision/2` and `ExSandbox.start/2` **before the
mechanism is called at all**. The library is declining to pretend, not reporting
a mechanism fault (`FR-016`).

MEASURED on darwin 25.5.0 with `ExSandbox.Mechanism.Beam`:

```elixir
sandbox = %ExSandbox.Sandbox{id: "probe-1", owner_ref: "probe", template_ref: "none"}
ExSandbox.provision(ExSandbox.Mechanism.Beam, sandbox)
#=> {:error,
#=>  {:capability_unavailable,
#=>   [
#=>     %ExSandbox.Capability{
#=>       name: :resource_limits,
#=>       available?: false,
#=>       detail: "macOS `taskpolicy -m` applies to its immediate child only and is
#=>                silently lost across an intervening exec (005 R9b), so a
#=>                configured cap is not an enforced cap"
#=>     },
#=>     %ExSandbox.Capability{name: :filesystem_confinement, available?: false, detail: ...},
#=>     %ExSandbox.Capability{name: :privilege_separation, available?: false, detail: ...},
#=>     %ExSandbox.Capability{name: :network_restriction, available?: false, detail: ...}
#=>   ]}}
```

**Read the `detail`, not the `name`.** The name says which guarantee is
unavailable; the detail says *why on this host*, and it is the part that tells
you whether the answer is "use another host", "use another mechanism", or
"nothing will fix this". The four above are the third kind: macOS has no mount
namespace and no network namespace, and a `sandbox-exec` profile is not
inherited across an intervening exec. No configuration change makes the BEAM
mechanism confine on that host.

### The report is shorter than the capability list, and that is not a bug

`ExSandbox.Capability.gating_defaults/0` has five names; the refusal above lists
four. `:disk_quota` is absent because `Mechanism.Beam` does not declare it in
`required_capabilities/0`. **Only what a mechanism says it requires is gated**,
and a mechanism that declares nothing is treated as requiring all five —
silence produces the stricter gate, never the weaker one (`FR-012b`).

### Why a mechanism can be refused nothing at all

`ExSandbox` gates on `required_capabilities/0 -- constructed_capabilities/0`.
`Mechanism.Docker` declares both as exactly
`[:resource_limits, :filesystem_confinement, :network_restriction]`, so the
subtraction is `[]` and the host is asked nothing. That is the intended reading:
a mechanism that brings its own kernel must not be refused for lacking a kernel
facility it never uses.

⚠️ **Nothing in the behaviour verifies a `constructed_capabilities/0` claim.** A
mechanism listing a name it does not build has widened its own gate silently.
What backs Docker's three is `DockerConfinementTest`, which breaches each one and
watches the breach stopped. Treat an unconformed mechanism's list as a promise,
not a measurement.

### Acting on it

| Detail says | Do |
|---|---|
| A kernel facility this OS does not have | Switch mechanism (`Mechanism.Docker` on macOS) or move to Linux |
| A facility present but not permitted to this process | Re-run with the privilege the detail names |
| A build artefact absent (`netns_nif` not compiled) | Install a C compiler and recompile; the build warned, it did not fail |

Refusals are also emitted as telemetry — `ExSandbox.Telemetry` fires on the
refusal path specifically because a mechanism declining to start is correct but
otherwise invisible behaviour.

## 2. `{:error, {:could_not_run, reason}}` from `execute/3`

Three returns, three different facts, and collapsing any two breaks a
requirement:

| Return | Means |
|---|---|
| `{:ok, %{exit_status: n}}` | The command **ran**. Non-zero is a *result*, not an error. |
| `{:error, {:could_not_run, reason}}` | The command **did not run** — sandbox gone, binary absent, mechanism could not reach in. |
| `{:error, {:limit_exceeded, capability}}` | The command was **stopped** by a limit it was launched under. |

⚠️ `{:could_not_run, _}` is not an exit status and must never be reported as
one. `008-FR-016` and `008-FR-026` both rest on it: mapping "the sandbox was
gone" onto a non-zero exit converts an *unperformed* check into a *failed* one,
and a failed check consumes a refinement iteration that `FR-026` says it must
not.

This is a live trap, not a hypothetical. MEASURED 2026-09-10, Docker engine
27.4.0: running a binary that does not exist inside the container produces exit
**126** with `OCI runtime exec failed: … executable file not found in $PATH` on
**stdout** and an empty stderr — so a mechanism that classifies by stderr alone
returns `{:ok, %{exit_status: 126}}` and reports "your test suite failed" for a
sandbox that never ran it. `Mechanism.Docker` now gates on the wording *and*
status ∈ `[126, 127]`.

The residual is stated rather than hidden: a tenant command that itself prints
`OCI runtime exec failed` and exits 126 is misclassified. A tenant that exits 126
on its own without that wording is correctly a result.

## 3. `⚠️ capability unavailable` from the conformance suite

The third outcome, distinct from pass and fail (`FR-011`, `FR-012b`):

| Suite observes | Verdict |
|---|---|
| Breach attempted, stopped | ✅ guarantee holds |
| Breach attempted, **not** stopped | ❌ mechanism failed |
| Breach cannot be attempted on this host | ⚠️ capability unavailable |
| Mechanism present, breach **never attempted** | ❌ not evidence — unavailable |

"This host cannot demonstrate the guarantee" and "this mechanism breached the
guarantee" lead to opposite actions. A ⚠️ row is not a passing row: it is an
untested boundary, and a report of all ⚠️ is a report that nothing was verified.

⚠️ **A green `mix test` on macOS says nothing about containment.** Six of `005`'s
ten success criteria rest on Linux kernel facilities with no macOS equivalent, so
`:isolation` and `:reclamation` are excluded there — visibly not run rather than
vacuously passing. The run prints its own disclaimer:

```
005: skipping isolation, reclamation tests on darwin.
Six of ten success criteria are NOT verified by this run.
```

To convert ⚠️ into ✅ or ❌, run the container:

```bash
docker compose -f docker/compose.isolation.yml up --build --abort-on-container-exit --exit-code-from isolation isolation
```

## See also

  * [Why refusal is the design](../explanation/refusal.md) — the reasoning, and the four times this library shipped the opposite defect
  * [How to implement a mechanism](implement-a-mechanism.md) — what your `required_capabilities/0` and `constructed_capabilities/0` must say
  * `ExSandbox.Capability` — the vocabulary and what each name means on each platform
