# Requirement IDs

The source in this library cites requirement identifiers heavily — `005-FR-011`, `003-FR-024`,
`029 T015`, `012-FR-016a`. There are roughly 350 of them across 45 of the 48 modules. This page
explains what they are so they read as citations rather than noise.

## Why they are still here

This library was extracted from a larger application whose codebase writes reasoning next to
code: moduledocs cite the requirement a decision serves, record what was **MEASURED** rather than
assumed, and mark load-bearing choices with a ⚠️. The identifiers are load-bearing in that style —
they say *which* rule a piece of code exists to satisfy, which is usually the fastest answer to
"why is this like this".

They were deliberately **not** stripped during extraction. Many sentences are built around the
citation grammatically ("`012-FR-001` forbids Ash, so this cannot delegate to a repo"), and
mechanically removing the token would leave prose that is worse than the shorthand. The tradeoff
accepted here is that an outside reader meets an unfamiliar identifier and needs this page once.

## And the name `Axonn`

The same docs mention `Axonn` — `Axonn.Sandbox.Provision`, `Axonn.ModelAccess.Backend.DelegatedCli`,
"Axonn's copy of this script". That is the application this library was extracted from. Nothing
here depends on it, references it at compile time, or needs it to run; `test/dependency_tree_test.exs`
enforces that.

The mentions are kept for the same reason the identifiers are: they name the concrete caller a
decision was measured against. "A host that tracks placements" is abstract, and the reasoning is
easier to check when the host is a real one. Read them as provenance — *this is who hit the problem
that produced this rule* — never as a dependency.

## Reading one

    005 - FR - 011
    │     │     │
    │     │     └── the requirement's number within that document
    │     └──────── the kind
    └────────────── the specification the requirement belongs to

Both `005-FR-011` and `005 FR-011` appear; the separator carries no meaning. A trailing letter
(`012-FR-016a`) marks a requirement refined after its first statement.

### Kinds

| Prefix | Meaning |
|---|---|
| `FR` | Functional requirement — a rule the implementation must satisfy |
| `NFR` | Non-functional requirement — performance, operability, security posture |
| `SC` | Success criterion — an observable condition that decides whether the feature is done |
| `T` | Task — a unit of the implementation plan, e.g. `005 T060a10` |
| `R` | Research finding — a measurement recorded before a decision, e.g. `research R2`, `R9` |

A `T` citation usually explains *when* something arrived and what it replaced. An `R` citation
points at evidence: `R2` and `R9` in particular are cited often, and both record measurements that
overturned an earlier assumption.

## The specifications

Each number is one specification in the originating application. They are not distributed with
this package — the ones that matter to a reader here are summarised by the code that cites them.

| ID | Specification | What it contributes to this library |
|---|---|---|
| `003` | sandbox-contract | The sandbox lifecycle contract and the conformance suite that enforces it. The most-cited (116 references) — most of `ExSandbox.Conformance` traces here. |
| `005` | sandbox-beam | The BEAM mechanism, Linux hardening, and the egress work under `T060`. Source of the refusal-over-partial-confinement rule. |
| `007` | agent-runtime | Consumer-side context for how sandboxes are driven. |
| `008` | generation-verification | Evidence and verification requirements — why a claim needs an observed breach behind it. |
| `010` | observability | Telemetry event shape. |
| `012` | sandbox-libraries | **The extraction itself**: `FR-001` (no host application, no Ash, no web framework), `FR-004` and `FR-014` (the public/private boundary), `FR-016` (the third outcome). See [boundary.md](../priv/boundary.md). |
| `013` | deployment-topology | Deployment separation, and the narrowed privilege grant the isolation harness runs under (`FR-006b`, `FR-006f`). |
| `014` | desktop-deployment | The macOS resource-cap floor — the `:darwin_hardening` tagged tests. |
| `015` | model-access | Consumer-side context for credential handling. |
| `029` | sandbox-reachability | Egress reachability: hostname allowlists, the DNS resolver, and what a sandbox is permitted to reach. |

## The three that explain the most

If you read only a few, these carry the reasoning that shapes the whole library:

- **`012-FR-001`** — this library depends on Elixir/OTP and `:telemetry`, and nothing else. It is
  why there is no repo, no schema, and no credential probe here, and why the conformance suite's
  credentials group reports "host capability unavailable" rather than passing.
- **`012-FR-016`/`016a`** — conformance scores **three** outcomes, not two: pass, guarantee
  failure, and capability unavailable. Collapsing the third into a failure produces breach reports
  for boundaries that were never tested.
- **`005` R9** — a host that cannot enforce confinement gets a refusal, not a weaker sandbox. A
  partially confined tenant is worse than none, because it looks contained.
