# Why this library cites documents that are not in it

`ex_sandbox` was an application inside the Axonn umbrella until 1.0.0, and it was moved out with
`git subtree split` so that its 143 commits came with it. The code came. The specification tree it
was written against did not, because that tree describes a platform this library is only one part
of.

The comments and docstrings here cite that tree constantly, and deliberately. This project's
convention is that a claim about behaviour names the thing that measured it, so a comment saying a
`pasta` ordering hazard is real names the probe script that demonstrated it. Stripping those
citations during the extraction would have converted measured statements into assertions, which is
the change this codebase is least willing to make. They were kept instead, and this page is what
makes them resolvable.

`test/documentation_pointers_test.exs` enforces the split below. A backticked filename anywhere in
`lib/`, `test/`, or `mix.exs` must either resolve in this repository or be listed there as one of
the three kinds of absence described here. A name that is neither is a broken pointer, and that
test is the thing that fails.

## 1. Artefacts that stayed in the umbrella

Reachable only in the originating repository. Cited for provenance, never as something a reader of
this package is expected to open.

| Name | What it is |
|---|---|
| `contracts/egress.md`, `contracts/hardening.md` | The interface contracts the egress and hardening subsystems were built to satisfy. The requirement IDs they define (`005-FR-011a` and the rest) are explained in [requirement-ids.md](requirement-ids.md), which did come across. |
| `012/contracts/execution-seam.md`, `008/data-model.md` | Contracts belonging to numbered features that own other parts of the platform. |
| `egress-path-measurements.md` | The measurement log for the egress path. Every numbered defect cited from a comment here is one of its entries. |
| `spec.md`, `quickstart.md` | Per-feature specification and operator walkthrough. |
| `docs/legacy/specify/014-desktop-deployment/spikes/darwin-hardening/baseline.md`, `spin.c` | The darwin hardening spike and the fixture it measured against. `test/support/darwin_fixtures/spin_nolimit.c` is this repository's deliberately-different sibling of that fixture, and says so. |
| `docker/launch-ordering-probe.sh`, `docker/wired-egress-e2e.sh`, `docker/netns-first-e2e.sh`, `docker/acceptor-e2e.sh`, `docker/unprivileged-census-probe.sh`, `docker/acceptor-mark-probe.py`, `docker/loopback-redirect-probe.py`, `docker/compose.memtiming.yml` | One-off probes, each written to settle one question and kept where it was written. The `docker/` directory here holds the isolation harness, which is a different thing: it runs on every change, and it is the reason `docker/census-baseline.txt` exists. |
| `library_boundary_test.exs`, `delegated_launch_test.exs`, `provision.ex`, `apps/axonn/test/axonn/model_access/credential_leak_test.exs` | Umbrella modules and tests. Where this repository has its own equivalent, the comment names both. |

⚠️ **A citation here is not a dependency.** Nothing in this library reads any of these files at
build time or at run time, and no consumer needs them. The isolation harness under `docker/` is
self-contained, and `mix test` needs nothing outside this tree.

## 2. This repository's own deleted history

Reachable with `git log`. These are named in comments that explain why the current code has the
shape it has, and naming the thing that was removed is the point.

`priv/egress/nsacceptor.py` was the Python listener the egress acceptor used to be, deleted in
1.1.0 when `setns(2)` made a namespace-local socket possible from the BEAM.
`pool_relay_wiring_test.exs` and `pool_transport_test.exs` were the two test files that justified
`ExSandbox.Egress.Pool`'s host listener; they were moved onto `ExSandbox.Egress.Acceptor` and
renamed when that listener was removed, and `ExSandbox.Egress.Decision` records why.
`pool_decide_test.exs` was renamed to `decision_test.exs` in the same commit, and the pointer to it
that stayed behind in `test/egress/supervision_test.exs` is the one this page's test was written for.

## 3. Produced rather than committed

Absent from a clean checkout by design.

`priv/netns_nif.so` is built from `c_src/netns_nif.c` by `Mix.Tasks.Compile.NetnsNif`, in the
consumer's own tree, and is excluded from the package so a maintainer's architecture never ships.
`docker/results/census.txt` and `docker/results/suite.log` are one isolation run's output.
`secret.txt` is a fixture a hardening test writes and then proves is unreadable.

## 4. In the repository, not in the isolation image

`docker/Dockerfile.isolation` copies the working tree, and `.dockerignore` holds back `.git/` and
`.github/` because a runtime image has no use for either. `.github/workflows/ci.yml` is therefore
cited by `test/test_helper.exs` and present on every developer machine and every CI checkout, and
absent from the one place the suite also runs.

The check resolves a name against the filesystem before it consults its allowlist, so on a full
checkout `ci.yml` resolves normally and this category is never reached. It exists so the suite
passes inside the container without the check having to be weakened everywhere else.
