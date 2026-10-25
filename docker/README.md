# The isolation harness

A real Linux host with systemd as PID 1, cgroup v2 delegation, and all five hardening
capabilities genuinely constructed. This is where `:isolation` and `:reclamation` run.

```bash
docker compose -f docker/compose.isolation.yml up --build \
  --abort-on-container-exit --exit-code-from isolation isolation
```

Results land in `docker/results/` — `suite.log` and `census.txt` — because systemd routes unit
output to the journal and the journal dies with the container (`docker logs` returns zero bytes).

⚠️ Both flags are load-bearing. Without `--abort-on-container-exit` compose waits on a container
that has already finished; without `--exit-code-from isolation` a failing suite exits 0.

## What the exit status means

The census gate is the container's exit status. It scores three outcomes, not two
(`012-FR-016a`):

| | Meaning | Effect on exit |
|---|---|---|
| `passed` | The guarantee was demonstrated | — |
| `failed` | The mechanism breached a guarantee | non-zero |
| `unavailable` | This host cannot demonstrate the check | none, up to the baseline |

Eight checks report `unavailable` here and are expected to: six credentials checks and two
network-confinement ones. This package has no data store to probe (`012-FR-001`), so it supplies
no credential probe. A consumer that has a database instantiates the same suite with its own probe;
that is where those checks get demonstrated. `census-baseline.txt` caps the number, so a
guarantee quietly *becoming* unavailable is a failure rather than a shrug.

## The gate is falsified, not assumed

A green run only means something if a red one is reachable. Recorded 2026-08-28, first two runs of
this harness on `Linux 6.10.14-linuxkit` (cgroup `cgroup2fs`, storage `ext2/ext3`, all five
capabilities `ok`):

**Unmodified** — exit `0`, 236.8s:

```
passed=702
unavailable=8
failed=0
invalid=0
ran=710

No mechanism defects in isolation + reclamation. 8 check(s) reported the third
outcome (host capability unavailable), which is neither a pass nor a defect.
(baseline for isolation + reclamation: at most 8)
```

**With one containment assertion inverted** — `IsolationFilesystemTest`'s "platform configuration
files are unreachable" changed to demand that a confined sandbox *can* read a host file — exit `2`:

```
passed=701
unavailable=8
failed=1
invalid=0
ran=710

FAILED ExSandbox.Mechanism.Beam.IsolationFilesystemTest.test platform configuration files are unreachable

The isolation + reclamation phase reported 1 genuine failure(s) -- see above.
```

The mutation was reverted immediately; the working tree is clean.

⚠️ The `unavailable` count is **8 in both runs**, and that is the part worth reading. The gate
moved the mutated check into `failed` rather than absorbing it into the third outcome. A gate that
could not tell those apart would report a real breach as "this host could not check" and exit 0.

## The gate has its own test

```bash
bash docker/census-gate-test.sh
```

No BEAM, no Docker, no container — it sources `census-gate.sh` and drives it through every census
shape it claims to handle: a missing census, `ran=0`, a truncated one with no `failed=` line, a
genuine failure alongside a suite that exited 0, and the `unavailable` ceiling in both directions.
Its last section reads the real `census_gate` invocations out of `run-isolation-tests.sh` and
fails if any resolved baseline key is absent from `census-baseline.txt` — the defect that once
left a phase ungated for as long as the baseline file had existed.

CI runs it in the boundary job, not the nightly one: an hour's wait to learn the gate is broken is
an hour the gate was not gating.

## ⚠️ Docker Desktop's 7.0 kernel refuses the unprivileged grant

Measured 2026-10-22 on Docker 29.8.2, `Linux 7.0.14-linuxkit`: with the grant below, `bwrap`
fails with `pivot_root: Operation not permitted`, `capabilities/0` reports
`filesystem_confinement` and `network_restriction` missing, and the gate exits 2. v1.4.0 fails the
same way, so the host changed, not the code. With `privileged: true` added in an override file the
same tree reports all five `ok` and passes, which shows the code works and nothing about
`013-FR-006b`. Until the minimal grant is found again, a green gate needs a host where it holds.

## Two traps this directory has already fallen into

⚠️ **No `command:` override, and no `docker compose run`.** A container command becomes PID 1 and
displaces systemd, so `probe_cgroups/0` reports no delegation, `available?/0` goes false, and every
isolation test skips — the container exits 0 having verified nothing, which is the exact failure
this harness exists to eliminate. The suite runs as a systemd unit instead
(`isolation-tests.service`).

⚠️ **`.dockerignore` must exclude `_build` and `deps`.** The image runs `COPY . .` and then
compiles. Without those two lines the copy lands the macOS-built artifacts in the tree, and a
Mach-O object dlopen'd by a Linux runtime fails with `invalid ELF header` — the image builds fine
and the suite dies on load, which reads as a defect in the code under test rather than in how it
got there. A consumer's `.dockerignore` carries the same two lines.

## Running it from a consumer

A repository that depends on ex_sandbox as a git dependency runs this directory's files from its
`deps/ex_sandbox/docker/`, with its own context, tests and baseline. The variables and their
defaults are tabled at the head of `compose.isolation.yml`; every default is this repository's
own run. A consumer with a database credential probe sets, for example:

```bash
harness="$(cd deps/ex_sandbox/docker && pwd -P)"
export ISOLATION_PROJECT=my-app-isolation ISOLATION_IMAGE=my-app-isolation:latest \
  ISOLATION_CONSUMER_DIR="$PWD" ISOLATION_HARNESS_DIR="$harness" \
  ISOLATION_DOCKERFILE="$harness/Dockerfile.isolation" \
  ISOLATION_RESULTS_DIR="$PWD/docker/results" \
  COMPOSE_PROFILES=database ISOLATION_APT_PACKAGES=postgresql-client \
  ISOLATION_ENV="MY_DB_HOST=postgres MY_DB_PORT=5432" \
  ISOLATION_SETUP="mix ecto.setup" ISOLATION_TESTS="test/my_app/conformance_test.exs" \
  ISOLATION_CENSUS_KEY=credentials
docker compose -f "$harness/compose.isolation.yml" up --build \
  --abort-on-container-exit --exit-code-from isolation isolation
```

The baseline (`ISOLATION_CENSUS_BASELINE`, default `docker/census-baseline.txt`) is read from the
consumer's tree, and the runner refuses to start when `ISOLATION_CENSUS_KEY` has no line in it: an
absent key would leave the phase ungated.
