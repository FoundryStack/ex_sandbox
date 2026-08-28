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

## Two traps this directory has already fallen into

⚠️ **No `command:` override, and no `docker compose run`.** A container command becomes PID 1 and
displaces systemd, so `probe_cgroups/0` reports no delegation, `available?/0` goes false, and every
isolation test skips — the container exits 0 having verified nothing, which is the exact failure
this harness exists to eliminate. The suite runs as a systemd unit instead
(`isolation-tests.service`).

⚠️ **`.dockerignore` must exclude `_build` and `deps`.** The image compiles the dependency tree in
its own cached layer and only then runs `COPY . .`. Without those two lines the copy lands the
macOS-built artifacts on top of the Linux ones, and a Mach-O object dlopen'd by a Linux runtime
fails with `invalid ELF header` — the image builds fine and the suite dies on load, which reads as
a defect in the code under test rather than in how it got there.
