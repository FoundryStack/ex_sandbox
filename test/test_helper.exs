# ⚠️ Six of `005`'s ten success criteria cannot be verified on this machine.
#
# `SC-001` (process isolation), `SC-002` (cluster isolation), `SC-003` (atom
# reclamation), `SC-004` (resource caps), `SC-006` (filesystem confinement), and
# `SC-008` (privilege separation) all rest on Linux kernel facilities — cgroup
# v2, user and mount namespaces, `setpriv`, `bwrap`. macOS has no equivalent
# that `005` accepted (see research R9b: `taskpolicy -m` is silently lost across
# an intervening exec, which fails *open*).
#
# So the `:isolation` and `:reclamation` tags are excluded off Linux. This makes
# `mix test` green locally, and that greenness is exactly the thing to be
# careful about: **a green local run says nothing about whether tenant code is
# contained.** If you are reading this while deciding whether a change is safe
# to ship, the local run is not the evidence you want.
#
# ## Run them here, without waiting for CI
#
#     docker compose -f docker/compose.isolation.yml up --build \
#       --abort-on-container-exit --exit-code-from isolation isolation
#     # results: docker/results/suite.log, census: docker/results/census.txt
#
# ⚠️ Not `run --rm ... isolation sh -c ...`. A container command displaces
# systemd as PID 1, `probe_cgroups/0` then reports no cgroup delegation, and
# every isolation check fails with an R9 refusal that reads as a mechanism
# defect rather than as an artefact of how it was launched (measured: 5/33).
#
# That container is a real Linux host with systemd as PID 1, cgroup v2
# delegation, `setpriv`, and `bwrap` -- all five capabilities genuinely
# constructed, not stubbed. It has found more than a dozen defects in code that
# passed every test on this machine, including a launch path that failed on
# *every* Linux host. Prefer it to a CI round-trip.
#
# ## The defects share one shape, and it is worth knowing before you debug here
#
# Most of them were **caused by the confinement working**. `:erpc` cannot reach a
# sandbox that has no network interfaces. `:os.getpid()` inside a pid namespace
# answers `2`. Distribution cannot start without a network, so a *named* peer
# aborts at boot. Elixir's stdlib is `:undef` inside a bare `erl`. In each case
# the stronger the isolation, the more reliably the code broke -- and several
# failed toward a *passing* test: `{:error, :undef}` and `:enoent` both satisfy
# "the sandbox could not do this" just as convincingly as a real boundary does.
#
# So when something here fails, ask first whether the test is reaching the
# sandbox the way the sandbox can actually be reached, and whether a passing
# assertion is measuring the boundary or measuring its own mistake.
linux? = match?({:unix, :linux}, :os.type())

# ⚠️ Linux is necessary and not sufficient. These tests launch a real sandbox,
# and the mechanism *refuses* to launch when any capability it requires is
# missing (R9, Principle II) -- correctly, because a partially confined tenant
# is worse than none.
#
# Left un-excluded on such a host, every one of them reports a **failure of the
# guarantee it names**. Measured: when `network_restriction` began reporting its
# true value, nineteen tests failed, among them "a sandbox cannot see the
# platform's processes" and "one sandbox halting leaves the platform serving".
# Neither had stopped being true; there was no sandbox to try them in.
#
# That is the same false report the conformance census avoids with its third
# outcome, arriving at the layer that has no third outcome to give -- ExUnit
# knows only pass and fail, so the honest answer has to be "not run".
missing_capabilities =
  if linux? do
    ExSandbox.Hardening.Linux.capabilities()
    |> Enum.reject(fn {_name, present?} -> present? end)
    |> Enum.map(&elem(&1, 0))
  else
    []
  end

# ⚠️ The CAPABILITY decides `excluded`, and the operating system is only the
# cheapest way to be sure the capability is absent. This line used to read
# `if linux?, do: [], else: [...]`, on the argument that a capability shortfall
# must never be expressed here -- `run-isolation-tests.sh` passes
# `--include isolation --include reclamation`, `--include` re-admits an excluded
# tag, so an exclusion here is inert inside the container and "changes the local
# run and nothing else".
#
# ⚠️ That argument was right about the mechanism and wrong about the population.
# There is a third kind of host besides "macOS" and "the isolation container": a
# **Linux machine with none of the capabilities**, and it is the one CI runs on.
# MEASURED, run 32590944743 on `main`: `library-boundary (ex_sandbox)` -- the job
# `ci.yml` calls required and "not a lint job" -- failed **32 tests**, every one
# of them `NOT DEMONSTRATED (host capability unavailable)`. `ubuntu-latest`
# carries no `bwrap` and no `pasta`, so `probe_mount_namespace/0` and
# `probe_network_policy/0` are both false and the mechanism refuses to provision,
# correctly. A required gate that cannot pass is not a gate, and the tests it
# was supposed to enforce were therefore running NOWHERE in automation.
#
# Predicating on the capability makes that host behave like macOS: excluded,
# with the red banner below saying out loud that nothing was verified. Two
# separate guards stop this from becoming a silent pass on a host that OUGHT to
# be capable:
#
#   * `--include` still wins inside the container, so an accidental edit here
#     cannot shrink the run that matters. That was the original point and it
#     still holds.
#   * `run-isolation-tests.sh` refuses outright, non-zero, when NO capability is
#     present -- so a container that fails to construct its hardening fails the
#     job rather than skipping quietly.
#
# `ExSandbox.Test.IsolationLaunch.provision_or_skip/2` remains the backstop for
# a host that reports a capability and then fails at the point of provisioning.
excluded = if linux? and missing_capabilities == [], do: [], else: [:isolation, :reclamation]

# ⚠️ The mirror image of the block above, and it exists for the same reason
# pointed the other way (014 T003).
#
# `014`'s Darwin tests establish their caps by **breaching them and watching
# macOS stop it** -- a 300 MB allocation under a 100 MB `taskpolicy -m` cap, a
# spinner under `RLIMIT_CPU`, a `sandbox-exec` profile. None of those
# mechanisms exists on Linux. Run there, every one of them would report a
# failure of a guarantee that was never this host's to give; excluded *without
# being named*, they would be worse -- a Linux CI run would go green having
# verified nothing about the macOS floor, which is precisely the false
# confidence `FR-014a` is written against.
#
# So they are ABSENT and SAID TO BE ABSENT: ExUnit reports the count as
# "N excluded", which is a different sentence from "N tests, 0 failures".
#
# ⚠️ This exclusion only reaches a test module that TAGS ITSELF. A `014` test
# file must carry `@moduletag :darwin_hardening` (or per-test `@tag`); an
# untagged Darwin test runs on Linux and fails there for a reason that reads as
# a mechanism defect. `ExSandbox.Hardening.DarwinTagTest` asserts this
# exclusion is configured, and carries a canary that FAILS rather than passes
# if a `:darwin_hardening` test ever executes off Darwin.
#
# ⚠️ Kept separate from `excluded` above rather than folded into it. That list
# is quoted verbatim in the two warnings below, which are about the *isolation*
# shortfall; appending an unrelated tag would make a Linux capability warning
# announce it was skipping macOS tests.
darwin? = match?({:unix, :darwin}, :os.type())
darwin_excluded = if darwin?, do: [], else: [:darwin_hardening]

# ⚠️ The same argument again, for a mechanism whose capabilities come from a
# container runtime rather than from this kernel (`host-sandbox-and-agent-workspace`).
#
# `ExSandbox.Mechanism.Docker` builds its own confinement, so its tests cannot
# be predicated on a host capability the way the two blocks above are -- the
# whole point of that mechanism is that the host lacks what it needs. What they
# CAN be predicated on is whether a daemon answered, and that is a fact about
# this machine that `ExSandbox.Test.DockerDaemon` asks once, before anything is
# excluded.
#
# ⚠️ Exclusion alone is not enough, and this is the failure the `014` block
# above already records: a group that is quietly absent reads as "0 failures".
# `ExSandbox.Mechanism.DockerTagTest` carries the canary -- a `:docker` test
# that FAILS if it executes on a host with no daemon -- so a missed exclusion
# lands as a failure rather than as a green run that verified no container.
docker_reachable? = ExSandbox.Test.DockerDaemon.reachable?()
docker_excluded = if docker_reachable?, do: [], else: [:docker]

cond do
  not linux? ->
    IO.puts("""
    \n\e[33m005: skipping #{Enum.join(excluded, ", ")} tests on #{elem(:os.type(), 1)}.
    Six of ten success criteria are NOT verified by this run.\e[0m
    """)

  missing_capabilities != [] ->
    # ⚠️ Louder than the macOS notice, deliberately. Off Linux nobody mistakes a
    # green run for evidence. On Linux they might -- the suite looks like it ran
    # somewhere it could have verified everything, and the excluded tests are
    # exactly the ones that would have caught a containment defect.
    #
    # ⚠️ This branch USED TO LIE, and reading CI's output is what showed it.
    # While `excluded` was decided by the OS alone, reaching here meant
    # `excluded == []` -- so it printed "skipping  tests" with an empty list and
    # then "they are NOT RUNNING" about 32 tests that were running and failing
    # in the lines directly below. The banner and the run disagreed, and the
    # banner is what a reader believes; `sandbox_gateway`'s own test_helper
    # records the same failure shape from the other direction. Predicating
    # `excluded` on the capability is what makes both sentences true.
    IO.puts("""
    \n\e[31m005: skipping #{Enum.join(excluded, ", ")} tests on a Linux host that
    CANNOT LAUNCH A SANDBOX. Missing: #{Enum.join(missing_capabilities, ", ")}.

    These tests are not passing -- they are NOT RUNNING. Every containment
    guarantee they cover (process, cluster, filesystem, privilege, resource
    caps) is UNVERIFIED by this run. A green result here is not evidence that
    tenant code is contained.

    Fix the capability and re-run; do not read this as success.\e[0m
    """)

  true ->
    :ok
end

if docker_excluded != [] do
  IO.puts("""
  \n\e[33mhost-sandbox-and-agent-workspace: skipping #{Enum.join(docker_excluded, ", ")} tests.
  #{ExSandbox.Test.DockerDaemon.unreachable_reason()}

  `ExSandbox.Mechanism.Docker`'s resource caps, network denial and filesystem
  confinement are NOT verified by this run. Start a container runtime and
  re-run before reading this as evidence that a Docker-backed sandbox confines
  anything.\e[0m
  """)
end

if darwin_excluded != [] do
  IO.puts("""
  \n\e[33m014: skipping #{Enum.join(darwin_excluded, ", ")} tests on #{elem(:os.type(), 1)}.
  The macOS resource-cap floor (memory, CPU, wall clock, sandbox-exec) is NOT
  verified by this run.\e[0m
  """)
end

ExUnit.start(exclude: excluded ++ darwin_excluded ++ docker_excluded)
