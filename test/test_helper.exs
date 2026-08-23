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

# ⚠️ Only the OS decides `excluded`. A capability shortfall must NOT be
# expressed here, and the reason is measured: `run-isolation-tests.sh` passes
# `--include isolation --include reclamation` precisely so that an accidental
# edit to this file cannot silently shrink the run. `--include` re-admits an
# excluded tag, so an exclusion added here is overridden inside the very
# container where it would matter -- it changes the local run and nothing else.
#
# The capability shortfall is handled where `--include` cannot reach it:
# `ExSandbox.Test.IsolationLaunch.provision_or_skip/2` refuses at the point of
# provisioning, naming the missing capability. The warning below still fires so
# the shortfall is impossible to miss.
excluded = if linux?, do: [], else: [:isolation, :reclamation]

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

if darwin_excluded != [] do
  IO.puts("""
  \n\e[33m014: skipping #{Enum.join(darwin_excluded, ", ")} tests on #{elem(:os.type(), 1)}.
  The macOS resource-cap floor (memory, CPU, wall clock, sandbox-exec) is NOT
  verified by this run.\e[0m
  """)
end

ExUnit.start(exclude: excluded ++ darwin_excluded)
