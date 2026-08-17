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

ExUnit.start(exclude: excluded)
