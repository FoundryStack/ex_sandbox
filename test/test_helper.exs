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
#     docker compose -f docker/compose.isolation.yml run --rm --build isolation
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

excluded = if linux?, do: [], else: [:isolation, :reclamation]

if excluded != [] do
  IO.puts("""
  \n\e[33m005: skipping #{Enum.join(excluded, ", ")} tests on #{elem(:os.type(), 1)}.
  Six of ten success criteria are NOT verified by this run.\e[0m
  """)
end

ExUnit.start(exclude: excluded)
