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
# constructed, not stubbed. It was worth building: the first run found seven
# defects in code that had passed every test on this machine, including a launch
# path that failed on *every* Linux host. Prefer it to a CI round-trip.
linux? = match?({:unix, :linux}, :os.type())

excluded = if linux?, do: [], else: [:isolation, :reclamation]

if excluded != [] do
  IO.puts("""
  \n\e[33m005: skipping #{Enum.join(excluded, ", ")} tests on #{elem(:os.type(), 1)}.
  Six of ten success criteria are NOT verified by this run.\e[0m
  """)
end

ExUnit.start(exclude: excluded)
