defmodule ExSandbox.Mechanism.Beam.LatencyTest do
  @moduledoc """
  Cold-start latency against `SC-005` (005 T044, R8).

  ## The 95th percentile, not the mean

  `SC-005` is "ready to serve within 5 seconds in **95% of attempts**". A mean
  satisfies that criterion while a quarter of provisions take twelve seconds,
  and the tenant who waited twelve seconds is the one who notices. So this
  measures the distribution and asserts on p95, reporting the mean and the max
  alongside it for diagnosis.

  ## ⚠️ If this fails, a warm pool is not the answer

  R8 anticipated the temptation and ruled it out. A pre-started node has already
  been launched under **some** uid, in **some** cgroup, with **some**
  environment. Assigning it to a tenant afterwards means either:

    1. it was started with that tenant's identity — so it is a per-tenant pool,
       and the memory it saves is the memory the pool holds; or
    2. it was started generically and is adjusted at assignment — but a running
       process cannot change its uid (that is what `setpriv` is *for*), and
       reassigning a cgroup mid-flight is precisely the "carefully restricted
       shared runtime" the spec's Assumptions forbid.

  Either way the isolation story breaks, and it breaks silently: the sandbox
  still starts, still serves, still passes every functional test. So a failure
  here is a reason to make the launch faster, not to stop launching.
  """
  use ExUnit.Case, async: false

  @moduletag :isolation
  @moduletag :latency

  # Long enough to be a distribution rather than an anecdote, short enough that
  # the suite stays runnable. 20 samples put p95 at the 19th value, so a single
  # slow outlier is visible rather than averaged away.
  @samples 20
  @target_ms 5_000
  @percentile 0.95

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  test "provision-to-ready is within #{@target_ms}ms at p#{trunc(@percentile * 100)}" do
    durations =
      for i <- 1..@samples do
        sandbox = %Sandbox{
          id: "latency-#{i}-#{System.unique_integer([:positive])}",
          owner_ref: "latency-owner",
          template_ref: "conformance-template",
          cpu_limit: 500,
          memory_limit_mb: 128,
          disk_quota_mb: 64
        }

        started = System.monotonic_time(:millisecond)
        {:ok, provisioned} = Beam.provision(sandbox)

        # "Ready to serve", not "the call returned". A sandbox that has been
        # launched but cannot yet answer is not ready, and timing only the
        # provision call would report a number no tenant experiences.
        {:ok, _} = Beam.call(provisioned, :erlang, :system_info, [:process_count])
        elapsed = System.monotonic_time(:millisecond) - started

        :ok = Beam.destroy(provisioned)
        elapsed
      end

    sorted = Enum.sort(durations)
    p95 = Enum.at(sorted, min(trunc(@percentile * @samples), @samples - 1))
    mean = Enum.sum(durations) / @samples

    IO.puts("""

    005 SC-005 cold-start latency over #{@samples} samples:
      p#{trunc(@percentile * 100)}:  #{p95}ms   (target #{@target_ms}ms)
      mean: #{Float.round(mean, 1)}ms
      min:  #{List.first(sorted)}ms
      max:  #{List.last(sorted)}ms
    """)

    assert p95 <= @target_ms,
           """
           cold start missed SC-005: p#{trunc(@percentile * 100)} was #{p95}ms against a #{@target_ms}ms target.

           ⚠️ Do NOT reach for a warm pool (R8). A pre-started node has already
           been launched under some uid, in some cgroup, with some environment,
           and a running process cannot change its uid — that is what `setpriv`
           is for. The isolation story breaks silently, because the sandbox
           still starts and still serves.

           Make the launch faster instead: the time is in `:peer`'s boot wait,
           the hardening command's exec chain, and storage preparation.

           Full distribution: #{inspect(sorted)}
           """
  end
end
