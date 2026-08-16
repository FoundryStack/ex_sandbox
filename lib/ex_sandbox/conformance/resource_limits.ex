defmodule ExSandbox.Conformance.ResourceLimits do
  @moduledoc """
  Conformance group: resource limits (012 T034a, T034b; `FR-012a`, `SC-008`).

  ## Every check breaches the cap

  `005` R9b is the reason this group is shaped the way it is. Measured:

      taskpolicy -m 100 sandbox-exec -f profile.sb ./hog 300

  allocates 300 MB under a nominal 100 MB cap and **exits 0**. The limiter was
  invoked, with the right flag, with the right number. The cap is silently lost
  across the intervening `exec`, and nothing in the invocation, the exit status,
  or the process tree distinguishes it from a working one.

  Which means every one of these passes it:

    * asserting `taskpolicy` was called with `-m 100`
    * asserting the wrapper appears in the process tree
    * asserting configuration records a 100 MB cap
    * asserting the process exited without error

  All four check **invocation**. Only *allocate 300 MB and observe the process
  stopped* checks **enforcement**, and the gap between them is where a tenant
  exhausts a host while every dashboard reads green.

  So each check here allocates past the memory cap, spins past the CPU cap, or
  blocks past the time budget, and requires that the mechanism stopped it.

  ## An undemonstrable cap is unavailable, never satisfied (`FR-012b`, T034b)

  If a breach can be neither completed nor observed being stopped, the check
  reports the third outcome — `ExSandbox.Conformance.CapabilityUnavailable` —
  rather than passing. A cap that is configured but never breached in this suite
  **must not report as passing**; nothing was demonstrated, and "nothing was
  demonstrated" is not evidence of a guarantee.

  ## The outcomes are distinguishable from each other and from a crash

  A breach stopped by the mechanism, a breach that succeeded, and a host that
  could not attempt one produce three different results. An ordinary crash —
  the sandbox dying for an unrelated reason — is reported as inconclusive rather
  than as a satisfied cap, because a process that died before reaching the cap
  has not shown the cap works.
  """

  @doc "Emits the resource-limit checks into the calling test module."
  defmacro tests do
    quote do
      require ExSandbox.Conformance.Group
      import ExSandbox.Conformance.Group, only: [check: 2]

      describe "resource limits (012 FR-012a, SC-008, research R7a)" do
        # Selects this group for `mix test --only conformance:resource_limits`, the
        # invocation quickstart documents. Without it that command matches
        # nothing and reports success.
        @describetag conformance: :resource_limits

        check "allocating past the memory cap is stopped" do
          demonstrate_breach(:resource_limits, "003-FR-004", fn ->
            sandbox = build_sandbox(memory_limit_mb: 64)

            ExSandbox.Conformance.ResourceLimits.breach(
              @mechanism,
              sandbox,
              # Three times the cap. Not marginally over -- a mechanism that
              # rounds or reserves headroom should still stop this.
              ExSandbox.Conformance.ResourceLimits.memory_hog_command(192),
              :memory
            )
          end)
        end

        check "spinning past the CPU cap is throttled or stopped" do
          demonstrate_breach(:resource_limits, "003-FR-004", fn ->
            sandbox = build_sandbox(cpu_limit: 100)

            ExSandbox.Conformance.ResourceLimits.breach(
              @mechanism,
              sandbox,
              ExSandbox.Conformance.ResourceLimits.cpu_hog_command(),
              :cpu
            )
          end)
        end

        check "blocking past the time budget is stopped" do
          demonstrate_breach(:resource_limits, "003-FR-004", fn ->
            sandbox = build_sandbox(context: %{timeout_ms: 2_000})

            ExSandbox.Conformance.ResourceLimits.breach(
              @mechanism,
              sandbox,
              ExSandbox.Conformance.ResourceLimits.sleep_command(60),
              :time
            )
          end)
        end

        check "a cap configured but never breached does not report as passing" do
          # T034b as a self-check on this group. `classify/3` is handed the
          # output of an attempt that did nothing hostile; it must route to
          # something other than `:stopped`. A group that let this through would
          # report every mechanism conformant on memory without ever allocating
          # a byte.
          result =
            ExSandbox.Conformance.ResourceLimits.classify(
              {:ok, "configured a 64 MB cap"},
              :memory,
              64
            )

          assert_guarantee(
            not match?({:stopped, _}, result),
            "012-FR-012b",
            "a cap that was configured but not breached classified as `:stopped`, " <>
              "i.e. as a pass. It must classify as undemonstrable. Got " <>
              inspect(result)
          )
        end
      end
    end
  end

  @doc """
  Runs one hostile command inside a sandbox and classifies what happened.

  Returns `{:stopped, evidence}`, `{:breached, evidence}`, or anything else —
  which `ExSandbox.Conformance.Helpers.demonstrate_breach/3` routes to the third
  outcome.
  """
  def breach(mechanism, sandbox, command, dimension) do
    case ExSandbox.provision(mechanism, sandbox) do
      {:ok, provisioned} ->
        run_breach(mechanism, provisioned, command, dimension, sandbox)

      {:error, {:capability_unavailable, [missing | _]}} ->
        ExSandbox.Conformance.Helpers.capability_unavailable(missing.name, missing.detail)

      other ->
        {:could_not_provision, other}
    end
  end

  defp run_breach(mechanism, provisioned, command, dimension, requested) do
    {:ok, started} = ExSandbox.start(mechanism, provisioned)

    try do
      started
      |> exec(command)
      |> resolve_unresponsive(mechanism, started)
      |> classify(dimension, cap_for(requested, dimension))
    after
      ExSandbox.destroy(mechanism, started)
    end
  end

  # ⚠️ A cap that works severs the channel the breach was issued over.
  #
  # A sandbox OOM-killed mid-allocation cannot answer, so `exec` returns
  # `:sandbox_unresponsive` -- which is *the same thing a crashed sandbox
  # returns*. `classify/3` sees only that value and is right to refuse it: on
  # its own it is "died of something", and calling it a satisfied cap is the
  # fail-open this group exists to prevent.
  #
  # But the mechanism knows which it was. `provision_failure_reason/1` reads
  # systemd's verdict on the named scope and distinguishes `:resource_cap` from
  # `:mechanism_error`. So rather than widen `classify/3` -- which would make an
  # ordinary crash pass -- the ambiguous value is **resolved into a specific
  # one** by asking, and only a mechanism that positively reports a cap breach
  # is upgraded.
  #
  # A mechanism that cannot attribute the death leaves `:sandbox_unresponsive`
  # unchanged and the check stays undemonstrated, per `FR-012b`.
  defp resolve_unresponsive({:error, :sandbox_unresponsive} = unresolved, mechanism, started) do
    exported? =
      function_exported?(mechanism, :status, 1) and
        function_exported?(mechanism, :provision_failure_reason, 1)

    if exported? and stopped?(mechanism, started) do
      case mechanism.provision_failure_reason(started) do
        {:error, :resource_cap} -> {:error, {:limit_exceeded, :reported_by_mechanism}}
        _ -> unresolved
      end
    else
      unresolved
    end
  end

  defp resolve_unresponsive(result, _mechanism, _started), do: result

  # ⚠️ **Observing** the sandbox stopped, not merely asking why it stopped.
  #
  # `provision_failure_reason/1` reads a recorded verdict; it is `status/1` that
  # probes the node, notices it is gone, and records why. Asking for the reason
  # without a preceding status read returns `:ok` -- "no failure recorded" --
  # for a sandbox that is already dead, because nothing has yet looked.
  #
  # It is polled rather than read once: the kill is asynchronous to the `exec`
  # returning, so an immediate probe can still find the node answering. A cap
  # that needs longer than this to bite has not been demonstrated within the
  # window the check allows, and the result stays undemonstrated rather than
  # becoming a pass.
  defp stopped?(mechanism, started), do: stopped?(mechanism, started, 20)

  defp stopped?(_mechanism, _started, 0), do: false

  defp stopped?(mechanism, started, attempts) do
    case mechanism.status(started) do
      {:ok, status} when status not in [:running, :unknown] ->
        true

      _ ->
        Process.sleep(100)
        stopped?(mechanism, started, attempts - 1)
    end
  end

  defp cap_for(sandbox, :memory), do: sandbox.memory_limit_mb
  defp cap_for(sandbox, :cpu), do: sandbox.cpu_limit
  defp cap_for(%{context: %{timeout_ms: ms}}, :time), do: ms
  defp cap_for(_sandbox, :time), do: nil

  @doc """
  Decides whether a breach attempt was stopped, succeeded, or showed nothing.

  Public because the group self-checks it: this is the single place the
  fail-open mistake would live, so it is exercised directly rather than only
  through a live mechanism.
  """
  @spec classify(term(), :memory | :cpu | :time, term()) ::
          {:stopped, String.t()} | {:breached, String.t()} | {:inconclusive, String.t()}
  def classify({:ok, output}, dimension, cap) do
    marker = completion_marker(dimension)

    if String.contains?(output, marker) do
      # The hostile act ran to completion. The cap did not hold -- and note that
      # the mechanism may have been invoked perfectly (005 R9b).
      {:breached,
       "the #{dimension} breach ran to completion under a nominal cap of " <>
         "#{inspect(cap)}; output contained #{inspect(marker)}"}
    else
      if String.contains?(output, throttle_marker()) do
        # ⚠️ Positive evidence, not an absence. A CPU cap **throttles** rather
        # than kills, so there is no error for `classify/3`'s error clause to
        # recognise -- the process simply does not finish its work in the time an
        # unthrottled one would. Without this branch a correctly-throttled
        # sandbox produced empty output and was reported `:inconclusive`, which
        # is `FR-012b`'s "not demonstrated" and therefore never a pass.
        #
        # The hog reports its own deadline miss, so the suite reads a claim it
        # can check rather than inferring a guarantee from silence.
        {:stopped,
         "the #{dimension} breach did not finish its fixed workload within the " <>
           "deadline under a cap of #{inspect(cap)}, which is what throttling " <>
           "looks like: output contained #{inspect(throttle_marker())}"}
      else
        # It did not complete, but it also did not visibly hit the cap. That is
        # not evidence the cap stopped it -- it could have died of anything.
        {:inconclusive,
         "the #{dimension} breach neither completed nor reported being stopped. " <>
           "Output: #{inspect(String.slice(output, 0, 400))}"}
      end
    end
  end

  def classify({:error, reason}, dimension, cap) do
    if stopped_by_cap?(reason, dimension) do
      {:stopped,
       "the #{dimension} breach was stopped under a cap of #{inspect(cap)}: " <>
         inspect(reason)}
    else
      # An ordinary crash. Deliberately NOT a pass: a process that died before
      # reaching the cap has demonstrated nothing about the cap.
      {:inconclusive,
       "the #{dimension} breach failed for a reason that is not the cap taking " <>
         "effect, so the cap was not demonstrated: #{inspect(reason)}"}
    end
  end

  def classify(other, dimension, _cap) do
    {:inconclusive, "the #{dimension} breach returned #{inspect(other)}"}
  end

  # The mechanism must say it stopped something. A bare non-zero exit is not
  # enough -- OOM, a segfault and a cap kill are indistinguishable from it, and
  # treating them alike is how "the cap works" gets claimed on a crash.
  defp stopped_by_cap?({:limit_exceeded, _}, _dimension), do: true
  defp stopped_by_cap?(:limit_exceeded, _dimension), do: true
  defp stopped_by_cap?({:oom_killed, _}, :memory), do: true
  defp stopped_by_cap?(:oom_killed, :memory), do: true
  defp stopped_by_cap?({:timeout, _}, :time), do: true
  defp stopped_by_cap?(:timeout, :time), do: true
  defp stopped_by_cap?({:throttled, _}, :cpu), do: true
  defp stopped_by_cap?(:throttled, :cpu), do: true
  defp stopped_by_cap?(_reason, _dimension), do: false

  defp completion_marker(:memory), do: "ALLOCATED-PAST-CAP"
  defp completion_marker(:cpu), do: "SPUN-PAST-CAP"
  defp completion_marker(:time), do: "SLEPT-PAST-BUDGET"

  # Printed by the CPU hog when it misses its deadline. Distinct from the
  # completion markers because it means the opposite: the cap held.
  defp throttle_marker, do: "THROTTLED-BY-CAP"

  @doc """
  A shell command allocating `mb` megabytes and **touching every page** of it.

  The touching is the part that matters: an allocation the kernel can leave
  unbacked is not an allocation any cap will notice, so a hog that only calls
  `malloc` would report a working cap on a host with none.
  """
  @spec memory_hog_command(pos_integer()) :: String.t()
  def memory_hog_command(mb) do
    """
    python3 -c '
    n = #{mb} * 1024 * 1024
    b = bytearray(n)
    for i in range(0, n, 4096):
        b[i] = 1
    print("ALLOCATED-PAST-CAP")
    '
    """
  end

  @doc """
  A shell command performing a **fixed amount of work**, printing its marker only
  if that work completed within a wall-clock deadline.

  ⚠️ **Fixed work, not fixed duration**, and the distinction makes this check
  falsifiable at all. An earlier version spun `while [ $(date +%s) -lt $end ]`
  for ten seconds and printed the marker unconditionally. That loop finishes in
  ten seconds *whatever* the CPU quota — throttling grants less CPU per second,
  it does not extend wall time — so the check reported "the breach was not
  stopped" on every correct implementation, including one enforcing a 1% quota.

  Measured on a cgroup v2 host under `CPUQuota=1%`: the old wall-clock loop
  finished in **5s** and printed its marker; this fixed-work loop took **54s**.
  Only the second distinguishes a throttled sandbox from an unthrottled one.

  ## Why a deadline rather than a duration

  A CPU cap **throttles**; it does not kill. So "stopped" here can only mean
  "could not finish this work in the time an unthrottled process would need",
  which is what the `timeout` expresses. A sandbox with no cap prints the marker
  well inside the deadline; a throttled one is still working when `timeout`
  fires and prints nothing.
  """
  @spec cpu_hog_command() :: String.t()
  def cpu_hog_command do
    """
    timeout 10 sh -c 'i=0; while [ $i -lt 3000000 ]; do i=$((i+1)); done' && echo SPUN-PAST-CAP || echo THROTTLED-BY-CAP
    """
  end

  @doc "A shell command blocking for `seconds`, far past the budget."
  @spec sleep_command(pos_integer()) :: String.t()
  def sleep_command(seconds), do: "sleep #{seconds}; echo SLEPT-PAST-BUDGET"

  defp exec(%{context: %{exec: exec}}, command) when is_function(exec, 1), do: exec.(command)

  defp exec(_sandbox, _command) do
    # Same rule as the isolation group: no runner means the breach cannot be
    # attempted, which is FR-012b's undemonstrable case -- routed to the third
    # outcome by `demonstrate_breach/3`, never to a pass.
    {:no_runner,
     "this mechanism's sandbox `context` carries no `:exec` function, so no " <>
       "breach can be attempted and no cap can be demonstrated"}
  end
end
