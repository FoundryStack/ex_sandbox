defmodule ExSandbox.Mechanism.Beam.ResourceCapTest do
  @moduledoc """
  Breaching a limit constrains or terminates that sandbox alone, and is reported
  as such (005 T034, `FR-008`, `FR-009`, `SC-004`).

  ## Established by breaching, never by inspecting configuration

  `012-FR-012a` requires exactly this, and R9b is why: `taskpolicy -m 100
  sandbox-exec … ./hog 300` allocates 300 MB under a nominal 100 MB cap and
  **exits 0**. Every check that asks whether the limiting mechanism was invoked
  passes there. Only allocating past the cap distinguishes a cap in force from
  a cap requested and lost.
  """
  use ExUnit.Case, async: false

  @moduletag :isolation
  # Allocating past a cap and filling a disk are slow, and a sandbox that is
  # *not* capped will take the full budget before failing.
  @moduletag timeout: 180_000

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  defp sandbox(tag, overrides) do
    Map.merge(
      %Sandbox{
        id: "rc-#{tag}-#{System.unique_integer([:positive])}",
        owner_ref: "owner-#{tag}",
        template_ref: "conformance-template",
        cpu_limit: 500,
        memory_limit_mb: 128,
        disk_quota_mb: 64
      },
      overrides
    )
  end

  defp launch(tag, overrides \\ %{}) do
    ExSandbox.Test.IsolationLaunch.provision_or_skip(Beam, sandbox(tag, overrides))
  end

  # ⚠️ Stdio, not `:erpc` -- a sandbox under `--unshare-net` has no network
  # interfaces, so distribution-based RPC cannot reach it however healthy it is.
  defp eval(sb, module, function, args, timeout \\ 10_000) do
    Beam.call(sb, module, function, args, timeout)
  end

  test "allocating past the memory cap terminates that sandbox and no other" do
    victim = launch("victim", %{memory_limit_mb: 128})
    bystander = launch("bystander")

    # Allocate well past the cap. Binaries rather than lists: they are allocated
    # outside the process heap, so the OS sees the growth even if the BEAM's own
    # GC would have reclaimed a list.
    :ok = hog_memory(victim)

    assert eventually(fn -> match?({:ok, s} when s != :running, Beam.status(victim)) end),
           """
           the sandbox allocated ~10 GB under a 128 MB cap and is still running.

           The cap was requested but is not in force (R9b) -- exactly the
           fail-open shape that inspecting configuration cannot detect.
           """

    assert {:ok, :running} = Beam.status(bystander),
           "an unrelated sandbox died when this one breached its memory cap"
  end

  test "a sandbox that breaches its cap is reported as :resource_cap, not an unexplained crash" do
    victim = launch("reported", %{memory_limit_mb: 128})

    :ok = hog_memory(victim)

    assert eventually(fn -> match?({:ok, s} when s != :running, Beam.status(victim)) end)

    # An operator seeing `:mechanism_error` here would go looking for a bug in
    # the platform. `:resource_cap` says the tenant hit its own limit, which is
    # a different conversation and the one `FR-009` requires.
    assert {:error, :resource_cap} = Beam.provision_failure_reason(victim)
  end

  # ⚠️ The **reporting** half of the cap, and it was broken while the two tests
  # above passed (Q17).
  #
  # `provision_failure_reason/1` said `:resource_cap` all along; what `execute/3`
  # *told its caller* was `{:could_not_run, {:timeout, 15000}}`, because the OOM
  # kill takes the sandbox's BEAM with it, the peer call then waits out the
  # library's ceiling, and `interpret_execution/4`'s `:timeout` clause matched
  # above the attribution that would have named memory.
  #
  # Measured in the container before the fix: the scope reported
  # `Result=oom-kill` **55 ms** after the exec began, `execute/3` returned
  # 15001 ms later, and `status/1` + `provision_failure_reason/1` answered
  # `{:error, :resource_cap}` in 8 ms when finally asked. A cap that fired in
  # 55 ms was reported as a command that could not be run.
  #
  # That is why this asserts on `execute/3` rather than on `status/1`: the
  # conformance suite's memory check consumes exactly this value, and
  # `Conformance.Execution.classify/4` scores `:could_not_run` as
  # `:inconclusive` -- so the guarantee reported the third outcome on a host
  # where it holds.
  test "a command killed by the memory cap is reported as :limit_exceeded, not :could_not_run" do
    victim = launch("execute-attribution", %{memory_limit_mb: 64})

    result =
      ExSandbox.execute(
        Beam,
        victim,
        {"/bin/sh", ["-c", ExSandbox.Conformance.ResourceLimits.memory_hog_command(192)]}
      )

    assert {:error, {:limit_exceeded, :memory}} = result
  end

  # The other direction, and it is what keeps the clause above from becoming a
  # fail-open. A call that waits out the ceiling for any reason **other** than a
  # cap must still say `:could_not_run`: attributing every timeout to memory
  # would report a cap as demonstrated by a sandbox that is alive and well.
  #
  # `sleep 60` under no declared `timeout_ms` is exactly that -- the ceiling
  # trips, the scope is untouched, and there is nothing to attribute.
  test "a timeout with no cap behind it is still could_not_run" do
    idle = launch("execute-no-cap", %{memory_limit_mb: 512})

    assert {:error, {:could_not_run, {:timeout, _}}} =
             ExSandbox.execute(Beam, idle, {"/bin/sh", ["-c", "sleep 60"]})

    assert {:ok, :running} = Beam.status(idle),
           "the sandbox died during a plain timeout, so this asserts nothing about attribution"
  end

  test "spinning all cores does not starve other sandboxes" do
    spinner = launch("spinner", %{cpu_limit: 100})
    bystander = launch("bystander", %{cpu_limit: 500})

    {:ok, cores} = eval(spinner, :erlang, :system_info, [:logical_processors])

    for _ <- 1..max(cores, 4) do
      spin_cpu(spinner)
    end

    # The bystander stays responsive within its probe deadline. A shared,
    # uncapped CPU would make this call miss its window.
    # ⚠️ Not `:erlang.is_alive/0` -- a sandbox is deliberately undistributed, so
    # that answers `false` on a perfectly healthy one. What is being measured is
    # *responsiveness under contention*, and the evidence for that is the call
    # returning promptly at all. `:erlang.now_time/0`-style work would do; the
    # node's own uptime is a real computation with a real answer.
    started = System.monotonic_time(:millisecond)
    assert {:ok, {uptime, _}} = eval(bystander, :erlang, :statistics, [:wall_clock], 15_000)
    assert is_integer(uptime)
    elapsed = System.monotonic_time(:millisecond) - started

    assert elapsed < 5_000,
           "a bystander took #{elapsed}ms to answer while another sandbox spun every core"

    assert {:ok, :running} = Beam.status(bystander)
  end

  test "filling the disk constrains that sandbox alone" do
    victim = launch("disk", %{disk_quota_mb: 64})
    bystander = launch("bystander")

    target = Path.join(ExSandbox.Hardening.Linux.storage_path(victim), "fill.bin")

    # ⚠️ Erlang's `:file`, never Elixir's `File`: the sandbox boots a bare `erl`
    # with only OTP on its code path, so `File.write/2` there returns `:undef`.
    # Here that would be actively misleading -- the assertion below accepts any
    # `{:error, _}` as evidence the quota held, and `:undef` is an `{:error, _}`.
    # The test would pass on a sandbox with no disk quota whatsoever.
    result =
      case eval(
             victim,
             :file,
             :write_file,
             [target, :binary.copy(<<0>>, 256 * 1024 * 1024)],
             60_000
           ) do
        {:ok, inner} -> inner
        error -> error
      end

    assert match?({:error, _}, result) or
             match?({:ok, s} when s != :running, Beam.status(victim)),
           "a sandbox wrote 256 MB under a 64 MB quota without being constrained"

    assert {:ok, :running} = Beam.status(bystander),
           "an unrelated sandbox was affected by this one filling its disk"
  end

  defp eventually(fun, remaining \\ 120) do
    cond do
      fun.() -> true
      remaining == 0 -> false
      true -> Process.sleep(500) && eventually(fun, remaining - 1)
    end
  end

  # ⚠️ **MFAs over OTP modules only — a fun cannot cross this boundary at all.**
  #
  # Measured in the container: `Beam.call(sb, :erlang, :apply, [fn -> ... end, []])`
  # returns `{:error, {:error, :undef}}` however self-contained the fun looks.
  # Every anonymous fun carries the module that defined it, and the sandbox
  # cannot load this test module -- or any Elixir module, since it boots a bare
  # `erl`. Named captures fail identically.
  #
  # That failure is dangerous rather than merely inconvenient: a hog that dies
  # instantly with `:undef` allocates nothing, the sandbox stays up, and the test
  # reports "the cap was requested but is not in force" -- accusing the mechanism
  # of the exact fail-open defect (R9b) this suite exists to detect, when nothing
  # was ever allocated.
  #
  # ⚠️ One binary, not many. `:lists.duplicate/2` was tried first and does not
  # work: it stores 10,000 references to *one* shared 1MB binary, allocating
  # ~1MB rather than 10GB, so a 128MB cap is never breached. A single
  # `:binary.copy/2` of 2GB is unambiguous.
  defp hog_memory(sandbox) do
    Beam.cast(sandbox, :erlang, :spawn, [:binary, :copy, [<<0>>, 2_000_000_000]])
  end

  defp spin_cpu(sandbox) do
    # ⚠️ Work **generated inside** the sandbox, not shipped to it. Passing
    # `:lists.seq(1, 20_000_000)` was tried and is wrong twice over: the list
    # crosses as data and allocates enough to trip the *memory* cap, so the
    # sandbox dies of the wrong limit and the CPU test reports a starved
    # bystander that was never starved.
    #
    # `pbkdf2_hmac` with a high iteration count burns CPU for seconds with
    # bounded allocation -- verified: the sandbox stays `:running` throughout.
    Beam.cast(sandbox, :erlang, :spawn, [
      :crypto,
      :pbkdf2_hmac,
      [:sha512, "spin", "salt", 20_000_000, 64]
    ])
  end
end
