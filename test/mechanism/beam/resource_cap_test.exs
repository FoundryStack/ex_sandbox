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
    {:ok, provisioned} = Beam.provision(sandbox(tag, overrides))
    on_exit(fn -> Beam.destroy(provisioned) end)
    provisioned
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
    :ok = Beam.cast(victim, :erlang, :apply, [hog_memory(), []])

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

    :ok = Beam.cast(victim, :erlang, :apply, [hog_memory(), []])

    assert eventually(fn -> match?({:ok, s} when s != :running, Beam.status(victim)) end)

    # An operator seeing `:mechanism_error` here would go looking for a bug in
    # the platform. `:resource_cap` says the tenant hit its own limit, which is
    # a different conversation and the one `FR-009` requires.
    assert {:error, :resource_cap} = Beam.provision_failure_reason(victim)
  end

  test "spinning all cores does not starve other sandboxes" do
    spinner = launch("spinner", %{cpu_limit: 100})
    bystander = launch("bystander", %{cpu_limit: 500})

    {:ok, cores} = eval(spinner, :erlang, :system_info, [:logical_processors])

    for _ <- 1..max(cores, 4) do
      Beam.cast(spinner, :erlang, :apply, [spin_cpu(), []])
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

  # ⚠️ These build **self-contained** funs to run inside the sandbox, and both
  # constraints are load-bearing.
  #
  # Self-contained: a capture like `&hog_memory/0` carries a reference to *this
  # test module*, which does not exist on the sandbox's code path -- the fun dies
  # with `:undef` the moment it is applied. Nothing allocates, the sandbox stays
  # up, and the memory-cap test fails claiming the cap is not in force. A
  # recursive anonymous fun (passed to itself) closes over nothing but itself.
  #
  # OTP only: `Enum`, `Stream`, and `String` are all `:undef` there too, for the
  # same reason -- the sandbox boots a bare `erl` with no Elixir on its path.
  defp hog_memory do
    fn ->
      grow = fn
        _grow, 0, acc ->
          acc

        grow, n, acc ->
          # Binaries rather than lists: allocated outside the process heap, so
          # the OS sees the growth even where the BEAM's GC would reclaim a list.
          grow.(grow, n - 1, [:binary.copy(<<0>>, 1024 * 1024) | acc])
      end

      grow.(grow, 10_000, [])
    end
  end

  defp spin_cpu do
    fn ->
      spin = fn
        _spin, 0 ->
          :ok

        spin, n ->
          _ = :erlang.phash2(:os.timestamp())
          spin.(spin, n - 1)
      end

      spin.(spin, 10_000_000)
    end
  end
end
