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
    {provisioned, String.to_atom(provisioned.mechanism_ref)}
  end

  test "allocating past the memory cap terminates that sandbox and no other" do
    {victim, victim_node} = launch("victim", %{memory_limit_mb: 128})
    {bystander, _} = launch("bystander")

    # Allocate well past the cap. Binaries rather than lists: they are allocated
    # outside the process heap, so the OS sees the growth even if the BEAM's own
    # GC would have reclaimed a list.
    _ =
      :erpc.cast(victim_node, :erlang, :apply, [
        fn ->
          Enum.reduce(1..10_000, [], fn _, acc ->
            [:binary.copy(<<0>>, 1024 * 1024) | acc]
          end)
        end,
        []
      ])

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
    {victim, victim_node} = launch("reported", %{memory_limit_mb: 128})

    _ =
      :erpc.cast(victim_node, :erlang, :apply, [
        fn ->
          Enum.reduce(1..10_000, [], fn _, acc -> [:binary.copy(<<0>>, 1024 * 1024) | acc] end)
        end,
        []
      ])

    assert eventually(fn -> match?({:ok, s} when s != :running, Beam.status(victim)) end)

    # An operator seeing `:mechanism_error` here would go looking for a bug in
    # the platform. `:resource_cap` says the tenant hit its own limit, which is
    # a different conversation and the one `FR-009` requires.
    assert {:error, :resource_cap} = Beam.provision_failure_reason(victim)
  end

  test "spinning all cores does not starve other sandboxes" do
    {_spinner, spinner_node} = launch("spinner", %{cpu_limit: 100})
    {bystander, bystander_node} = launch("bystander", %{cpu_limit: 500})

    cores = :erpc.call(spinner_node, :erlang, :system_info, [:logical_processors], 10_000)

    for _ <- 1..max(cores, 4) do
      :erpc.cast(spinner_node, :erlang, :apply, [
        fn ->
          Stream.repeatedly(fn -> :erlang.phash2(:os.timestamp()) end) |> Enum.take(10_000_000)
        end,
        []
      ])
    end

    # The bystander stays responsive within its probe deadline. A shared,
    # uncapped CPU would make this call miss its window.
    started = System.monotonic_time(:millisecond)
    assert :erpc.call(bystander_node, :erlang, :is_alive, [], 15_000)
    elapsed = System.monotonic_time(:millisecond) - started

    assert elapsed < 5_000,
           "a bystander took #{elapsed}ms to answer while another sandbox spun every core"

    assert {:ok, :running} = Beam.status(bystander)
  end

  test "filling the disk constrains that sandbox alone" do
    {victim, victim_node} = launch("disk", %{disk_quota_mb: 64})
    {bystander, _} = launch("bystander")

    target = "/sandbox/#{victim.id}/fill.bin"

    result =
      :erpc.call(
        victim_node,
        File,
        :write,
        [target, :binary.copy(<<0>>, 256 * 1024 * 1024)],
        60_000
      )

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
end
