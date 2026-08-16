defmodule ExSandbox.Mechanism.Beam.IsolationProcessesTest do
  @moduledoc """
  A sandbox sees only its own processes (005 T029, `FR-001`, `FR-002`).

  A supervised process tree inside the platform's VM passes every *functional*
  test of a sandbox and fails this one: `Process.list/0` there returns the
  platform's processes and every other tenant's. That is the distinction this
  file exists to draw.
  """
  use ExUnit.Case, async: false

  @moduletag :isolation

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  defp sandbox(tag) do
    %Sandbox{
      id: "proc-#{tag}-#{System.unique_integer([:positive])}",
      owner_ref: "owner-#{tag}",
      template_ref: "conformance-template",
      cpu_limit: 500,
      memory_limit_mb: 128,
      disk_quota_mb: 256
    }
  end

  defp launch(tag) do
    {:ok, provisioned} = Beam.provision(sandbox(tag))
    on_exit(fn -> Beam.destroy(provisioned) end)
    {provisioned, String.to_atom(provisioned.mechanism_ref)}
  end

  test "a sandbox cannot see the platform's processes" do
    {_sb, node} = launch("a")

    # A process on the platform, registered under a name the sandbox could find
    # if it shared a process table.
    marker = :"platform_marker_#{System.unique_integer([:positive])}"
    pid = spawn(fn -> Process.sleep(:infinity) end)
    Process.register(pid, marker)
    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)

    registered = :erpc.call(node, :erlang, :registered, [], 10_000)

    refute marker in registered,
           "sandbox can see the platform's registered process #{marker} -- not a separate runtime"

    # Count as well as name: a shared table would show the platform's hundreds,
    # while a fresh node runs a few dozen.
    count = :erpc.call(node, :erlang, :system_info, [:process_count], 10_000)

    assert count < 200,
           "sandbox reports #{count} processes, which is platform-sized rather than sandbox-sized"
  end

  test "one sandbox cannot see another tenant's processes" do
    {_a, node_a} = launch("a")
    {_b, node_b} = launch("b")

    # Registered inside tenant B, so the name exists on a real runtime rather
    # than only in this test's imagination.
    :erpc.call(
      node_b,
      Process,
      :register,
      [:erlang.spawn(fn -> Process.sleep(:infinity) end), :tenant_b_marker],
      10_000
    )

    assert :tenant_b_marker in :erpc.call(node_b, :erlang, :registered, [], 10_000),
           "precondition failed: the marker was never registered on tenant B"

    registered_in_a = :erpc.call(node_a, :erlang, :registered, [], 10_000)

    refute :tenant_b_marker in registered_in_a,
           "tenant A can see tenant B's process -- the sandboxes share a runtime"
  end
end
