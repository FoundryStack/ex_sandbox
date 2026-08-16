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
    provisioned
  end

  # ⚠️ `Beam.call/5`, never `:erpc.call/5`. The sandbox runs under
  # `--unshare-net` and has no network interfaces, so distribution-based RPC
  # raises `{:erpc, :noconnection}` against a healthy sandbox -- a failure that
  # looks exactly like a crashed node and grows *more* likely as the confinement
  # gets stronger. `Beam.call/5` goes over the stdio control channel, which
  # survives network isolation by construction.
  defp eval(sb, module, function, args) do
    assert {:ok, result} = Beam.call(sb, module, function, args)
    result
  end

  test "a sandbox cannot see the platform's processes" do
    sb = launch("a")

    # A process on the platform, registered under a name the sandbox could find
    # if it shared a process table.
    marker = :"platform_marker_#{System.unique_integer([:positive])}"
    pid = spawn(fn -> Process.sleep(:infinity) end)
    Process.register(pid, marker)
    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)

    registered = eval(sb, :erlang, :registered, [])

    refute marker in registered,
           "sandbox can see the platform's registered process #{marker} -- not a separate runtime"

    # Count as well as name: a shared table would show the platform's hundreds,
    # while a fresh node runs a few dozen.
    count = eval(sb, :erlang, :system_info, [:process_count])

    assert count < 200,
           "sandbox reports #{count} processes, which is platform-sized rather than sandbox-sized"
  end

  test "one sandbox cannot see another tenant's processes" do
    sb_a = launch("a")
    sb_b = launch("b")

    # Spawned *inside* tenant B. An earlier version evaluated `:erlang.spawn/1`
    # in this test process and shipped the resulting pid, which registers a
    # **local** pid under a remote name -- the marker would exist on B without B
    # ever hosting the process, and the test would still pass. Passing the fun
    # to `:erlang.spawn/1` on the far side is what makes the precondition real.
    # ⚠️ Pure Erlang: `Process.*` is `:undef` inside the sandbox, so this fun
    # would die on its first line and register nothing. The precondition assert
    # below catches that, but only because it exists -- without it, "tenant A
    # cannot see the marker" would be satisfied by a marker that was never
    # created.
    # ⚠️ Registered by an MFA the sandbox resolves itself. A fun -- anonymous or
    # captured -- cannot cross this boundary at all: it carries the module that
    # defined it, which the sandbox cannot load, so it dies with `:undef` and
    # registers nothing. The precondition below is what catches that; without it
    # "tenant A cannot see the marker" would be satisfied by a marker that never
    # existed.
    pid = eval(sb_b, :erlang, :spawn, [:timer, :sleep, [60_000]])
    true = eval(sb_b, :erlang, :register, [:tenant_b_marker, pid])

    assert :tenant_b_marker in eval(sb_b, :erlang, :registered, []),
           "precondition failed: the marker was never registered on tenant B"

    registered_in_a = eval(sb_a, :erlang, :registered, [])

    refute :tenant_b_marker in registered_in_a,
           "tenant A can see tenant B's process -- the sandboxes share a runtime"
  end

end
