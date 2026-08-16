defmodule ExSandbox.Mechanism.Beam.IsolationHaltTest do
  @moduledoc """
  A sandbox halting itself takes down nothing else (005 T031, `FR-005`, R6).

  ## This is the test that catches `peer_down: :crash`

  `:crash` reads like good supervision hygiene — a dead peer should surely
  crash its supervisor. Verified at `peer.erl:250` and `:962-968`, it terminates
  the **origin** process with the sandbox's exit reason, which hands tenant code
  a way to kill platform processes by halting itself. That inverts `FR-005`
  into its exact opposite.

  A test that only asserts "the halted sandbox is gone" passes under `:crash`.
  The assertions that matter here are about everything that did **not** halt.
  """
  use ExUnit.Case, async: false

  @moduletag :isolation

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  defp sandbox(owner, tag) do
    %Sandbox{
      id: "halt-#{tag}-#{System.unique_integer([:positive])}",
      owner_ref: owner,
      template_ref: "conformance-template",
      cpu_limit: 500,
      memory_limit_mb: 128,
      disk_quota_mb: 256
    }
  end

  defp launch(owner, tag) do
    {:ok, provisioned} = Beam.provision(sandbox(owner, tag))
    on_exit(fn -> Beam.destroy(provisioned) end)
    provisioned
  end

  test "one sandbox halting leaves the platform and every other sandbox serving" do
    # Three sandboxes across two tenants, per the task: a single survivor could
    # be explained by luck, and a second tenant is what shows the blast radius
    # does not cross an owner boundary.
    victim = launch("tenant-one", "victim")
    sibling = launch("tenant-one", "sibling")
    stranger = launch("tenant-two", "stranger")

    platform_marker = :"platform_alive_#{System.unique_integer([:positive])}"
    platform_pid = spawn(fn -> Process.sleep(:infinity) end)
    Process.register(platform_pid, platform_marker)
    on_exit(fn -> if Process.alive?(platform_pid), do: Process.exit(platform_pid, :kill) end)

    # The test process itself must survive; under `peer_down: :crash` it is the
    # origin, and this is where it would be killed.
    test_pid = self()

    # Fire-and-forget over stdio: the node dies mid-call, so a synchronous call
    # would simply error and tell us nothing about the survivors. `:erpc.cast`
    # would not reach it at all -- the sandbox has no network interfaces.
    :ok = Beam.cast(victim, :erlang, :halt, [1])

    # The victim really did go. Without this the survival assertions below could
    # pass because nothing ever halted.
    assert eventually(fn -> match?({:ok, s} when s != :running, Beam.status(victim)) end),
           "the victim sandbox never actually halted, so this test proved nothing"

    assert Process.alive?(test_pid),
           "the origin process died with the sandbox -- `peer_down: :crash` (R6)"

    assert Process.whereis(platform_marker) == platform_pid,
           "a platform process died when a sandbox halted itself"

    for survivor <- [sibling, stranger] do
      assert {:ok, :running} = Beam.status(survivor),
             "sandbox #{survivor.id} (owner #{survivor.owner_ref}) died with an unrelated sandbox"
    end
  end

  test "the halt is reported distinguishably rather than as an unexplained crash" do
    victim = launch("tenant-one", "reported")

    :ok = Beam.cast(victim, :erlang, :halt, [1])

    assert eventually(fn -> match?({:ok, s} when s != :running, Beam.status(victim)) end)

    # `:absent`, not `:unknown`: a halted sandbox is definitively gone, and
    # reporting uncertainty would send reconciliation looking for something to
    # reconcile.
    assert {:ok, :absent} = Beam.status(victim)
  end

  defp eventually(fun, remaining \\ 50) do
    cond do
      fun.() -> true
      remaining == 0 -> false
      true -> Process.sleep(100) && eventually(fun, remaining - 1)
    end
  end
end
