defmodule ExSandbox.Mechanism.BeamStopReleasesEgressTest do
  @moduledoc """
  Stopping a sandbox returns its egress `/30`: a relaunch acquires a fresh
  binding and overwrites the row, so one kept through stop leaked a `/30` per
  stop and start until every launch was refused with `:pool_exhausted`.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Egress.Binding
  alias ExSandbox.Egress.Registry, as: EgressRegistry
  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  setup do
    sandbox = %Sandbox{
      id: "beam-stop-egress-#{System.unique_integer([:positive])}",
      owner_ref: "test",
      template_ref: "test"
    }

    {:ok, binding} = Binding.acquire([{"example.com", 443}])
    on_exit(fn -> Binding.release(binding) end)

    :ets.insert(
      Beam.registry_table(),
      {sandbox.id, %{peer: nil, binding: binding, acceptor_pid: nil, forward: nil}}
    )

    on_exit(fn -> :ets.delete(Beam.registry_table(), sandbox.id) end)
    %{sandbox: sandbox, binding: binding}
  end

  test "stop releases the binding and keeps the row stopped", %{
    sandbox: sandbox,
    binding: binding
  } do
    assert {:ok, ^sandbox} = Beam.stop(sandbox)

    refute EgressRegistry.registered?(binding.source_key)

    assert [{_, %{stopped: true, binding: nil, acceptor_pid: nil}}] =
             :ets.lookup(Beam.registry_table(), sandbox.id)
  end

  test "a second stop is safe", %{sandbox: sandbox} do
    assert {:ok, _} = Beam.stop(sandbox)
    assert {:ok, _} = Beam.stop(sandbox)
  end
end
