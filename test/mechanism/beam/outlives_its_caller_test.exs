defmodule ExSandbox.Mechanism.Beam.OutlivesItsCallerTest do
  @moduledoc """
  A sandbox lives until `stop/1` or `destroy/1`, not until the process that
  provisioned it exits.

  ## The wrong implementation this is written against

  One that launches the node with `:peer.start_link/1`. The peer process traps
  exits and halts its node when its parent exits, for any reason, `:normal`
  included. OBSERVED 2026-09-21 on a host publishing a generated app: the
  sandbox's scope ended the instant the deployment job returned, and a sandbox
  woken by an HTTP request died as that request answered.
  """
  use ExUnit.Case, async: false

  @moduletag :isolation

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  for reason <- [:normal, :shutdown] do
    test "a sandbox answers after its provisioner exits #{inspect(reason)}" do
      sandbox = %Sandbox{
        id: "outlives-#{System.unique_integer([:positive])}",
        owner_ref: "outlives-owner",
        template_ref: "conformance-template",
        cpu_limit: 500,
        memory_limit_mb: 128,
        disk_quota_mb: 64
      }

      parent = self()

      {pid, ref} =
        spawn_monitor(fn ->
          send(parent, {:provisioned, Beam.provision(sandbox)})
          exit(unquote(reason))
        end)

      assert_receive {:provisioned, {:ok, provisioned}}, 30_000
      assert_receive {:DOWN, ^ref, :process, ^pid, unquote(reason)}, 5_000

      # A linked peer halts its node asynchronously after the exit signal; a
      # call made at once can land before the halt does.
      Process.sleep(2_000)

      try do
        assert {:ok, _count} = Beam.call(provisioned, :erlang, :system_info, [:process_count])
      after
        Beam.destroy(provisioned)
      end
    end
  end
end
