defmodule ExSandbox.Mechanism.Beam.UpdateEgressTest do
  @moduledoc """
  A running sandbox's allowlist changes without a restart.

  The same sandbox dials the same destination twice. The first dial is refused
  because the allowlist does not name it; `ExSandbox.update_egress/4` then adds
  it, and the second dial connects. The sandbox is never stopped in between, so
  the only thing that can explain the second verdict is the replaced policy.
  """
  use ExUnit.Case, async: false

  @moduletag :isolation

  alias ExSandbox.Conformance.Network
  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  test "a destination added to a running sandbox is reachable on the next dial" do
    permitted = Network.permitted_address()
    {host, port} = added = Network.denied_address()

    sandbox =
      ExSandbox.Test.IsolationLaunch.provision_or_skip(Beam, %Sandbox{
        id: "update-egress-#{System.unique_integer([:positive])}",
        owner_ref: "tenant-update-egress",
        template_ref: "conformance-template",
        cpu_limit: 500,
        memory_limit_mb: 128,
        disk_quota_mb: 256,
        context: %{network_allowlist: [permitted]}
      })

    # ⚠️ The host must reach the destination itself, or "still refused after
    # the update" would be the host's egress, not the sandbox's policy.
    case :gen_tcp.connect(String.to_charlist(host), port, [], 3_000) do
      {:ok, socket} -> :gen_tcp.close(socket)
      {:error, reason} -> flunk("the host cannot reach #{host}:#{port} (#{inspect(reason)})")
    end

    refute sandbox.context.connect.(host, port) == :connected,
           "#{host}:#{port} was reachable before the allowlist named it"

    assert {:ok, updated} =
             ExSandbox.update_egress(Beam, sandbox, [permitted, added], host_aliases: [])

    assert updated.context.network_allowlist == [permitted, added]

    assert sandbox.context.connect.(host, port) == :connected,
           "the running sandbox still refused #{host}:#{port} after the update"
  end
end
