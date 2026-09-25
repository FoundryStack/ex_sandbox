defmodule ExSandbox.Mechanism.Beam.PublicEgressTest do
  @moduledoc """
  The `"public"` entry on a running sandbox: every public host becomes
  reachable, the refused classes stay refused, and replacing the list again
  takes it away.

  A private or metadata address is often unreachable from the host anyway, so
  "the dial did not connect" alone proves nothing about policy. Each refusal is
  also asserted as a `[:ex_sandbox, :egress, :refused]` event for that address,
  which only the acceptor's decision emits.
  """
  use ExUnit.Case, async: false

  @moduletag :isolation

  alias ExSandbox.Conformance.Network
  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  test "public reaches a host on no list and never the refused classes" do
    permitted = Network.permitted_address()
    {host, port} = Network.denied_address()

    sandbox =
      ExSandbox.Test.IsolationLaunch.provision_or_skip(Beam, %Sandbox{
        id: "public-egress-#{System.unique_integer([:positive])}",
        owner_ref: "tenant-public-egress",
        template_ref: "conformance-template",
        cpu_limit: 500,
        memory_limit_mb: 128,
        disk_quota_mb: 256,
        context: %{network_allowlist: [permitted]}
      })

    case :gen_tcp.connect(String.to_charlist(host), port, [], 3_000) do
      {:ok, socket} -> :gen_tcp.close(socket)
      {:error, reason} -> flunk("the host cannot reach #{host}:#{port} (#{inspect(reason)})")
    end

    handler = "public-egress-#{System.unique_integer([:positive])}"
    test_process = self()

    :telemetry.attach(
      handler,
      [:ex_sandbox, :egress, :refused],
      fn _event, _measurements, metadata, _ -> send(test_process, {:refused_event, metadata}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler) end)

    assert {:ok, _} = ExSandbox.update_egress(Beam, sandbox, ["public"])

    assert sandbox.context.connect.(host, port) == :connected,
           "#{host}:#{port} is on no list and was refused under public"

    for {address, inward} <- [
          {{10, 0, 0, 5}, "10.0.0.5"},
          {{169, 254, 169, 254}, "169.254.169.254"}
        ] do
      refute sandbox.context.connect.(inward, 80) == :connected,
             "public reached #{inward}, which is the platform's network"

      assert_receive {:refused_event, %{address: ^address, port: 80, reason: :not_permitted}},
                     5_000,
                     "#{inward} was not refused by the acceptor's decision"
    end

    assert {:ok, _} = ExSandbox.update_egress(Beam, sandbox, [permitted])

    refute sandbox.context.connect.(host, port) == :connected,
           "#{host}:#{port} stayed reachable after public was replaced"
  end
end
