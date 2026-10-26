defmodule ExSandbox.Gateway.EgressWithoutClientTest do
  @moduledoc """
  Egress verdicts are answered on the gateway, from the last allowlist the
  client applied, while no client is connected (`sandbox/FR-297` of
  `let-sandboxes-outlive-a-deploy`).
  """
  use ExUnit.Case, async: false

  @moduletag :isolation

  alias ExSandbox.Conformance.Network
  alias ExSandbox.Mechanism.Gateway
  alias ExSandbox.Sandbox

  test "an allowlist applied through the client holds after the client is gone" do
    path = "/tmp/exsg-egress-#{System.unique_integer([:positive])}.sock"
    start_supervised!({ExSandbox.Gateway, socket_path: path, name: :egress_gateway})
    client = start_supervised!({Gateway, socket_path: path})

    refused = Network.denied_address()
    {host, port} = allowed = Network.permitted_address()

    sandbox =
      ExSandbox.Test.IsolationLaunch.provision_or_skip(Gateway, %Sandbox{
        id: "gw-egress-#{System.unique_integer([:positive])}",
        owner_ref: "tenant-gw-egress",
        template_ref: "conformance-template",
        cpu_limit: 500,
        memory_limit_mb: 128,
        disk_quota_mb: 256,
        context: %{network_allowlist: [refused]}
      })

    on_exit(fn -> ExSandbox.Mechanism.Beam.destroy(sandbox) end)
    refute sandbox.context.connect.(host, port) == :connected

    assert {:ok, _updated} =
             ExSandbox.update_egress(Gateway, sandbox, [allowed], host_aliases: [])

    :ok = stop_supervised(Gateway)
    refute Process.alive?(client)

    {refused_host, refused_port} = refused
    assert sandbox.context.connect.(host, port) == :connected
    refute sandbox.context.connect.(refused_host, refused_port) == :connected
  end
end
