defmodule ExSandbox.Mechanism.Beam.NodeLauncherForwardTest do
  @moduledoc """
  The host loopback ports a launch publishes the sandbox's service ports on.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Mechanism.Beam.NodeLauncher
  alias ExSandbox.Sandbox

  defp sandbox(overrides) do
    struct!(%Sandbox{id: "forward", owner_ref: "t", template_ref: "t"}, overrides)
  end

  test "publishes nothing for a sandbox that names no service port" do
    assert NodeLauncher.forward(sandbox(service_port: nil)) == nil
    assert NodeLauncher.forward(sandbox(service_port: nil, extra_service_ports: [4001])) == nil
  end

  test "pairs the service port alone when there are no extras" do
    assert [{host_port, 4000}] = NodeLauncher.forward(sandbox(service_port: 4000))
    assert host_port > 0
  end

  test "pairs every port, primary first, each on its own host port" do
    pairs = NodeLauncher.forward(sandbox(service_port: 4000, extra_service_ports: [4001, 4000]))

    assert Enum.map(pairs, &elem(&1, 1)) == [4000, 4001]

    host_ports = Enum.map(pairs, &elem(&1, 0))
    assert Enum.uniq(host_ports) == host_ports
  end
end
