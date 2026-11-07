defmodule ExSandbox.Mechanism.Gateway.ConformanceTest do
  @moduledoc """
  `003`'s conformance suite against `ExSandbox.Mechanism.Gateway`, served by
  an `ExSandbox.Gateway` running `ExSandbox.Mechanism.Beam` in this VM. It
  must pass as `ExSandbox.Mechanism.Beam.ConformanceTest` does (task 2.2 of
  `let-sandboxes-outlive-a-deploy`).
  """
  @host_can_run ExSandbox.Capability.missing(ExSandbox.Mechanism.Beam.required_capabilities()) ==
                  []

  if @host_can_run do
    use ExSandbox.Conformance, mechanism: ExSandbox.Mechanism.Gateway

    setup_all do
      path = "/tmp/exsg-conformance-#{System.unique_integer([:positive])}.sock"
      {:ok, gateway} = ExSandbox.Gateway.start_link(socket_path: path, name: :conformance_gateway)
      {:ok, client} = ExSandbox.Mechanism.Gateway.start_link(socket_path: path)

      on_exit(fn ->
        for pid <- [client, gateway], Process.alive?(pid), do: Process.exit(pid, :shutdown)
      end)

      :ok
    end
  else
    use ExUnit.Case, async: false

    test "the gateway conformance suite did not run on this host" do
      missing = ExSandbox.Capability.missing(ExSandbox.Mechanism.Beam.required_capabilities())
      IO.puts("\n\e[33mthe Gateway conformance suite did NOT run on this host.\e[0m")
      assert missing != []
    end
  end
end
