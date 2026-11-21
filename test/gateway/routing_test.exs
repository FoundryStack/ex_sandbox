defmodule ExSandbox.Gateway.RoutingTest do
  @moduledoc """
  `ExSandbox.Mechanism.Gateway` with several clients: a sandbox's requests go
  to the client its route names, and `list_running/0` lists every client's.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Mechanism.Gateway
  alias ExSandbox.Sandbox

  defmodule Here do
    @moduledoc false
    @behaviour ExSandbox.Mechanism
    @impl true
    def required_capabilities, do: []
    @impl true
    def provision(sandbox),
      do: {:ok, %{sandbox | context: %{host: fn -> :here end}}}

    @impl true
    def start(sandbox), do: {:ok, sandbox}
    @impl true
    def stop(sandbox), do: {:ok, sandbox}
    @impl true
    def destroy(_sandbox), do: :ok
    @impl true
    def status(_sandbox), do: {:ok, :here}
    @impl true
    def list_running, do: {:ok, ["here-a"]}
    @impl true
    def usage(_sandbox), do: {:ok, %{memory_mb: 1}}
    @impl true
    def execute(_sandbox, _command, _opts \\ []), do: {:error, :not_supported}
    @impl true
    def update_egress(sandbox, _allowed), do: {:ok, sandbox}
  end

  defmodule There do
    @moduledoc false
    @behaviour ExSandbox.Mechanism
    @impl true
    def required_capabilities, do: []
    @impl true
    def provision(sandbox),
      do: {:ok, %{sandbox | context: %{host: fn -> :there end}}}

    @impl true
    def start(sandbox), do: {:ok, sandbox}
    @impl true
    def stop(sandbox), do: {:ok, sandbox}
    @impl true
    def destroy(_sandbox), do: :ok
    @impl true
    def status(_sandbox), do: {:ok, :there}
    @impl true
    def list_running, do: {:ok, ["there-a"]}
    @impl true
    def usage(_sandbox), do: {:ok, %{memory_mb: 1}}
    @impl true
    def execute(_sandbox, _command, _opts \\ []), do: {:error, :not_supported}
    @impl true
    def update_egress(sandbox, _allowed), do: {:ok, sandbox}
  end

  def route("there-" <> _id), do: :there_client
  def route(_id), do: nil

  def clients(names), do: names

  setup do
    previous = Application.get_env(:ex_sandbox, :gateway_client)

    Application.put_env(:ex_sandbox, :gateway_client,
      route: {__MODULE__, :route, []},
      clients: {__MODULE__, :clients, [[:there_client]]},
      connect_wait_ms: 2_000
    )

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ex_sandbox, :gateway_client, previous),
        else: Application.delete_env(:ex_sandbox, :gateway_client)
    end)

    here = "/tmp/exsr-#{System.unique_integer([:positive])}.sock"
    there = "/tmp/exsr-#{System.unique_integer([:positive])}.sock"

    start_supervised!({ExSandbox.Gateway, socket_path: here, mechanism: Here, name: :gw_here},
      id: :gw_here
    )

    start_supervised!({ExSandbox.Gateway, socket_path: there, mechanism: There, name: :gw_there},
      id: :gw_there
    )

    start_supervised!({Gateway, socket_path: here}, id: :client_here)
    start_supervised!({Gateway, socket_path: there, name: :there_client}, id: :client_there)
    :ok
  end

  defp sandbox(id), do: %Sandbox{id: id, owner_ref: "o", template_ref: "t"}

  test "a sandbox's requests and its context functions go to the client its route names" do
    assert {:ok, :there} = Gateway.status(sandbox("there-1"))
    assert {:ok, :here} = Gateway.status(sandbox("here-1"))

    assert {:ok, provisioned} = Gateway.provision(sandbox("there-2"))
    assert provisioned.context.host.() == :there
  end

  test "the running sandboxes of every client are listed" do
    assert {:ok, listed} = Gateway.list_running()
    assert Enum.sort(listed) == ["here-a", "there-a"]
  end

  test "a client that does not answer fails the list" do
    stop_supervised!(:client_there)
    assert {:error, :host_unreachable} = Gateway.list_running()
  end
end
