defmodule ExSandbox.AddressDispatchTest do
  @moduledoc """
  `ExSandbox.address/2` against a mechanism that implements the optional
  callback and one that does not.

  The case worth a test is the mechanism that omits it: `address/1` is optional
  precisely so a mechanism written before reachability existed keeps compiling,
  and a wrapper that called it anyway would turn every such mechanism into an
  `UndefinedFunctionError` at the moment a host first asked where a sandbox was.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Sandbox

  defmodule Silent do
    @moduledoc false
    # Deliberately no `address/1`: the shape of every mechanism that existed
    # before the callback did.
    @behaviour ExSandbox.Mechanism

    @impl true
    def provision(sandbox), do: {:ok, sandbox}
    @impl true
    def start(sandbox), do: {:ok, sandbox}
    @impl true
    def stop(sandbox), do: {:ok, sandbox}
    @impl true
    def destroy(_sandbox), do: :ok
    @impl true
    def status(_sandbox), do: {:ok, :running}
    @impl true
    def list_running, do: {:ok, []}
    @impl true
    def usage(_sandbox), do: {:ok, %{}}
    @impl true
    def execute(_sandbox, {_cmd, _args}, _opts \\ []), do: {:error, :not_supported}
  end

  defmodule Reachable do
    @moduledoc false
    @behaviour ExSandbox.Mechanism

    @impl true
    def provision(sandbox), do: {:ok, sandbox}
    @impl true
    def start(sandbox), do: {:ok, sandbox}
    @impl true
    def stop(sandbox), do: {:ok, sandbox}
    @impl true
    def destroy(_sandbox), do: :ok
    @impl true
    def status(_sandbox), do: {:ok, :running}
    @impl true
    def list_running, do: {:ok, []}
    @impl true
    def usage(_sandbox), do: {:ok, %{}}
    @impl true
    def execute(_sandbox, {_cmd, _args}, _opts \\ []), do: {:error, :not_supported}
    @impl true
    def address(%Sandbox{service_port: nil}), do: {:ok, nil}
    def address(%Sandbox{service_port: port}), do: {:ok, "127.0.0.1:#{port}"}
  end

  defp sandbox(overrides \\ []) do
    struct!(
      %Sandbox{
        id: "address-#{System.unique_integer([:positive])}",
        owner_ref: "t",
        template_ref: "t"
      },
      overrides
    )
  end

  test "a mechanism that implements the callback answers through it" do
    assert {:ok, "127.0.0.1:4000"} = ExSandbox.address(Reachable, sandbox(service_port: 4000))
    assert {:ok, nil} = ExSandbox.address(Reachable, sandbox())
  end

  test "a mechanism that does not implement it reports no address rather than raising" do
    assert {:ok, nil} = ExSandbox.address(Silent, sandbox(service_port: 4000))
  end
end
