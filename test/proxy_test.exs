defmodule ExSandbox.ProxyTest do
  @moduledoc """
  Forwarding decisions refuse on anything but a positive answer (012 T041,
  `006` R4/R7).
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Conformance.Helpers
  alias ExSandbox.Proxy

  defmodule Running do
    @moduledoc false
    @behaviour ExSandbox.Mechanism
    @impl true
    def required_capabilities, do: []
    @impl true
    def provision(s), do: {:ok, s}
    @impl true
    def start(s), do: {:ok, s}
    @impl true
    def stop(s), do: {:ok, s}
    @impl true
    def destroy(_s), do: :ok
    @impl true
    def status(_s), do: {:ok, :running}
    @impl true
    def list_running, do: {:ok, []}
    @impl true
    def usage(_s), do: {:ok, %{}}
  end

  defmodule Stopped do
    @moduledoc false
    @behaviour ExSandbox.Mechanism
    @impl true
    def required_capabilities, do: []
    @impl true
    def provision(s), do: {:ok, s}
    @impl true
    def start(s), do: {:ok, s}
    @impl true
    def stop(s), do: {:ok, s}
    @impl true
    def destroy(_s), do: :ok
    @impl true
    def status(_s), do: {:ok, :stopped}
    @impl true
    def list_running, do: {:ok, []}
    @impl true
    def usage(_s), do: {:ok, %{}}
  end

  defmodule Blind do
    @moduledoc false
    @behaviour ExSandbox.Mechanism
    @impl true
    def required_capabilities, do: []
    @impl true
    def provision(s), do: {:ok, s}
    @impl true
    def start(s), do: {:ok, s}
    @impl true
    def stop(s), do: {:ok, s}
    @impl true
    def destroy(_s), do: :ok
    @impl true
    def status(_s), do: {:error, :cannot_reach_daemon}
    @impl true
    def list_running, do: {:ok, []}
    @impl true
    def usage(_s), do: {:ok, %{}}
  end

  defp with_address(address) do
    Helpers.build_sandbox(context: %{address: address})
  end

  describe "the authorizing case" do
    test "a running sandbox with an address resolves" do
      assert {:ok, {"127.0.0.1", 4001}} =
               Proxy.target(Running, with_address({"127.0.0.1", 4001}))
    end

    test "the address is returned uninterpreted (FR-007)" do
      # A node name, a tuple, a path -- this library stores and returns, never
      # parses. Any structure it understood would be structure it could break.
      weird = {:via, :some_registry, %{node: :sandbox@host, extra: [1, 2]}}
      assert {:ok, ^weird} = Proxy.target(Running, with_address(weird))
    end
  end

  describe "the refusing cases (006 R4)" do
    test "a stopped sandbox is refused, with the status named" do
      assert {:error, {:not_running, :stopped}} =
               Proxy.target(Stopped, with_address({"127.0.0.1", 4001}))
    end

    test "a mechanism that cannot report status refuses rather than forwarding" do
      # The row most likely to be written the other way. "We could not tell"
      # arriving at a live sandbox is how a request reaches the wrong tenant.
      assert {:error, {:status_unknown, :cannot_reach_daemon}} =
               Proxy.target(Blind, with_address({"127.0.0.1", 4001}))
    end

    test "a running sandbox with no recorded address is refused" do
      assert {:error, :no_address} = Proxy.target(Running, Helpers.build_sandbox())
    end

    test "a nil address is not an address" do
      assert {:error, :no_address} = Proxy.target(Running, with_address(nil))
    end
  end

  describe "address/1 answers a different question than target/2" do
    test "it resolves without a status check" do
      # Deliberately usable before the sandbox is observably running, for a
      # mechanism's own start path.
      assert {:ok, {"127.0.0.1", 4001}} =
               Proxy.address(with_address({"127.0.0.1", 4001}))
    end

    test "it still refuses when there is nothing to return" do
      assert {:error, :no_address} = Proxy.address(Helpers.build_sandbox())
    end
  end

  describe "no caching (006 R7)" do
    test "the source declares no cache" do
      source = File.read!("lib/ex_sandbox/proxy.ex")

      refute source =~ ~r/:ets\.(new|insert|lookup)/,
             "the proxy caches addresses. A stale route is a cross-tenant breach " <>
               "(006 R7), not a correctness bug."

      refute source =~ ~r/:persistent_term|Cachex/
    end

    test "two calls both consult the mechanism" do
      defmodule Counting do
        @moduledoc false
        @behaviour ExSandbox.Mechanism
        @impl true
        def required_capabilities, do: []
        @impl true
        def provision(s), do: {:ok, s}
        @impl true
        def start(s), do: {:ok, s}
        @impl true
        def stop(s), do: {:ok, s}
        @impl true
        def destroy(_s), do: :ok
        @impl true
        def status(_s) do
          count = Process.get(:status_calls, 0)
          Process.put(:status_calls, count + 1)
          {:ok, :running}
        end

        @impl true
        def list_running, do: {:ok, []}
        @impl true
        def usage(_s), do: {:ok, %{}}
      end

      sandbox = with_address({"127.0.0.1", 4001})
      Proxy.target(Counting, sandbox)
      Proxy.target(Counting, sandbox)

      assert Process.get(:status_calls) == 2,
             "the second call reused the first answer -- that is the cache 006 R7 forbids"
    end
  end
end
