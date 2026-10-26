defmodule ExSandbox.Gateway.BudgetTest do
  @moduledoc """
  The gateway's budget (`let-sandboxes-outlive-a-deploy` task 2.5): a gateway
  VM holding 25 sandboxes idles at no more than 80 MB resident, and a call
  through it adds no more than 1 ms at p99 over the mechanism's own call, for
  terms up to 64 KB.

  The gateway runs in a peer VM over `ExSandbox.BudgetMechanism`, so the
  resident size is the gateway's and the overhead is the socket hop alone.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.BudgetMechanism
  alias ExSandbox.Mechanism.Gateway
  alias ExSandbox.Sandbox

  @sandboxes 25
  @rss_budget_kb 80 * 1024
  @p99_budget_us 1_000
  @calls 400

  setup do
    path = "/tmp/exsg-budget-#{System.unique_integer([:positive])}.sock"
    store = Path.join(System.tmp_dir!(), "exsg-budget-#{System.unique_integer([:positive])}")
    paths = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])
    args = paths ++ Enum.map(release_vm_args(), &String.to_charlist/1)
    {:ok, peer, _node} = :peer.start_link(%{connection: :standard_io, args: args})
    {:ok, _apps} = :peer.call(peer, Application, :ensure_all_started, [:elixir])
    :ok = :peer.call(peer, Application, :load, [:ex_sandbox])
    {:ok, modules} = :peer.call(peer, :application, :get_key, [:ex_sandbox, :modules])
    :peer.call(peer, :code, :ensure_modules_loaded, [modules])

    :peer.call(peer, :erlang, :spawn, [
      BudgetMechanism,
      :serve,
      [[socket_path: path, store_dir: store]]
    ])

    start_supervised!({Gateway, socket_path: path})

    on_exit(fn ->
      File.rm(path)
      File.rm_rf(store)
    end)

    sandboxes =
      for n <- 1..@sandboxes do
        sandbox = %Sandbox{id: "budget-#{n}", owner_ref: "o", template_ref: "t"}
        {:ok, provisioned} = ExSandbox.provision(Gateway, sandbox)
        {:ok, started} = ExSandbox.start(Gateway, provisioned)
        started
      end

    %{peer: peer, sandboxes: sandboxes}
  end

  if :os.type() != {:unix, :linux} do
    @tag skip: "the budget is a Linux host's resident size; a bare macOS VM alone reads 66 MB"
  end

  test "an idle gateway with 25 sandboxes stays within 80 MB resident", %{
    peer: peer,
    sandboxes: sandboxes
  } do
    assert {:ok, running} = Gateway.list_running()
    assert length(running) == length(sandboxes)

    :peer.call(peer, :erlang, :garbage_collect, [])
    os_pid = :peer.call(peer, :os, :getpid, [])

    [rss] =
      Regex.run(~r/VmRSS:\s+(\d+) kB/, File.read!("/proc/#{os_pid}/status"),
        capture: :all_but_first
      )

    rss_kb = String.to_integer(rss)

    IO.puts("gateway idle RSS with #{@sandboxes} sandboxes: #{div(rss_kb, 1024)} MB")
    assert rss_kb <= @rss_budget_kb, "the gateway reads #{rss_kb} KB resident"
  end

  test "a call through the gateway adds at most 1 ms at p99 for terms up to 64 KB", %{
    sandboxes: [sandbox | _]
  } do
    for size <- [64, 4 * 1024, 64 * 1024] do
      term = :binary.copy(<<7>>, size)
      {:ok, ^term} = Gateway.call(sandbox, Function, :identity, [term])

      through = p99(fn -> Gateway.call(sandbox, Function, :identity, [term]) end)
      direct = p99(fn -> BudgetMechanism.call(sandbox, Function, :identity, [term], 5_000) end)
      overhead = through - direct

      IO.puts("gateway call overhead at #{size} B: p99 #{overhead} us")
      assert overhead <= @p99_budget_us, "#{size} B adds #{overhead} us at p99"
    end
  end

  defp release_vm_args do
    Path.expand("../../rel/vm.args.eex", __DIR__)
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.reject(&String.starts_with?(&1, "#"))
    |> Enum.flat_map(&String.split/1)
  end

  defp p99(fun) do
    samples =
      for _ <- 1..@calls do
        {us, {:ok, _}} = :timer.tc(fun)
        us
      end

    samples |> Enum.sort() |> Enum.at(div(@calls * 99, 100) - 1)
  end
end
