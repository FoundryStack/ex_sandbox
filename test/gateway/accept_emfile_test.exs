defmodule ExSandbox.Gateway.AcceptEmfileTest do
  @moduledoc """
  A gateway out of descriptors keeps its listener and its node.

  The gateway runs in a peer under `ulimit -n`, with the rest of the table filled
  the way a leak fills it. A connection then makes `:gen_tcp.accept/1` return
  `:emfile`. Exiting on that restarts `Server`, whose `init/1` needs a descriptor
  for the `id` it runs, which walks the restart intensity up to the application.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.BudgetMechanism
  alias ExSandbox.DescriptorHog
  alias ExSandbox.Gateway
  alias ExSandbox.Gateway.Protocol
  alias ExSandbox.Gateway.Server

  @limit ~c"ulimit -n 256; exec erl \"$@\""

  setup do
    path = "/tmp/exsg-emfile-#{System.unique_integer([:positive])}.sock"
    store = Path.join(System.tmp_dir!(), "exsg-emfile-#{System.unique_integer([:positive])}")
    code_path = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    {:ok, peer, _node} =
      :peer.start_link(%{
        connection: :standard_io,
        exec: {~c"/bin/sh", [~c"-c", @limit, ~c"sh"]},
        args: code_path
      })

    {:ok, _apps} = :peer.call(peer, Application, :ensure_all_started, [:elixir])
    :ok = :peer.call(peer, DescriptorHog, :preload, [])

    :peer.call(peer, :erlang, :spawn, [
      BudgetMechanism,
      :serve,
      [[socket_path: path, store_dir: store]]
    ])

    wait_for_socket(path)

    on_exit(fn ->
      File.rm(path)
      File.rm_rf(store)
    end)

    %{peer: peer, path: path}
  end

  test "an accept that hits :emfile leaves the server up, and it serves once a descriptor frees",
       %{peer: peer, path: path} do
    server = server_pid(peer)
    assert is_pid(server)

    hog = :peer.call(peer, DescriptorHog, :start, [])
    Process.sleep(500)

    {:ok, _refused} = connect(path)

    Process.sleep(1_000)
    assert server_pid(peer) == server

    :peer.call(peer, :erlang, :send, [hog, :release])

    # A fresh connection: Linux keeps the first one queued, macOS drops it.
    {:ok, client} = connect(path)
    hello = {:request, 1, :hello, %{versions: Protocol.versions()}}
    :ok = :gen_tcp.send(client, Protocol.encode(hello))
    assert {:ok, frame} = :gen_tcp.recv(client, 0, 10_000)
    assert {:ok, {:reply, 1, {:ok, %{version: _}}}} = Protocol.decode(frame)
  end

  defp connect(path),
    do: :gen_tcp.connect({:local, path}, 0, [:binary, packet: 4, active: false], 1_000)

  defp server_pid(peer) do
    peer
    |> :peer.call(Supervisor, :which_children, [Gateway])
    |> Enum.find_value(fn {id, pid, _, _} -> id == Server && pid end)
  catch
    :exit, _ -> nil
  end

  defp wait_for_socket(path, attempts \\ 100) do
    cond do
      File.exists?(path) ->
        :ok

      attempts == 0 ->
        flunk("the gateway never bound #{path}")

      true ->
        Process.sleep(20)
        wait_for_socket(path, attempts - 1)
    end
  end
end
