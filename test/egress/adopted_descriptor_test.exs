defmodule ExSandbox.Egress.AdoptedDescriptorTest do
  @moduledoc """
  A socket adopted with `{:fd, fd}` keeps its descriptor when it is closed.

  `inet_drv.c` marks such a socket `prebound` and `erl_inet_close/1` then skips
  the real close, on every route: `:gen_tcp.close/1`, a refused connect, a peer's
  EOF, the owner's exit. `:erlang.ports/0` therefore stays flat while
  `/proc/self/fd` climbs, so this file counts descriptors and not ports.

  The first group needs no NIF and runs on any host. The second drives the NIF's
  sockets through a real acceptor and needs the isolation image, or any Linux
  container with `CAP_SYS_ADMIN` and `CAP_NET_ADMIN`.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Egress.Acceptor
  alias ExSandbox.Egress.NetnsSocket

  @loopback {127, 0, 0, 1}
  @connections 50
  @slack 5

  describe "what the driver does with an adopted socket" do
    setup do
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: @loopback])
      {:ok, port} = :inet.port(listener)
      {:ok, raw} = :socket.open(:inet, :stream, :tcp)
      {:ok, fd} = :socket.getopt(raw, :otp, :fd)
      {:ok, adopted} = :gen_tcp.connect(@loopback, port, [:binary, active: false, fd: fd])
      {:ok, peer} = :gen_tcp.accept(listener, 1_000)

      on_exit(fn -> :socket.close(raw) end)
      %{raw: raw, adopted: adopted, peer: peer}
    end

    test "close leaves the descriptor open: the peer sees no EOF", ctx do
      :ok = :gen_tcp.close(ctx.adopted)
      assert :gen_tcp.recv(ctx.peer, 0, 200) == {:error, :timeout}

      :ok = :socket.close(ctx.raw)
      assert :gen_tcp.recv(ctx.peer, 0, 1_000) == {:error, :closed}
    end

    # `NetnsSocket.close/1` closes the descriptor itself. If the driver ever did
    # too, the second close would hit whatever socket now has that number.
    test "a peer's EOF leaves it open too, so nothing else closes it first", ctx do
      :ok = :gen_tcp.close(ctx.peer)
      assert :gen_tcp.recv(ctx.adopted, 0, 1_000) == {:error, :closed}
      :ok = :gen_tcp.close(ctx.adopted)

      assert :socket.getopt(ctx.raw, :socket, :type) == {:ok, :stream}
    end
  end

  describe "the forward path" do
    @describetag :isolation

    setup do
      unless NetnsSocket.available?(), do: flunk("netns_nif did not load on a :isolation host")
      %{host_port: free_tcp_port()}
    end

    test "a refused connection gives its upstream descriptor back", %{host_port: host_port} do
      ns_port = free_tcp_port()
      {:ok, acceptor} = start_acceptor(forward: [{host_port, ns_port}])

      before = descriptors()
      ports_before = length(:erlang.ports())

      for _ <- 1..@connections do
        {:ok, client} = :gen_tcp.connect(@loopback, host_port, [:binary, active: false])
        assert :gen_tcp.recv(client, 0, 5_000) == {:error, :closed}
        :gen_tcp.close(client)
      end

      assert length(:erlang.ports()) - ports_before <= @slack
      assert_flat(before, "after #{@connections} refused forwards")
      GenServer.stop(acceptor)
    end

    test "a relayed connection gives its descriptor back and the tenant sees the close",
         %{host_port: host_port} do
      {:ok, tenant} = :gen_tcp.listen(0, [:binary, active: false, ip: @loopback])
      {:ok, ns_port} = :inet.port(tenant)
      {:ok, acceptor} = start_acceptor(forward: [{host_port, ns_port}])

      before = descriptors()

      for _ <- 1..@connections do
        {:ok, client} = :gen_tcp.connect(@loopback, host_port, [:binary, active: false])
        {:ok, server} = :gen_tcp.accept(tenant, 5_000)

        :ok = :gen_tcp.send(client, "ping")
        assert :gen_tcp.recv(server, 4, 5_000) == {:ok, "ping"}

        :ok = :gen_tcp.close(client)
        assert :gen_tcp.recv(server, 0, 2_000) == {:error, :closed}
        :ok = :gen_tcp.close(server)
      end

      assert_flat(before, "after #{@connections} relayed forwards")
      GenServer.stop(acceptor)
    end

    test "stopping the acceptor gives back its listener and resolver descriptors" do
      before = descriptors()

      for _ <- 1..10 do
        {:ok, udp} = :gen_udp.open(0, ip: @loopback)
        {:ok, resolver_port} = :inet.port(udp)
        :gen_udp.close(udp)

        {:ok, acceptor} = start_acceptor(resolver: {@loopback, resolver_port})
        wait_for_continue(acceptor)
        GenServer.stop(acceptor)
      end

      assert_flat(before, "after 10 acceptors came and went")
    end
  end

  defp start_acceptor(opts) do
    Acceptor.start_link(
      [source_key: {10, 200, 0, 0}, holder_pid: String.to_integer(System.pid()), port: 0] ++ opts
    )
  end

  defp wait_for_continue(acceptor), do: :sys.get_state(acceptor)

  defp free_tcp_port do
    {:ok, socket} = :gen_tcp.listen(0, ip: @loopback)
    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)
    port
  end

  defp descriptors, do: length(File.ls!("/proc/self/fd"))

  # Polled: a relay gives its upstream descriptor back just after the client sees
  # the close, so an immediate read races the last teardown.
  defp assert_flat(before, label, attempts \\ 40) do
    grown = descriptors() - before

    cond do
      grown <= @slack ->
        :ok

      attempts == 0 ->
        flunk("descriptors grew by #{grown} #{label}")

      true ->
        Process.sleep(50)
        assert_flat(before, label, attempts - 1)
    end
  end
end
