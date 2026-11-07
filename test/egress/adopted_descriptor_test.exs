defmodule ExSandbox.Egress.AdoptedDescriptorTest do
  @moduledoc """
  A socket adopted with `{:fd, fd}` keeps its descriptor when it is closed.

  OTP's inet driver (inet_drv.c, outside this tree) marks such a socket
  `prebound` and `erl_inet_close/1` then skips the real close, on every route: `:gen_tcp.close/1`, a refused connect, a peer's
  EOF, the owner's exit. `:erlang.ports/0` therefore stays flat while
  `/proc/self/fd` climbs, so this file counts descriptors and not ports.

  The first two groups need no NIF and run on any host. The third drives the NIF's
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

    # The keeper `NetnsSocket.adopt/3` starts closes the descriptor itself. If
    # the driver ever did too, the second close would hit whatever socket now
    # has that number.
    test "a peer's EOF leaves it open too, so nothing else closes it first", ctx do
      :ok = :gen_tcp.close(ctx.peer)
      assert :gen_tcp.recv(ctx.adopted, 0, 1_000) == {:error, :closed}
      :ok = :gen_tcp.close(ctx.adopted)

      assert :socket.getopt(ctx.raw, :socket, :type) == {:ok, :stream}
    end

    test "the owner's exit leaves it open too, :kill included", ctx do
      owner = spawn(fn -> :gen_tcp.recv(ctx.adopted, 0) end)
      :ok = :gen_tcp.controlling_process(ctx.adopted, owner)
      Process.exit(owner, :kill)

      assert :gen_tcp.recv(ctx.peer, 0, 200) == {:error, :timeout}
    end
  end

  # The test stands in for the NIF. It opens the descriptor with `:socket`, the
  # release it hands the keeper only reports, and the test then closes the
  # descriptor once through `:socket`, which is what lets the peer see the EOF.
  describe "the keeper NetnsSocket.adopt/3 starts" do
    setup do
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: @loopback])
      {:ok, port} = :inet.port(listener)
      {:ok, raw} = :socket.open(:inet, :stream, :tcp)
      {:ok, fd} = :socket.getopt(raw, :otp, :fd)
      test = self()

      on_exit(fn -> :socket.close(raw) end)

      %{
        listener: listener,
        raw: raw,
        fd: fd,
        open: fn -> {:ok, fd} end,
        connect: &:gen_tcp.connect(@loopback, port, [:binary, active: false, fd: &1]),
        release: fn fd ->
          send(test, {:released, fd})
          :ok
        end
      }
    end

    test "an owner killed mid-recv gives the descriptor back once, after its port", ctx do
      test = self()

      owner =
        spawn(fn ->
          {:ok, socket} = NetnsSocket.adopt(ctx.open, :gen_tcp, ctx.connect, ctx.release)
          send(test, {:adopted, socket})
          :gen_tcp.recv(socket, 0)
        end)

      assert_receive {:adopted, socket}
      {:ok, peer} = :gen_tcp.accept(ctx.listener, 1_000)
      Process.exit(owner, :kill)

      assert_receive {:released, fd}
      assert fd == ctx.fd
      assert Port.info(socket) == nil
      refute_receive {:released, _}, 200

      :ok = :socket.close(ctx.raw)
      assert :gen_tcp.recv(peer, 0, 1_000) == {:error, :closed}
    end

    test "closing the socket gives the descriptor back once", ctx do
      {:ok, socket} = NetnsSocket.adopt(ctx.open, :gen_tcp, ctx.connect, ctx.release)
      refute_receive {:released, _}, 100

      :ok = :gen_tcp.close(socket)
      assert_receive {:released, _}
      refute_receive {:released, _}, 200
    end

    test "a refused adoption gives the descriptor back and says so", ctx do
      {:ok, closed} = :gen_tcp.listen(0, ip: @loopback)
      {:ok, port} = :inet.port(closed)
      :ok = :gen_tcp.close(closed)
      refused = &:gen_tcp.connect(@loopback, port, [:binary, active: false, fd: &1])

      assert NetnsSocket.adopt(ctx.open, :gen_tcp, refused, ctx.release) ==
               {:error, {:adopt, :econnrefused}}

      assert_receive {:released, _}
      refute_receive {:released, _}, 200
    end

    test "a caller killed while the keeper adopts gives the descriptor back", ctx do
      slow = fn fd ->
        Process.sleep(200)
        ctx.connect.(fd)
      end

      caller = spawn(fn -> NetnsSocket.adopt(ctx.open, :gen_tcp, slow, ctx.release) end)
      Process.sleep(50)
      Process.exit(caller, :kill)

      assert_receive {:released, _}, 1_000
      refute_receive {:released, _}, 200
    end

    test "a descriptor that never opened is not released", ctx do
      unsupported = fn -> {:error, :unsupported} end

      assert NetnsSocket.adopt(unsupported, :gen_tcp, ctx.connect, ctx.release) ==
               {:error, :unsupported}

      refute_receive {:released, _}, 100
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

    test "a connection the tenant closes first gives its descriptor back too",
         %{host_port: host_port} do
      {:ok, tenant} = :gen_tcp.listen(0, [:binary, active: false, ip: @loopback])
      {:ok, ns_port} = :inet.port(tenant)
      {:ok, acceptor} = start_acceptor(forward: [{host_port, ns_port}])

      before = descriptors()

      for _ <- 1..@connections do
        {:ok, client} = :gen_tcp.connect(@loopback, host_port, [:binary, active: false])
        {:ok, server} = :gen_tcp.accept(tenant, 5_000)

        :ok = :gen_tcp.close(server)
        assert :gen_tcp.recv(client, 0, 2_000) == {:error, :closed}
        :ok = :gen_tcp.close(client)
      end

      assert_flat(before, "after #{@connections} forwards the tenant closed")
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

    test "a relay killed mid-forward gives its upstream descriptor back and the tenant sees the close",
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

        Process.exit(relay_owning(server), :kill)
        assert :gen_tcp.recv(server, 0, 2_000) == {:error, :closed}
        :ok = :gen_tcp.close(server)
        :ok = :gen_tcp.close(client)
      end

      assert_flat(before, "after #{@connections} relays were killed")
      GenServer.stop(acceptor)
    end

    test "a killed acceptor gives back its listener and resolver descriptors" do
      before = descriptors()

      for _ <- 1..10 do
        {:ok, udp} = :gen_udp.open(0, ip: @loopback)
        {:ok, resolver_port} = :inet.port(udp)
        :gen_udp.close(udp)

        {:ok, acceptor} = start_acceptor(resolver: {@loopback, resolver_port})
        wait_for_continue(acceptor)
        Process.unlink(acceptor)
        Process.exit(acceptor, :kill)
      end

      assert_flat(before, "after 10 acceptors were killed")
    end
  end

  # The relay's upstream is the port whose local end is the tenant's peer, and
  # the relay is the process that port is connected to.
  defp relay_owning(server) do
    {:ok, upstream_end} = :inet.peername(server)

    Enum.find_value(:erlang.ports(), fn port ->
      with {:name, ~c"tcp_inet"} <- Port.info(port, :name),
           {:ok, ^upstream_end} <- :inet.sockname(port),
           {:connected, pid} <- Port.info(port, :connected) do
        pid
      else
        _ -> nil
      end
    end) || flunk("no port holds the relay's upstream end #{inspect(upstream_end)}")
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
