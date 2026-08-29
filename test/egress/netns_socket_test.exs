defmodule ExSandbox.Egress.NetnsSocketTest do
  use ExUnit.Case, async: true

  @moduledoc """
  The contract of `ExSandbox.Egress.NetnsSocket`, on both kinds of host.

  ## What this file does NOT establish

  Every namespace used here is `/proc/self/ns/net` — the namespace this BEAM is
  already in. That exercises the whole syscall path (`open`, `setns`, `socket`,
  `bind`, `listen`, `setsockopt`, the readback, and the `{:fd, _}` adoption) with
  no privileged setup, but it cannot show that a socket lands somewhere the BEAM
  is not. Only `docker/compose.isolation.yml` with a real sandbox can, because
  only there does a second namespace exist.

  The measurement that shows the crossing is recorded in `c_src/netns_nif.c`:
  a listener adopted from a namespace fd, unreachable from the host namespace
  (`:econnrefused`), reachable from inside it. Do not read a green run here as
  evidence of that.
  """

  alias ExSandbox.Egress.NetnsSocket

  @self_netns "/proc/self/ns/net"

  describe "availability" do
    test "available?/0 agrees with whether the shared object was built" do
      # Not `:os.type() == {:unix, :linux}`. A Linux host built without a C
      # compiler must report the same `false` as macOS, and asserting on the
      # platform instead of the artefact would call that host available.
      built? = File.exists?(Path.join(:code.priv_dir(:ex_sandbox), "netns_nif.so"))
      assert NetnsSocket.available?() == built?
    end
  end

  describe "when namespace-local sockets are unavailable" do
    @describetag :skip_if_available

    test "both entry points refuse rather than falling back to the host namespace" do
      if NetnsSocket.available?() do
        # ⚠️ Not a failure, and not silently skipped either. See the moduletag
        # note: on a host where the NIF loaded there is no unavailable case to
        # exercise, and the refusal is covered by the type signature alone.
        :ok
      else
        assert NetnsSocket.listen(@self_netns, 0) == {:error, :unsupported}
        assert NetnsSocket.socket(@self_netns, 42) == {:error, :unsupported}
      end
    end
  end

  describe "descriptors" do
    @describetag :isolation

    setup do
      unless NetnsSocket.available?() do
        flunk(
          "netns_nif did not load on a host tagged :isolation -- the NIF " <>
            "build failed, and every network check is about to fail for a " <>
            "reason that will not name it"
        )
      end

      :ok
    end

    test "listen/2 produces a descriptor gen_tcp adopts" do
      assert {:ok, fd} = NetnsSocket.listen(@self_netns, 0)
      assert is_integer(fd) and fd > 2

      assert {:ok, socket} =
               :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}, {:fd, fd}])

      assert {:ok, {{0, 0, 0, 0}, port}} = :inet.sockname(socket)
      assert port > 0
      :gen_tcp.close(socket)
    end

    test "listen/2 binds INADDR_ANY, not loopback" do
      # ⚠️ Load-bearing, and measured rather than stylistic: the redirect
      # rewrites the destination to the namespace's own primary address, so a
      # connection arrives from e.g. `172.19.0.4` and a loopback-bound listener
      # is never reached. A socket bound to 127.0.0.1 would pass every unit test
      # here and accept nothing in production.
      assert {:ok, fd} = NetnsSocket.listen(@self_netns, 0)
      assert {:ok, socket} = :gen_tcp.listen(0, [:binary, {:active, false}, {:fd, fd}])
      assert {:ok, {{0, 0, 0, 0}, _}} = :inet.sockname(socket)
      :gen_tcp.close(socket)
    end

    test "socket/2 carries SO_MARK through the adoption into inet" do
      assert {:ok, fd} = NetnsSocket.socket(@self_netns, 42)
      assert {:ok, socket} = :gen_tcp.listen(0, [:binary, {:active, false}, {:fd, fd}])

      # `SOL_SOCKET` is 1 and `SO_MARK` is 36; OTP exposes no named option.
      assert {:ok, [{:raw, 1, 36, <<42, 0, 0, 0>>}]} =
               :inet.getopts(socket, [{:raw, 1, 36, 4}])

      :gen_tcp.close(socket)
    end

    test "udp/2 produces a descriptor gen_udp adopts" do
      assert {:ok, fd} = NetnsSocket.udp(@self_netns, 0)
      assert {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}, {:fd, fd}])
      assert {:ok, {{0, 0, 0, 0}, port}} = :inet.sockname(socket)
      assert port > 0
      :gen_udp.close(socket)
    end

    test "udp/2 carries a datagram, so the DNS leg has a real socket" do
      # ⚠️ Not just "a descriptor came back". A bound socket that cannot receive
      # is what a wrong `bind` produces, and the symptom in production is names
      # silently not resolving -- which reads as a slow network, and which every
      # denial check scores as green.
      assert {:ok, fd} = NetnsSocket.udp(@self_netns, 0)
      assert {:ok, server} = :gen_udp.open(0, [:binary, {:active, false}, {:fd, fd}])
      assert {:ok, {_, port}} = :inet.sockname(server)

      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])
      :ok = :gen_udp.send(client, {127, 0, 0, 1}, port, "QUERY")

      assert {:ok, {_address, _port, "QUERY"}} = :gen_udp.recv(server, 0, 2_000)

      :gen_udp.close(client)
      :gen_udp.close(server)
    end

    test "a namespace that does not exist yields a named failure and no descriptor" do
      # The stage name is the point. `{:error, :open, 2}` says the path was
      # wrong; `{:error, :setns, 1}` would say the capability was missing. Both
      # would otherwise arrive as "the network did not work".
      assert {:error, :open, errno} = NetnsSocket.listen("/proc/self/ns/no-such-thing", 0)
      assert errno == 2
    end

    test "a descriptor is never returned for a mark the kernel refused" do
      # ⚠️ This is the whole reason the mark is set in C. `:inet.setopts/2`
      # reports `:ok` when the kernel rejects `SO_MARK` for want of
      # `CAP_NET_ADMIN`/`CAP_NET_RAW`, and the option then reads back as zero --
      # measured. An Elixir-side set fails OPEN, and the symptom is a
      # *permitted* destination timing out while every denial check stays green.
      #
      # On this host the capability is present, so the assertion available here
      # is the positive one: whatever comes back has the mark the caller asked
      # for. The negative is measured in `c_src/netns_nif.c` with the capability
      # dropped, where the same call returns `{:error, :setsockopt_mark, 1}`.
      case NetnsSocket.socket(@self_netns, 7) do
        {:ok, fd} ->
          {:ok, socket} = :gen_tcp.listen(0, [:binary, {:active, false}, {:fd, fd}])

          assert {:ok, [{:raw, 1, 36, <<7, 0, 0, 0>>}]} =
                   :inet.getopts(socket, [{:raw, 1, 36, 4}])

          :gen_tcp.close(socket)

        {:error, stage, _errno} ->
          assert stage in [:setsockopt_mark, :getsockopt_mark, :mark_readback_mismatch]
      end
    end
  end
end
