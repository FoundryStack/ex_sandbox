defmodule ExSandbox.Egress.PoolRelayWiringTest do
  @moduledoc """
  That the pool actually *calls* the relay on the permit path (005 T060a9).

  ## Why this file exists separately from `relay_test.exs`

  `relay_test.exs` establishes that `Relay.splice/3` carries bytes. That is a
  statement about the relay, not about the pool, and the two were disconnected
  for the entire time the placeholder existed.

  ⚠️ **Measured, and the reason this file exists:** replacing the pool's
  `Relay.splice/3` call with `:gen_tcp.close(socket)` -- reverting it to the
  placeholder in every way that matters -- left **all 306 host tests green**.
  Every test that reaches the pool's listener on macOS dies at
  `OriginalDst.read/1` with `:unavailable`, so the `:permitted` branch never
  executes and the relay call is unreachable code. A correct relay and no relay
  at all are indistinguishable to the whole host suite.

  That is the same defect species as the unsupervised `Egress.Pool` (`3a4f5eb`)
  and the unreferenced `Egress.Binding` (`8af4e76`): a component that is correct
  in isolation and wired to nothing. All three were found by sabotage, and none
  by reading.

  ## How the path is made reachable

  `handle_connection/3` takes a destination reader, defaulting to the real one.
  These tests pass a stub, which is the *only* thing macOS genuinely cannot do
  -- `SO_ORIGINAL_DST` does not exist there. Everything downstream is the real
  code: the real `decide/3`, the real registry, the real relay.

  ⚠️ The stub is a test seam and not a configuration option. A host that could
  substitute the destination reader could name any destination and have the
  policy evaluated against that rather than against the kernel's record, which
  is the forgeable claim `OriginalDst` exists to prevent. `start_link/1` does
  not accept it.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Egress.Pool
  alias ExSandbox.Egress.Registry

  setup do
    registry = start_supervised!({Registry, name: :"reg_#{System.unique_integer([:positive])}"})
    %{registry: registry}
  end

  # An echo server standing in for a permitted destination.
  defp echo_server do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listener)

    task =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        echo_loop(socket)
        :gen_tcp.close(listener)
      end)

    {port, task}
  end

  defp echo_loop(socket) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, data} ->
        :gen_tcp.send(socket, data)
        echo_loop(socket)

      {:error, _} ->
        :gen_tcp.close(socket)
    end
  end

  test "a permitted connection is relayed, not closed", %{registry: registry} do
    # ⚠️ THE test of this file. It is the only assertion anywhere that fails if
    # the pool stops calling the relay, and it is why the seam above exists.
    {dest_port, echo} = echo_server()

    # Register the loopback /30 -- the source these test connections arrive
    # from -- with the echo server as its one permitted destination.
    :ok = Registry.assign({127, 0, 0, 0}, [{"127.0.0.1", dest_port}], registry)

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, pool_port} = :inet.port(listener)
    test_process = self()

    accepted =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        :ok = :gen_tcp.controlling_process(socket, test_process)
        socket
      end)

    {:ok, client} = :gen_tcp.connect(~c"127.0.0.1", pool_port, [:binary, active: false], 5_000)
    server_side = Task.await(accepted, 5_000)

    # The real handler, with the real registry and the real relay. Only the
    # destination read is stubbed, because macOS cannot perform it.
    Pool.handle_connection(server_side, registry, fn _socket ->
      {:ok, {{127, 0, 0, 1}, dest_port}}
    end)

    assert :ok = :gen_tcp.send(client, "through")

    assert {:ok, "through"} = :gen_tcp.recv(client, 0, 5_000),
           "a PERMITTED connection did not reach its destination -- the pool is not calling the relay"

    :gen_tcp.close(client)
    :gen_tcp.close(listener)
    Task.shutdown(echo, :brutal_kill)
  end

  # ⚠️ **A sabotage that SURVIVED this file, and what it taught.** The first
  # attempt at breaking the deny path relayed refused connections to
  # `127.0.0.1:1` -- a dead port. All 9 tests stayed green, because the relay
  # failed to connect and closed the socket, which is byte-for-byte the outcome
  # a correct refusal produces. The tests assert on the socket, and the socket
  # could not tell the difference.
  #
  # The sabotage that does get caught forwards denials to the destination the
  # sandbox actually asked for -- which is also the only version a real bug
  # would take, since a relay wired to a hardcoded dead port is not a plausible
  # mistake. Recorded because the surviving sabotage was *reassuring* and
  # meaningless: it proved the tests tolerate a broken forward, not that they
  # detect an unauthorised one.
  test "a denied connection is still closed once the relay exists", %{registry: registry} do
    # ⚠️ The other direction, and the one that matters more. Adding a relay is
    # the single change in this subsystem that could turn a denial into a
    # forward -- every other component fails safe when it fails. A relay reached
    # on the deny path would be a boundary that enforces nothing while every
    # unit test of `decide/3` still passes.
    {dest_port, echo} = echo_server()

    # Registered, but the permitted destination is a DIFFERENT port, so the
    # echo server is denied. This is not `:unknown_source`.
    :ok = Registry.assign({127, 0, 0, 0}, [{"127.0.0.1", dest_port + 1}], registry)

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, pool_port} = :inet.port(listener)
    test_process = self()

    accepted =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        :ok = :gen_tcp.controlling_process(socket, test_process)
        socket
      end)

    {:ok, client} = :gen_tcp.connect(~c"127.0.0.1", pool_port, [:binary, active: false], 5_000)
    server_side = Task.await(accepted, 5_000)

    Pool.handle_connection(server_side, registry, fn _socket ->
      {:ok, {{127, 0, 0, 1}, dest_port}}
    end)

    assert {:error, :closed} = :gen_tcp.recv(client, 0, 5_000),
           "a DENIED destination was reachable -- the relay is being called on the deny path"

    :gen_tcp.close(listener)
    Task.shutdown(echo, :brutal_kill)
  end

  test "an unknown source is closed even though a relay now exists", %{registry: registry} do
    # Default-deny, re-checked now that a forwarding path exists. `decide/3`'s
    # unit test covers the verdict; this covers the consequence at the socket.
    {dest_port, echo} = echo_server()

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, pool_port} = :inet.port(listener)
    test_process = self()

    accepted =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        :ok = :gen_tcp.controlling_process(socket, test_process)
        socket
      end)

    {:ok, client} = :gen_tcp.connect(~c"127.0.0.1", pool_port, [:binary, active: false], 5_000)
    server_side = Task.await(accepted, 5_000)

    # Nothing registered for this /30.
    Pool.handle_connection(server_side, registry, fn _socket ->
      {:ok, {{127, 0, 0, 1}, dest_port}}
    end)

    assert {:error, :closed} = :gen_tcp.recv(client, 0, 5_000),
           "an UNREGISTERED source reached a destination -- default-deny is not holding"

    :gen_tcp.close(listener)
    Task.shutdown(echo, :brutal_kill)
  end

  test "a destination that cannot be read is closed, not relayed", %{registry: registry} do
    # ⚠️ The fault path, which is the one a relay makes dangerous. A malfunction
    # must fail toward refusal; forwarding here would mean the enforcement point
    # stops enforcing precisely when something is wrong with it.
    :ok = Registry.assign({127, 0, 0, 0}, [{"127.0.0.1", 9999}], registry)

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, pool_port} = :inet.port(listener)
    test_process = self()

    accepted =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        :ok = :gen_tcp.controlling_process(socket, test_process)
        socket
      end)

    {:ok, client} = :gen_tcp.connect(~c"127.0.0.1", pool_port, [:binary, active: false], 5_000)
    server_side = Task.await(accepted, 5_000)

    Pool.handle_connection(server_side, registry, fn _socket -> {:error, :unavailable} end)

    assert {:error, :closed} = :gen_tcp.recv(client, 0, 5_000)

    :gen_tcp.close(listener)
  end
end
