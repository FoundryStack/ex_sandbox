defmodule ExSandbox.Egress.RelayTest do
  @moduledoc """
  The outbound half: what happens *after* `decide/3` permits (005 T060a9).

  ## Why these tests do not go through the pool's listener

  `acceptor_transport_test.exs` documents the trap in detail: off-Linux every
  connection dies at `OriginalDst.read/1` with `:unavailable`, so the policy is
  never consulted and the relay is never reached. A relay test written against
  the pool's listener would be **vacuous on macOS** — green whether or not a
  single byte is ever forwarded, for the same reason the transport tests cannot
  establish anything about the allowlist there.

  So these drive `Relay.splice/3` directly with two real sockets. That is the
  decision the relay actually makes — *given a permitted connection and a
  destination, do bytes cross in both directions and is the pair torn down* —
  and it is reachable on every host.

  ⚠️ What this deliberately does NOT claim: that the redirect works, that
  `SO_ORIGINAL_DST` yields the right destination, or that a sandbox's traffic
  reaches here at all. Those are container facts, established by the conformance
  network group. These tests establish that the forwarding half is not a stub.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Relay

  # A throwaway echo server standing in for the destination. Returns the port
  # it listened on; the caller connects to it as the pool would.
  defp echo_server do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listener)

    # The echo task accepts AND uses its socket, so ownership stays with it and
    # no `controlling_process/2` transfer is needed -- unlike `client_pair/0`.
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

  # Stands in for the sandbox side: a connected pair, one end held by the test.
  #
  # ⚠️ `controlling_process/2` is load-bearing, and leaving it out cost three
  # failing tests that looked like relay defects. A `:gen_tcp` socket is owned
  # by the process that accepted it; the accepting `Task` exits as soon as it
  # returns, and the kernel closes the socket with it. The relay then had a
  # dead socket to work with and every byte-carrying assertion failed with
  # `{:error, :closed}` -- while the two REFUSAL tests passed, because a closed
  # socket is indistinguishable from a correctly refused one.
  #
  # That asymmetry is the point: a harness bug that closes sockets makes a
  # working relay look broken and a broken relay look correct. Worth the note,
  # because the next person to add a test here will reach for `Task.async` the
  # same way.
  defp client_pair do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listener)
    test_process = self()

    task =
      Task.async(fn ->
        {:ok, accepted} = :gen_tcp.accept(listener, 5_000)
        :ok = :gen_tcp.controlling_process(accepted, test_process)
        accepted
      end)

    {:ok, client} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 5_000)
    server_side = Task.await(task, 5_000)
    :gen_tcp.close(listener)
    {client, server_side}
  end

  test "a permitted connection carries bytes to the destination and back" do
    # ⚠️ The central non-vacuity assertion of the whole relay. Every other test
    # in the egress tree asserts that something is REFUSED, and a stub that
    # closes every socket satisfies all of them. This is the one that fails
    # against the placeholder, and it is why `FR-011a` calls an allowlist that
    # permits nothing an outage rather than confinement.
    {dest_port, echo} = echo_server()
    {client, sandbox_side} = client_pair()

    relay = Task.async(fn -> Relay.splice(sandbox_side, {{127, 0, 0, 1}, dest_port}, []) end)

    assert :ok = :gen_tcp.send(client, "ping")
    assert {:ok, "ping"} = :gen_tcp.recv(client, 0, 5_000)

    :gen_tcp.close(client)
    Task.shutdown(relay, :brutal_kill)
    Task.shutdown(echo, :brutal_kill)
  end

  test "bytes cross in both directions, not just sandbox to destination" do
    # ⚠️ A half-duplex relay forwards the request and drops the response. The
    # sandbox connects, sends, and hangs -- which reads as a slow destination
    # rather than a broken proxy, and every denial check still passes.
    {dest_port, echo} = echo_server()
    {client, sandbox_side} = client_pair()

    relay = Task.async(fn -> Relay.splice(sandbox_side, {{127, 0, 0, 1}, dest_port}, []) end)

    assert :ok = :gen_tcp.send(client, "first")
    assert {:ok, "first"} = :gen_tcp.recv(client, 0, 5_000)
    assert :ok = :gen_tcp.send(client, "second")
    assert {:ok, "second"} = :gen_tcp.recv(client, 0, 5_000)

    :gen_tcp.close(client)
    Task.shutdown(relay, :brutal_kill)
    Task.shutdown(echo, :brutal_kill)
  end

  test "an unreachable destination closes the sandbox side rather than hanging" do
    # ⚠️ Fail closed, and *visibly*. A relay that leaves the sandbox socket open
    # when the outbound connect fails turns a refusal into an indefinite hang:
    # from inside, indistinguishable from a destination that is merely slow, and
    # the conformance probe would time out rather than report a refusal.
    {client, sandbox_side} = client_pair()

    # Port 1 on loopback: nothing listens, and connect fails fast rather than
    # timing out the way a routed-but-silent address would.
    relay = Task.async(fn -> Relay.splice(sandbox_side, {{127, 0, 0, 1}, 1}, []) end)

    assert {:error, :closed} = :gen_tcp.recv(client, 0, 5_000)

    Task.shutdown(relay, :brutal_kill)
  end

  test "closing the destination closes the sandbox side" do
    # ⚠️ Without this the sandbox holds a socket to a destination that is gone,
    # and the pool holds the other end forever -- a descriptor leak whose only
    # symptom is the pool failing to accept once the limit is hit, long after
    # and nowhere near the cause.
    {dest_port, echo} = echo_server()
    {client, sandbox_side} = client_pair()

    relay = Task.async(fn -> Relay.splice(sandbox_side, {{127, 0, 0, 1}, dest_port}, []) end)

    assert :ok = :gen_tcp.send(client, "hello")
    assert {:ok, "hello"} = :gen_tcp.recv(client, 0, 5_000)

    # Killing the echo server drops the destination side.
    Task.shutdown(echo, :brutal_kill)

    assert {:error, :closed} = :gen_tcp.recv(client, 0, 5_000)

    :gen_tcp.close(client)
    Task.shutdown(relay, :brutal_kill)
  end

  test "splice returns rather than looping forever once the sandbox closes" do
    # ⚠️ The relay runs per connection. One that never returns is a process leak
    # per sandbox connection, which at any real rate exhausts the node -- and
    # like the descriptor leak above, it surfaces far from its cause.
    {dest_port, echo} = echo_server()
    {client, sandbox_side} = client_pair()

    relay = Task.async(fn -> Relay.splice(sandbox_side, {{127, 0, 0, 1}, dest_port}, []) end)

    :gen_tcp.send(client, "bye")
    :gen_tcp.recv(client, 0, 5_000)
    :gen_tcp.close(client)

    assert {:ok, _} = Task.yield(relay, 5_000),
           "splice/3 did not return after the sandbox closed; one leaked process per connection"

    Task.shutdown(echo, :brutal_kill)
  end
end
