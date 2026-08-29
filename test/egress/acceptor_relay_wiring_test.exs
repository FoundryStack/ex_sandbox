defmodule ExSandbox.Egress.AcceptorRelayWiringTest do
  @moduledoc """
  That the acceptor actually *calls* the relay on the permit path, and never on
  any other (005 T060a9).

  ## Why this file exists separately from `relay_test.exs`

  `relay_test.exs` establishes that `Relay.splice/3` carries bytes. That is a
  statement about the relay, not about the acceptor, and the two were
  disconnected for the entire time `Egress.Pool.relay/2` was a placeholder that logged
  and closed.

  ⚠️ **Measured, and the reason this file exists:** replacing the permit branch's
  `Relay.splice/3` call with `:gen_tcp.close(socket)` -- reverting it to the
  placeholder in every way that matters -- left **all 306 host tests green**.
  Every connection that reaches the real listener on macOS dies at
  `OriginalDst.read/1` with `:unavailable`, so the permit branch never executes
  and the relay call is unreachable code. A correct relay and no relay at all are
  indistinguishable to the whole host suite.

  That is the same defect species as the unsupervised Egress.Pool (`3a4f5eb`)
  and the unreferenced `Egress.Binding` (`8af4e76`): a component that is correct
  in isolation and wired to nothing. All three were found by sabotage, and none
  by reading.

  ## ⚠️ This file used to test the wrong copy of this code

  It was `pool_relay_wiring_test.exs`, and it drove `Egress.Pool.handle_connection/3`.
  That function was reachable only from `Pool`'s own listener, which binds
  `127.0.0.1` in the **host** namespace -- and an `nft` `redirect` is DNAT to the
  local machine as the *sandbox's* namespace sees it, so nothing was ever
  redirected there. The tested implementation was dead and the live one, here,
  had two tests. Moving the file is the whole point of the change that produced
  it: these assertions now stand over the code a tenant's connection actually
  reaches.

  ## How the path is made reachable off Linux

  `init/1` is called with `listen: false` and two fields of the resulting state
  are then rewritten in this process:

    * `destination_reader`, because `SO_ORIGINAL_DST` does not exist on macOS.
    * `netns`, because entering one needs a namespace and `CAP_NET_ADMIN`, and
      `nil` is the relay's documented "there is no namespace" case rather than a
      fallback for one that could not be entered.

  Everything downstream is the real code: the real `verdict/3`, the real
  registry, the real `Decision.decide/3`, the real relay.

  ⚠️ Neither field is settable through `start_link/1`, and that is deliberate
  rather than incidental. A host able to substitute the destination reader could
  name any destination and have the policy evaluated against that rather than
  against the kernel's record, which is the forgeable claim `OriginalDst` exists
  to prevent. Rewriting a map inside a test process is not an interface.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Egress.Acceptor
  alias ExSandbox.Egress.Registry

  # The acceptor's `source_key` is the sandbox's /30. `sandbox_address/1` turns
  # it into `{127, 0, 0, 2}`, which `Policy.source_key/1` masks straight back to
  # this key -- so registering it here is registering the policy for the sandbox
  # this acceptor serves.
  @source_key {127, 0, 0, 0}

  setup do
    registry = start_supervised!({Registry, name: :"reg_#{System.unique_integer([:positive])}"})
    %{registry: registry}
  end

  defp state(registry, destination_read) do
    {:ok, state} =
      Acceptor.init(
        source_key: @source_key,
        holder_pid: 1,
        port: 18_080,
        resolver: nil,
        registry: registry,
        listen: false
      )

    %{state | netns: nil, destination_reader: fn _socket -> destination_read end}
  end

  # ⚠️ Mirrors `accept_loop/1`'s ownership handshake rather than calling the
  # handler inline, and the difference is not cosmetic. `:gen_tcp.recv/3` on a
  # passive socket is refused for any process that is not the controlling one,
  # so a handler running in the test process while the test process still owns
  # the socket makes the relay's own `recv` fail with `:einval` -- it tears the
  # pair down before a byte moves, and a PERMITTED destination reads as refused.
  # That is how the race this handshake closes was found.
  defp handle_owned(socket, state) do
    test_process = self()

    {:ok, pid} =
      Task.start(fn ->
        receive do
          :owned -> send(test_process, {:handled, Acceptor.handle_connection(socket, state)})
        end
      end)

    :ok = :gen_tcp.controlling_process(socket, pid)
    send(pid, :owned)
    :ok
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

  # One connected pair, standing in for a tenant connection the acceptor has
  # just accepted. Returns the client end and the end the acceptor would hold.
  defp accepted_pair do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listener)
    test_process = self()

    accepted =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        :ok = :gen_tcp.controlling_process(socket, test_process)
        socket
      end)

    {:ok, client} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 5_000)
    server_side = Task.await(accepted, 5_000)

    on_exit(fn ->
      :gen_tcp.close(client)
      :gen_tcp.close(listener)
    end)

    {client, server_side}
  end

  test "a permitted connection is relayed, not closed", %{registry: registry} do
    # ⚠️ THE test of this file. It is the only assertion anywhere that fails if
    # the acceptor stops calling the relay, and it is why the seams above exist.
    {dest_port, echo} = echo_server()
    :ok = Registry.assign(@source_key, [{"127.0.0.1", dest_port}], registry)

    {client, server_side} = accepted_pair()

    handle_owned(server_side, state(registry, {:ok, {{127, 0, 0, 1}, dest_port}}))

    assert :ok = :gen_tcp.send(client, "through")

    assert {:ok, "through"} = :gen_tcp.recv(client, 0, 5_000),
           "a PERMITTED connection did not reach its destination -- the acceptor is not calling the relay"

    Task.shutdown(echo, :brutal_kill)
  end

  # ⚠️ **A sabotage that SURVIVED this file, and what it taught.** The first
  # attempt at breaking the deny path relayed refused connections to
  # `127.0.0.1:1` -- a dead port. Every test stayed green, because the relay
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

    # Registered, but the permitted destination is a DIFFERENT port, so the echo
    # server is denied. This is not `:unknown_source`.
    :ok = Registry.assign(@source_key, [{"127.0.0.1", dest_port + 1}], registry)

    {client, server_side} = accepted_pair()

    handle_owned(server_side, state(registry, {:ok, {{127, 0, 0, 1}, dest_port}}))
    assert_receive {:handled, :ok}, 5_000

    assert {:error, :closed} = :gen_tcp.recv(client, 0, 5_000),
           "a DENIED destination was reachable -- the relay is being called on the deny path"

    Task.shutdown(echo, :brutal_kill)
  end

  test "an unknown source is closed even though a relay now exists", %{registry: registry} do
    # Default-deny, re-checked now that a forwarding path exists. `decide/3`'s
    # unit test covers the verdict; this covers the consequence at the socket.
    {dest_port, echo} = echo_server()
    {client, server_side} = accepted_pair()

    # Nothing registered for this /30.
    handle_owned(server_side, state(registry, {:ok, {{127, 0, 0, 1}, dest_port}}))
    assert_receive {:handled, :ok}, 5_000

    assert {:error, :closed} = :gen_tcp.recv(client, 0, 5_000),
           "an UNREGISTERED source reached a destination -- default-deny is not holding"

    Task.shutdown(echo, :brutal_kill)
  end

  test "a destination that cannot be read is closed, not relayed", %{registry: registry} do
    # ⚠️ The fault path, which is the one a relay makes dangerous. A malfunction
    # must fail toward refusal; forwarding here would mean the enforcement point
    # stops enforcing precisely when something is wrong with it.
    :ok = Registry.assign(@source_key, [{"127.0.0.1", 9999}], registry)

    {client, server_side} = accepted_pair()

    handle_owned(server_side, state(registry, {:error, :unavailable}))
    assert_receive {:handled, :ok}, 5_000

    assert {:error, :closed} = :gen_tcp.recv(client, 0, 5_000)
  end
end
