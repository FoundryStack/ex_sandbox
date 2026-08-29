defmodule ExSandbox.Egress.AcceptorConnectionTest do
  use ExUnit.Case, async: true

  @moduledoc """
  What `ExSandbox.Egress.Acceptor` does with one accepted connection.

  ## Why this is worth a host-agnostic test

  The acceptor moved from a separate OS process into this node (2026-08-29), and
  with it the per-connection decision moved from `nsacceptor.py` into
  `handle_connection/2`. That code is only *reached* on Linux with a real
  namespace, so without this file its behaviour would be established solely by
  the isolation suite — which is the arrangement that let four earlier defects in
  this subsystem survive, each of them correct code that nothing reached.

  ⚠️ The direction that matters is the one this file checks. Every other
  component here fails safe when it fails: a broken decoder refuses, a missing
  policy denies. The acceptor is a place where the *natural* bug goes the other
  way — a connection whose destination could not be read is not a policy
  decision, and code that relayed it anyway would be an enforcement point that
  stops enforcing exactly when something is wrong with it.
  """

  alias ExSandbox.Egress.Acceptor

  setup do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, {:active, false}, {:ip, {127, 0, 0, 1}}])
    {:ok, port} = :inet.port(listener)
    {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, {:active, false}])
    {:ok, accepted} = :gen_tcp.accept(listener, 1_000)

    on_exit(fn ->
      :gen_tcp.close(client)
      :gen_tcp.close(listener)
    end)

    %{accepted: accepted, client: client}
  end

  defp state do
    {:ok, state} =
      Acceptor.init(
        source_key: {10, 0, 99, 0},
        holder_pid: 1,
        port: 18_080,
        resolver: nil,
        listen: false
      )

    state
  end

  test "a connection whose destination cannot be read is closed, not relayed", %{
    accepted: accepted,
    client: client
  } do
    # ⚠️ An ordinary loopback socket carries no `SO_ORIGINAL_DST` record: it was
    # never redirected. That is a host or kernel fault rather than a denial, and
    # it is deliberately treated the same way at the socket -- closed.
    #
    # On macOS the option is silently absent for every connection, which is what
    # makes this reachable off Linux at all. `ExSandbox.Egress.OriginalDst`
    # documents why an ambiguous read is refused rather than guessed at.
    assert :ok = Acceptor.handle_connection(accepted, state())

    assert {:error, :closed} = :gen_tcp.recv(client, 0, 500),
           """
           The acceptor left a connection open whose destination it could not
           establish. From inside the sandbox that is an indefinite hang rather
           than a refusal, which the conformance probe scores as a timeout -- and
           any path where a fault results in more reachability than a success is
           the one bug direction this subsystem cannot tolerate.
           """
  end

  test "the refusal is a closed socket, never a protocol-level rejection", %{
    accepted: accepted,
    client: client
  } do
    # The sandbox is not aware it is being proxied and has no frame in which to
    # receive a rejection, so from inside a denied destination must behave like
    # an unreachable one (`FR-011a`). Bytes sent back here would be interpreted
    # as the destination's own response.
    :ok = Acceptor.handle_connection(accepted, state())

    assert {:error, :closed} = :gen_tcp.recv(client, 0, 500)
  end

  test "init/1 without a listener still carries the namespace it would bind" do
    # `/proc/<holder-pid>/ns/net`, not a name under `/var/run/netns`: the
    # sandbox's namespace is created by `pasta` and never registered with
    # `ip netns`, so a name for it does not exist.
    assert state().netns == "/proc/1/ns/net"
  end
end
