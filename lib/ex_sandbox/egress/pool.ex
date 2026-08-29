defmodule ExSandbox.Egress.Pool do
  @moduledoc """
  The single implementation of "may this sandbox reach this destination"
  (005 T060a1/T060a3, `contracts/egress.md`).

  ## ⚠️ There is no pool here any more (2026-08-29)

  There was. This module supervised a listener on `127.0.0.1` in the **host**
  namespace, one for every sandbox, and `013-FR-014c`'s blast-radius argument is
  what justified sharing it — a process per sandbox is the heaviest way to get
  blast radius, and this pool held no platform credential.

  That design cannot work, and the reason is not a bug that was fixed. An `nft`
  `redirect` is DNAT **to the local machine as the redirecting namespace sees
  it**, so it can only ever reach a socket in that namespace. Measured: with this
  pool listening on the host and the redirect installed in the sandbox's
  namespace, the tenant's connect returned OK and the pool never saw the
  connection. `ExSandbox.Egress.Acceptor` is where the traffic lands, one per
  namespace, since `setns(2)` made a namespace-local socket possible from this
  BEAM.

  The listener stayed here for ten days after it stopped being reachable, and the
  moduledoc it carried said so — including the condition for removing it: *"If
  this comment outlives the tests that justify it, the listener should go."* It
  did, in the worst way available. `pool_relay_wiring_test.exs` and
  `pool_transport_test.exs` were the tests that justified it, and by the end they
  were driving **this** copy of the accept-decide-relay path while the acceptor's
  copy — the one every tenant connection actually reaches — had two tests.
  Correct tests over dead code, which is the same defect species as the
  unsupervised pool (`3a4f5eb`) and the unreferenced `Binding` (`8af4e76`) with
  the polarity reversed. Both files now stand over the acceptor.

  Deleted with the listener: `init/1`'s `:gen_tcp.listen`, `handle_continue/2`,
  `accept_loop/3`, `port/1`, `handle_connection/3`, `relay/2`,
  `source_address/1`, and the entry in `ExSandbox.Application`'s supervision
  tree. This module is no longer a process.

  ## What is left, and why it is shared

  `decide/3`. Every acceptor calls it, so there is exactly one implementation of
  the allowlist question and moving the listener into the namespaces did not fork
  it. It used to be reached over an `AF_UNIX` socket via `ExSandbox.Egress.Verdict`,
  because the acceptor was a separate OS process; both are gone and the call is
  ordinary.

  ## How a connection is attributed

  ⚠️ **Not by `peername` any more, and the change is load-bearing.** The host
  pool masked the peer address to a `/30` because every sandbox reached the same
  socket and they had to be told apart. An acceptor serves **one** namespace:
  nothing else can reach it, so the sandbox's identity is the acceptor's own
  existence. `ExSandbox.Egress.Acceptor.verdict/3` supplies the key it was
  started with and reconstructs the address this function masks.

  `ExSandbox.Egress.Policy` is where the masking and the matching live, and why
  a source key cannot be forged.

  ## Refusal is a closed socket, not an error message

  A refused connection is closed. It is not answered with a protocol-level
  rejection, because the sandbox is not aware it is being proxied and has no
  frame in which to receive one. From inside, a denied destination behaves like
  an unreachable one — which is what `FR-011a` describes. The socket handling is
  `ExSandbox.Egress.Acceptor.handle_connection/2`'s; this module returns a
  verdict and touches no socket.
  """

  alias ExSandbox.Egress.Policy
  alias ExSandbox.Egress.Registry

  @typedoc "What was decided about one connection attempt."
  @type decision :: :permitted | {:refused, :not_permitted} | {:refused, :unknown_source}

  @doc """
  Decides whether a connection from `source` to `destination` may proceed.

  Split out from the socket handling so the decision is testable without a
  network: `003`'s conformance suite establishes the boundary by *attempting*
  connections, but a unit test of the decision itself should not need a
  listener to state what the rule is.
  """
  @spec decide(:inet.ip4_address(), {String.t(), :inet.port_number()}, GenServer.server()) ::
          decision()
  def decide(source, destination, registry \\ Registry) do
    key = Policy.source_key(source)

    case Registry.lookup(key, registry) do
      [] ->
        # ⚠️ Distinguished from `:not_permitted` for diagnosis only -- both
        # refuse. An unknown source is a sandbox whose policy was never
        # registered or was already released, and treating that as "no
        # restrictions" is the failure mode `Registry.lookup/2` returning `[]`
        # exists to prevent.
        {:refused, :unknown_source}

      allowed ->
        # ⚠️ The resolutions are fetched **for this source key**, not for the
        # connection and not globally. `029-FR-012` matches a hostname entry
        # against what *this* sandbox resolved that name to; a table shared
        # across sandboxes would let one tenant's answer decide another
        # tenant's verdict, which is the cross-tenant shape
        # `ExSandbox.Egress.Registry`'s moduledoc already guards in the
        # allowlist itself.
        if Policy.permits?(allowed, destination, Registry.resolutions(key, registry)) do
          :permitted
        else
          {:refused, :not_permitted}
        end
    end
  end
end
