defmodule ExSandbox.Proxy do
  @moduledoc """
  Forwards a request to a running sandbox's address (012 T041, contracts/boundary.md).

  ## What this is not

  It is not an HTTP client, and it does not know what a "request" is. `FR-001`
  forbids `ex_sandbox` any dependency, which rules out Finch, Mint, Req, and
  Plug alike — so this library cannot ship the forwarding itself.

  What it can own, and what a host would otherwise reimplement per mechanism, is
  **deciding where a request goes and whether it may go at all**. That decision
  has three failure modes worth centralising:

    * forwarding to a sandbox that is not running,
    * forwarding to a stale address, and
    * treating "we could not tell" as "go ahead".

  So `target/2` resolves an address and refuses on anything but a positive
  answer. The host performs the transport with whatever client it already has.

  ## Address resolution is the mechanism's, not this library's

  A mechanism knows where its sandboxes listen; nothing else does. A BEAM
  sandbox is a node name, a container is an IP and port, and a future mechanism
  may be a unix socket. The mechanism puts the address in the sandbox's
  `context` under `:address`, and this module only decides whether to hand it
  back.

  ## No caching, ever (`006` R7)

  `target/2` re-resolves on every call. `006` R7 is explicit that a stale
  hostname→sandbox route is a **cross-tenant data breach** rather than a
  correctness bug — requests for one tenant's address reaching another tenant's
  sandbox — and that caching this particular lookup is the optimisation someone
  adds later without recognising what its failure mode is.

  There is no cache here and no option to add one. If profiling ever shows the
  resolution is a bottleneck, the admissible fix is a cache invalidated in the
  same transaction as the state change, which is a host concern with access to
  the transaction — not something this library can do correctly.
  """

  alias ExSandbox.Sandbox

  @typedoc """
  Where a running sandbox can be reached.

  Deliberately loose: a `{host, port}` for a container, a node name for a BEAM
  sandbox, a path for a unix socket. This library stores and returns it without
  interpretation (`FR-007`).
  """
  @type address :: term()

  @typedoc "Why a forward was refused. Each is distinguishable (`006` R4)."
  @type refusal ::
          {:not_running, ExSandbox.Mechanism.status()}
          | :no_address
          | {:status_unknown, term()}

  @doc """
  Resolves where to forward a request for `sandbox`, or refuses.

  Refuses on **every** outcome but a positive one — `006` R4's decision table
  applied here. The row that matters is the last: a mechanism that cannot report
  status refuses rather than forwarding, because "we could not tell" arriving at
  a live sandbox is how a request reaches the wrong tenant.

      case ExSandbox.Proxy.target(MyMechanism, sandbox) do
        {:ok, address} -> MyClient.forward(address, conn)
        {:error, reason} -> refuse(conn, reason)
      end
  """
  @spec target(module(), Sandbox.t()) :: {:ok, address()} | {:error, refusal()}
  def target(mechanism, %Sandbox{} = sandbox) do
    case ExSandbox.status(mechanism, sandbox) do
      {:ok, :running} -> resolve_address(sandbox)
      {:ok, status} -> {:error, {:not_running, status}}
      {:error, reason} -> {:error, {:status_unknown, reason}}
    end
  end

  @doc """
  The address a mechanism recorded for this sandbox, without a status check.

  Public because a mechanism's own start path needs it before the sandbox is
  observably running. **Not** a substitute for `target/2` on a request path: it
  answers "where would this be" rather than "may this be reached now".
  """
  @spec address(Sandbox.t()) :: {:ok, address()} | {:error, :no_address}
  def address(%Sandbox{} = sandbox), do: resolve_address(sandbox)

  defp resolve_address(%Sandbox{context: %{address: address}}) when not is_nil(address) do
    {:ok, address}
  end

  defp resolve_address(%Sandbox{}), do: {:error, :no_address}
end
