defmodule ExSandbox.Egress.Pool do
  @moduledoc """
  One acceptor pool for every sandbox, enforcing each one's allowlist
  (005 T060a1/T060a3, `contracts/egress.md`).

  ## Why one pool rather than a process per sandbox

  `013-FR-014c` asks for blast radius, not process count. A process per sandbox
  is the heaviest way to get it: at 500 sandboxes that is 500 supervised OS
  processes doing almost nothing. This pool holds no platform credential, and
  because no sandbox has a route to any other, compromising it yields the union
  of permitted *outbound destinations* rather than a path between tenants —
  `003-FR-002` does not depend on it.

  ## How a connection is attributed

  The sandbox's netns has a default route pointing here, so a connection arrives
  with the sandbox's own source address. `:inet.peername/1` reports what the
  kernel saw, `Policy.source_key/1` masks it to the /30, and that is the
  identity — see `ExSandbox.Egress.Policy` for why it cannot be forged.

  ⚠️ **The intended destination is recovered from the kernel, not from the
  client.** Under transparent enforcement the sandbox believes it is talking to
  the destination directly, so there is no protocol frame in which it could
  state one — which is exactly the property that makes `T060a3` transparent and
  keeps `Principle VI` intact. Any design where the sandbox *tells* the pool
  where it wants to go reintroduces a claim the sandbox controls.

  `ExSandbox.Egress.OriginalDst` reads that record. An earlier note here said
  it was unreachable from `:gen_tcp`; that was wrong, and measuring it is what
  unblocked this transport — see that module for what the measurement showed
  and why every ambiguous read is refused.

  ## Refusal is a closed socket, not an error message

  A refused connection is closed. It is not answered with a protocol-level
  rejection, because the sandbox is not aware it is being proxied and has no
  frame in which to receive one. From inside, a denied destination behaves like
  an unreachable one — which is what `FR-011a` describes.
  """

  use GenServer

  require Logger

  alias ExSandbox.Egress.OriginalDst
  alias ExSandbox.Egress.Policy
  alias ExSandbox.Egress.Registry

  @typedoc "What the pool decided about one connection attempt."
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
        if Policy.permits?(allowed, destination) do
          :permitted
        else
          {:refused, :not_permitted}
        end
    end
  end

  # -- Server ---------------------------------------------------------------

  @doc false
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, 0)
    registry = Keyword.get(opts, :registry, Registry)

    # `{active, once}` gives back-pressure by construction: the pool reads one
    # message at a time per connection rather than letting a fast sandbox fill
    # its mailbox.
    listen_opts = [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}]

    case :gen_tcp.listen(port, listen_opts) do
      {:ok, listener} ->
        {:ok, actual_port} = :inet.port(listener)
        state = %{listener: listener, port: actual_port, registry: registry}
        {:ok, state, {:continue, :accept}}

      {:error, reason} ->
        {:stop, {:listen_failed, reason}}
    end
  end

  @impl true
  def handle_continue(:accept, state) do
    parent = self()
    Task.start_link(fn -> accept_loop(state.listener, parent, state.registry) end)
    {:noreply, state}
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, state.port, state}

  @doc "The port this pool is listening on."
  @spec port(GenServer.server()) :: :inet.port_number()
  def port(server \\ __MODULE__), do: GenServer.call(server, :port)

  defp accept_loop(listener, parent, registry) do
    case :gen_tcp.accept(listener) do
      {:ok, socket} ->
        handle_connection(socket, registry)
        accept_loop(listener, parent, registry)

      {:error, :closed} ->
        :ok

      {:error, reason} ->
        Logger.warning("egress pool accept failed: #{inspect(reason)}")
        accept_loop(listener, parent, registry)
    end
  end

  # A refused connection is closed, never answered. See the moduledoc: the
  # sandbox is not aware it is being proxied and has no frame in which to
  # receive a rejection, so from inside a denied destination behaves like an
  # unreachable one -- which is what `FR-011a` describes.
  # ⚠️ `destination_reader` exists **only** so this path is reachable in a test,
  # and its default is the real reader. The reason it is needed is measured, not
  # hypothetical: on macOS `OriginalDst.read/1` returns `{:error, :unavailable}`
  # for every connection, so the `:permitted` branch below never executes and
  # `relay/2` is dead code there. Deleting the relay call entirely left all 306
  # host tests green -- the same defect species as the unsupervised pool and the
  # unreferenced `Binding`, found the same way, by sabotage rather than review.
  #
  # ⚠️ It is a **test seam, not a configuration option**. It is not read from
  # application config and no consumer can set it: a host able to substitute the
  # destination reader could name any destination it liked and have the policy
  # checked against that instead of the kernel's record, which is exactly the
  # forgeable claim `OriginalDst` exists to prevent. The pool's public
  # `start_link/1` does not accept it.
  @doc false
  # Public only so `pool_relay_wiring_test.exs` can drive the permit-and-relay
  # path with a stub reader. Not part of the interface (`FR-014`), and no
  # consumer calls it -- the accept loop above is its only production caller.
  def handle_connection(socket, registry, destination_reader \\ &OriginalDst.read/1) do
    with {:ok, source} <- source_address(socket),
         {:ok, destination} <- destination_reader.(socket),
         :permitted <- decide(source, destination, registry) do
      relay(socket, destination)
    else
      other ->
        # ⚠️ **Every non-permit path lands here, including the ones that are not
        # policy decisions at all** -- an unreadable peername, a destination
        # that could not be decoded. Those are host or kernel faults rather
        # than denials, and they are deliberately treated the same way at the
        # socket: closed.
        #
        # T060a5's rule, applied to a single connection: fail toward refusal,
        # never toward pass. A fault that let the connection through would be
        # an enforcement point that stops enforcing precisely when something is
        # wrong with it. The reason is logged so the census and an operator can
        # tell a denial from a malfunction, which is the distinction that must
        # not be lost -- but it is lost in the *logs*, not in the *outcome*.
        log_refusal(other)
        :gen_tcp.close(socket)
    end
  end

  defp source_address(socket) do
    case :inet.peername(socket) do
      {:ok, {address, _port}} -> {:ok, address}
      {:error, reason} -> {:error, {:no_peername, reason}}
    end
  end

  # ⚠️ This was a placeholder that logged and closed until T060a9. The
  # placeholder was honest -- `decide/3` had already permitted the connection,
  # so closing denied something the policy allows, a false *negative* that
  # fails closed and shows up as the "permitted destination is reachable" check
  # not passing. It was never a false pass.
  #
  # ⚠️ The note it carried said wiring the outbound half "needs the netns and
  # redirect rules T060a3 installs". That was wrong, and the wrongness cost a
  # cycle: T060a3b landed the netns and the check did not move. The relay never
  # depended on the redirect -- it needs two sockets and a destination, both of
  # which it is handed. Measured by the census declining to improve after the
  # supposed blocker was removed.
  #
  # Runs in its own process: `splice/3` blocks until the connection ends, and
  # calling it inline would stop this pool accepting anything else for the
  # lifetime of one tenant connection -- a denial-of-service any sandbox could
  # trigger by opening a connection and never closing it.
  defp relay(socket, destination) do
    {:ok, pid} = Task.start(fn -> ExSandbox.Egress.Relay.splice(socket, destination) end)

    # The relay process must own the socket, or it is closed when this
    # accept-loop iteration moves on. Same ownership rule that cost three
    # apparent relay failures in `relay_test.exs` -- see `client_pair/0` there.
    case :gen_tcp.controlling_process(socket, pid) do
      :ok ->
        :ok

      {:error, reason} ->
        # Fail closed: if ownership could not be transferred the relay cannot
        # work, and a socket left open would hang the sandbox rather than
        # refusing it.
        Logger.warning("egress: could not hand off a permitted connection (#{inspect(reason)})")
        :gen_tcp.close(socket)
    end
  end

  # ⚠️ `warning`, not `debug`, and the level is load-bearing rather than a
  # matter of taste.
  #
  # A policy denial is this pool's central security event -- the moment a tenant
  # was stopped from reaching somewhere. At `debug` it is filtered out by every
  # configuration this project ships, so the record of an enforcement decision
  # existed only on a developer machine with a lowered threshold.
  #
  # How it surfaced, and why it could only surface there: on macOS
  # `OriginalDst.read/1` fails, so the `{:error, _}` clause below runs at
  # `warning` and the transport test's log assertion passed. In the isolation
  # container the destination reads fine, the `{:refused, _}` clause runs
  # instead, and the same assertion failed. The one host where the denial path
  # actually executes is the one where its log disappeared.
  #
  # Why the container reaches this clause at all, measured rather than assumed:
  # the transport test connects to the pool directly, with no netns and no
  # redirect anywhere in the picture. On Linux a plain loopback socket still
  # answers `SO_ORIGINAL_DST` -- measured in the isolation image,
  # `{:ok, {{127,0,0,1}, 36039}}`, the socket's own local address. So the
  # destination read *succeeds*, `decide/3` runs, finds no policy for that /30,
  # and lands here as `{:refused, :unknown_source}`. On macOS the same read
  # fails and the `{:error, _}` clause below runs instead. Same test, same
  # assertion, two different branches -- which is why this could only be seen
  # by running the container.
  #
  # ⚠️ The first fix was `info`, and it was wrong for a reason worth keeping:
  # `config/test.exs` sets `level: :warning`, so `Logger.info` is dropped before
  # any handler sees it. Measured -- `capture_log` returned `""`. That fix reads
  # as an obvious improvement over `debug` and would have left the container
  # failure exactly as it was, with a commit message claiming otherwise.
  defp log_refusal({:refused, reason}),
    do: Logger.warning("egress: refused (#{inspect(reason)})")

  # ⚠️ No catch-all clause, deliberately. `handle_connection/2`'s `else` can be
  # reached only by `{:refused, _}` from `decide/3` or `{:error, _}` from the
  # peername and destination reads -- the compiler proves it, and rejected a
  # defensive third clause as unreachable.
  #
  # Leaving one in would have been worse than redundant: a dead clause tells a
  # later reader that some other outcome is possible here, and the next person
  # to add an outcome would trust it to catch them rather than being forced,
  # by a compile error, to decide what the new outcome means.
  defp log_refusal({:error, reason}),
    do: Logger.warning("egress: could not establish a destination (#{inspect(reason)})")
end
