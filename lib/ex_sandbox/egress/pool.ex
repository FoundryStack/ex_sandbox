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
  defp handle_connection(socket, registry) do
    with {:ok, source} <- source_address(socket),
         {:ok, destination} <- OriginalDst.read(socket),
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

  # ⚠️ Relaying is not yet implemented, and this is the honest placeholder for
  # it rather than a silent success. `decide/3` has already permitted the
  # connection, so closing here denies something the policy allows -- a
  # false *negative*, which fails closed and is visible as the "permitted
  # destination is reachable" check not passing. It is not a false pass.
  #
  # Wiring the outbound half needs the netns and redirect rules T060a3 installs;
  # until those exist there is nothing to relay from.
  defp relay(socket, destination) do
    Logger.debug("egress: permitted #{inspect(destination)}, relay not yet wired")
    :gen_tcp.close(socket)
  end

  defp log_refusal({:refused, reason}),
    do: Logger.debug("egress: refused (#{inspect(reason)})")

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
