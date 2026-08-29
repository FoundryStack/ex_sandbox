defmodule ExSandbox.Egress.Acceptor do
  @moduledoc """
  The listener that lives inside one sandbox's network namespace
  (005 T060a1/T060a3, `contracts/egress.md`).

  ## Why this exists, and what it replaced

  Egress.Pool -- the module now called `ExSandbox.Egress.Decision`, back when it
  still held a socket -- bound `127.0.0.1` in the **host** namespace and was
  designed as one pool for every sandbox — `013-FR-014c` argued for blast
  radius, not process count, and a process per sandbox is the heaviest way to
  get it.

  That design cannot work, and the reason is not a bug to fix. An `nft`
  `redirect` is DNAT **to the local machine as the namespace sees it**, so it
  can only ever reach a socket in that namespace. Measured: with the pool
  listening on the host and the redirect installed in the sandbox's namespace,
  the tenant's connect returned OK and the pool never saw the connection.

  The one alternative that preserved a single pool — `dnat` to the gateway —
  was measured and **does not work**: `pasta` is a userspace stack that
  terminates and re-originates connections, so the pool reads
  `ORIGINAL_DST=127.0.0.1:<pool port>`, its own address, and would judge every
  connection against that. See `egress-path-measurements.md` option (b).

  So the acceptor moves to where the redirect lands. The blast-radius argument
  survives in substance — no acceptor holds a platform credential, and no
  sandbox has a route to any other — but the shape it justified does not.

  ## Why this is no longer a separate OS process (2026-08-29)

  It used to be. The reasoning was that the BEAM runs in the host namespace, a
  socket it opens is a host socket, and no option to `:gen_tcp.listen/2` changes
  which namespace a socket belongs to. The first two are true. The third is
  true and irrelevant, which is the part that was missed for a year.

  `setns(2)` with `CLONE_NEWNET` affects only the calling **thread**. So the
  socket can be created in the sandbox's namespace on a thread of its own and
  the descriptor handed back, and `:gen_tcp.listen/2` will adopt it with
  `{:fd, Fd}`. The socket never moves; it was never here. Measured:

      listener adopted from the namespace fd   {:ok, {{0, 0, 0, 0}, 9200}}
      connect from the HOST namespace          {:error, :econnrefused}
      connect from INSIDE the namespace        received its bytes
      SO_ORIGINAL_DST on the accepted socket   readable

  The `econnrefused` is the load-bearing half: that port does not exist here.

  ⚠️ The namespace is named by `/proc/<holder-pid>/ns/net`, and `holder_pid` is
  the **namespace holder**, never `pasta`'s own pid. See `ExSandbox.Egress.Pasta`:
  the pidfile records pasta's host-side process, and entering that one puts the
  listener in the *host* namespace, where it would bind a host port and see none
  of the sandbox's traffic. That hazard is unchanged by dropping the helper --
  only the mechanism that consumes the pid changed, from `nsenter -t` to a path
  under `/proc`.

  ## What dropping the helper deleted

  The helper could not be asked a question in-process, so everything it needed
  had to become a protocol: an `AF_UNIX` verdict socket with its own wire
  format, a second one for DNS with its own framing, the sandbox's identity
  passed on `argv`, a readiness line parsed off stdout, and the discipline that
  any failure to *obtain* a verdict is a refusal because the platform might be
  unreachable. None of that was incidental complexity -- all of it was the cost
  of the process boundary. `decide/3` is now an ordinary function call, so the
  boundary and its protocols are gone rather than simplified.

  ## What is enforced here, and what is not

  Nothing. The decision is `ExSandbox.Egress.Decision.decide/3`'s, unchanged and
  shared, so there is exactly one implementation of "may this sandbox reach
  this destination" and moving the listener did not fork it.

  ⚠️ The identity is different, though, and the difference is load-bearing.
  The host pool attributed a connection by `peername` masked to a `/30`,
  because every sandbox reached the same socket and they had to be told apart.
  This acceptor serves **one** namespace: nothing else can reach it, so the
  sandbox's identity is the acceptor's own existence rather than anything read
  off the connection. `source_key` is supplied at start and is not derived from
  the peer — a per-namespace listener that trusted `peername` would be reading
  a value the tenant partly controls in order to answer a question it has
  already answered by connecting at all.
  """

  use GenServer

  require Logger

  alias ExSandbox.Egress.NetnsSocket
  alias ExSandbox.Egress.OriginalDst
  alias ExSandbox.Egress.Policy
  alias ExSandbox.Egress.Relay
  alias ExSandbox.Egress.Resolver

  @typedoc "How to reach the namespace this acceptor serves."
  @type spec :: %{
          source_key: Policy.source_key(),
          holder_pid: pos_integer(),
          port: :inet.port_number()
        }

  @doc false
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name))
  end

  @impl true
  def init(opts) do
    source_key = Keyword.fetch!(opts, :source_key)
    holder_pid = Keyword.fetch!(opts, :holder_pid)
    port = Keyword.fetch!(opts, :port)

    state = %{
      source_key: source_key,
      holder_pid: holder_pid,
      port: port,
      netns: netns_path(holder_pid),
      listener: nil,
      resolver: Keyword.get(opts, :resolver),
      registry: Keyword.get(opts, :registry, ExSandbox.Egress.Registry),

      # ⚠️ Fixed here, and deliberately **not** read from `opts`. A host able to
      # substitute the destination reader could name any destination it liked
      # and have the policy checked against that instead of against the kernel's
      # record, which is exactly the forgeable claim `OriginalDst` exists to
      # prevent. `start_link/1` cannot carry one.
      #
      # It is a field rather than a hardcoded call because the tests that drive
      # `handle_connection/2` and `accept_loop/1` overwrite it on the state map
      # they were handed -- see `acceptor_relay_wiring_test.exs`. That is a
      # rewrite of a local map inside the test process, not an interface, and it
      # is the only way this path is reachable off Linux: on macOS
      # `OriginalDst.read/1` returns `{:error, :unavailable}` for every
      # connection, so the permit branch below never executes.
      destination_reader: &OriginalDst.read/1
    }

    # ⚠️ `listen: false` exists for the tests that assert on this module's
    # arithmetic and its decision delegation, which are host-agnostic and must
    # run on macOS where there is no namespace to enter. It is NOT a
    # configuration option and no consumer sets it: an acceptor that came up
    # without a listener in production would be a supervised process reporting
    # healthy while nothing at all was bound, which is the exact shape of
    # every defect this subsystem has found.
    if Keyword.get(opts, :listen, true) do
      open_listener(state)
    else
      {:ok, state}
    end
  end

  defp open_listener(state) do
    case NetnsSocket.listen(state.netns, state.port) do
      {:ok, fd} ->
        adopt(fd, state)

      # ⚠️ Stopped, not degraded. There is deliberately no path here that binds
      # the host namespace instead: that listener would come up, be supervised,
      # accept nothing, and leave the sandbox's traffic going wherever the
      # redirect sends it. A refusal to start propagates to the launch, which is
      # where an operator can see it and act on it.
      {:error, :unsupported} ->
        {:stop, {:listen_failed, :netns_sockets_unavailable}}

      {:error, stage, errno} ->
        {:stop, {:listen_failed, {stage, errno}}}
    end
  end

  defp adopt(fd, state) do
    # The port argument is ignored when `{:fd, _}` is given -- the bind already
    # happened inside the namespace. `active: false` for the same reason the
    # relay uses blocking `recv`: the sandbox controls when it reads, so
    # anything else lets it make this node buffer on its behalf without bound.
    case :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}, {:fd, fd}]) do
      {:ok, listener} ->
        {:ok, %{state | listener: listener}, {:continue, :accept}}

      {:error, reason} ->
        {:stop, {:listen_failed, {:adopt, reason}}}
    end
  end

  # `/proc/<pid>/ns/net` rather than a name under `/var/run/netns`: the sandbox's
  # namespace is created by `pasta` and never registered with `ip netns`, so a
  # name for it does not exist. The `/proc` path needs no bookkeeping and
  # disappears with the holder, which is the correct lifetime.
  defp netns_path(holder_pid), do: "/proc/#{holder_pid}/ns/net"

  @impl true
  def handle_continue(:accept, state) do
    Task.start_link(fn -> accept_loop(state) end)
    start_resolver_leg(state)
    {:noreply, state}
  end

  # The DNS leg. `nil` is a sandbox launched without a resolver, which is a
  # sandbox that cannot resolve names -- deliberate, and not a degradation of
  # this one.
  defp start_resolver_leg(%{resolver: nil}), do: :ok

  defp start_resolver_leg(%{resolver: {_address, port}} = state) do
    # ⚠️ A failure here does NOT stop the acceptor, and the asymmetry with the
    # TCP listener is deliberate. No TCP listener means the tenant's traffic
    # goes wherever the redirect sends it, unpoliced -- that must refuse the
    # launch. No resolver means names do not resolve, which the tenant sees
    # immediately as a failure of its own request. One is a silent hole in the
    # boundary; the other is a loud missing feature.
    case NetnsSocket.udp(state.netns, port) do
      {:ok, fd} ->
        case :gen_udp.open(0, [:binary, {:active, false}, {:fd, fd}]) do
          {:ok, socket} ->
            Task.start_link(fn -> resolver_loop(socket, state) end)
            :ok

          {:error, reason} ->
            Logger.error(
              "egress acceptor could not adopt the resolver socket: #{inspect(reason)}"
            )
        end

      other ->
        Logger.error("egress acceptor could not bind the resolver socket: #{inspect(other)}")
    end
  end

  defp resolver_loop(socket, state) do
    case :gen_udp.recv(socket, 0) do
      {:ok, {address, port, query}} ->
        # ⚠️ An ordinary call to the running resolver. This used to be a
        # length-prefixed frame
        # over an `AF_UNIX` socket carrying `"<source-key>\n" <> query`, because
        # the acceptor was a different process and could not simply ask. The
        # frame, its parser, and the rule that any framing error is silence all
        # existed to bridge a boundary that no longer exists.
        #
        # ⚠️ Silence, not an error reply, on every failure. That is what the
        # frame protocol did too, and for a reason that survives: a resolver
        # that answers "denied" tells the tenant its query was *seen*, which is
        # a channel. A dropped datagram is what an unreachable resolver looks
        # like.
        case Resolver.answer_via(query, state.source_key) do
          {:ok, reply} -> :gen_udp.send(socket, address, port, reply)
          _ -> :ok
        end

        resolver_loop(socket, state)

      {:error, :closed} ->
        :ok

      {:error, reason} ->
        Logger.warning("egress acceptor resolver recv failed: #{inspect(reason)}")
        resolver_loop(socket, state)
    end
  end

  @doc false
  # Public only so `acceptor_transport_test.exs` can drive the loop over an
  # ordinary loopback listener it put into the state map. There is no consumer:
  # `handle_continue/2` above is its production caller, and the state it is
  # handed there came from `init/1`.
  #
  # ⚠️ The property this exposure exists to keep testable is the third clause: a
  # refusal must not end the loop. An acceptor that died on its first refusal
  # would deny everything afterwards -- a boundary that holds by being broken,
  # which passes every denial check in the conformance suite while making the
  # sandbox useless.
  @spec accept_loop(map()) :: :ok
  def accept_loop(state) do
    case :gen_tcp.accept(state.listener) do
      {:ok, socket} ->
        # One process per connection, unlinked from the accept loop: a
        # connection that dies must not take the listener with it, and the
        # listener must be back in `accept/1` before the relay finishes.
        #
        # ⚠️ The handler WAITS to be told it owns the socket, and the handshake
        # is load-bearing rather than ceremony. `:gen_tcp.recv/3` on a passive
        # socket is refused for any process that is not the controlling one, so
        # without the wait `handle_connection/2` races
        # `controlling_process/2`: it reads the destination, decides, connects
        # upstream, and only then reads -- usually losing the race, and
        # occasionally winning it. Winning looks like a permitted destination
        # that closed immediately, which is indistinguishable from a denial from
        # inside the sandbox and leaves no trace beyond one `:einval` deep in
        # the relay.
        #
        # MEASURED: the same ownership mistake in `acceptor_relay_wiring_test`
        # produced exactly that -- the relay tore the pair down before a byte
        # moved, and the permitted destination read as refused. `Pool` never hit
        # it because it transferred ownership to the relay task rather than to
        # the handler.
        {:ok, pid} =
          Task.start(fn ->
            receive do
              :owned -> handle_connection(socket, state)
            after
              # The accept loop is two calls away from sending this. A handler
              # still waiting after five seconds means the loop died between the
              # two, and a socket nobody owns must be closed rather than leaked.
              5_000 -> :gen_tcp.close(socket)
            end
          end)

        :ok = :gen_tcp.controlling_process(socket, pid)
        send(pid, :owned)
        accept_loop(state)

      {:error, :closed} ->
        :ok

      {:error, reason} ->
        Logger.warning("egress acceptor accept failed: #{inspect(reason)}")
        accept_loop(state)
    end
  end

  @doc """
  Decides one accepted connection and either relays it or closes it.

  ⚠️ The destination is read from the kernel with `SO_ORIGINAL_DST`, never from
  the client. This is a *transparent* proxy: the sandbox believes it is talking
  to the destination directly, so there is no frame in which it could state one
  -- which is what keeps the claim unforgeable. Any design where the sandbox
  tells the acceptor where it wants to go reintroduces exactly that claim.

  ⚠️ Every non-permit outcome closes the socket, including the ones that are not
  policy decisions -- an undecodable destination, an unreadable option. Those
  are host or kernel faults rather than denials, and they are deliberately
  treated the same way at the socket. A fault that let the connection through
  would be an enforcement point that stops enforcing precisely when something is
  wrong with it. The reason is logged so an operator can tell a denial from a
  malfunction; that distinction is lost in the *logs*, never in the *outcome*.
  """
  @spec handle_connection(:gen_tcp.socket(), map()) :: :ok
  def handle_connection(socket, state) do
    with {:ok, destination} <- state.destination_reader.(socket),
         :permitted <- verdict(state, destination, state.registry) do
      Relay.splice(socket, destination, netns: state.netns)
      :ok
    else
      other ->
        log_refusal(other)
        :gen_tcp.close(socket)
    end
  end

  # ⚠️ `warning`, not `debug`, and the level is load-bearing rather than a
  # matter of taste. A policy denial is this subsystem's central security event
  # -- the moment a tenant was stopped from reaching somewhere. At `debug` it is
  # filtered out by every configuration this project ships, so the record of an
  # enforcement decision would exist only on a developer machine with a lowered
  # threshold. `info` is no better: `config/test.exs` sets `level: :warning`, so
  # `Logger.info` is dropped before any handler sees it -- measured,
  # `capture_log` returned `""`.
  #
  # ⚠️ The two clauses are the only thing separating "the allowlist said no"
  # from "this host cannot enforce at all". Both close the socket identically,
  # deliberately, so a fault cannot let traffic through; the distinction is lost
  # in the *outcome* and must therefore survive in the *logs*, which is what
  # T060a5 requires reach the census.
  defp log_refusal({:refused, reason}),
    do: Logger.warning("egress: refused (#{inspect(reason)})")

  # ⚠️ No catch-all clause, deliberately. `handle_connection/2`'s `else` is
  # reachable only by `{:refused, _}` from `verdict/3` or `{:error, _}` from the
  # destination read -- the compiler proves it, and rejected a defensive third
  # clause as unreachable. Leaving one in would tell a later reader that some
  # other outcome is possible here, and the next person to add an outcome would
  # trust it to catch them rather than being forced, by a compile error, to
  # decide what the new outcome means.
  defp log_refusal({:error, reason}),
    do: Logger.warning("egress: could not establish a destination (#{inspect(reason)})")

  @impl true
  def terminate(_reason, %{listener: listener}) when not is_nil(listener) do
    :gen_tcp.close(listener)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  @doc """
  What the shared decision says about a connection from this sandbox.

  Delegates to `ExSandbox.Egress.Decision.decide/3` with the `source_key` this
  acceptor was started for — see the moduledoc on why the key is supplied
  rather than read from the peer.

  ⚠️ Returns the tagged verdict rather than a boolean because
  `handle_connection/2` has to log *why* it refused, and `false` cannot say
  whether the allowlist denied the destination or the sandbox has no registered
  policy at all. `permits?/3` below is this function with the tag discarded, so
  there is one implementation and the two cannot drift.
  """
  @spec verdict(spec(), {String.t(), :inet.port_number()}, GenServer.server()) ::
          ExSandbox.Egress.Decision.decision()
  def verdict(%{source_key: source_key}, destination, registry) do
    ExSandbox.Egress.Decision.decide(sandbox_address(source_key), destination, registry)
  end

  @doc """
  Whether a connection from this acceptor's sandbox may reach `destination`.
  """
  @spec permits?(spec(), {String.t(), :inet.port_number()}, GenServer.server()) :: boolean()
  def permits?(state, destination, registry),
    do: verdict(state, destination, registry) == :permitted

  @doc """
  The acceptor's own /30, expressed as an address `Policy.source_key/1` masks
  back to that /30 — so the shared decision function is reached with the
  identity this acceptor was started for.

  Public because `ExSandbox.Egress.Binding` derives the same address, and two
  copies of this arithmetic would be two things that must agree forever. The
  symptom of them drifting is a sandbox judged against a *neighbouring*
  sandbox's allowlist — a cross-tenant policy error with no local sign of being
  wrong.
  """
  @spec sandbox_address(Policy.source_key()) :: :inet.ip4_address()
  def sandbox_address({a, b, c, d}), do: {a, b, c, d + 2}
end
