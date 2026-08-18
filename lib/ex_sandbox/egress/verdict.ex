defmodule ExSandbox.Egress.Verdict do
  @moduledoc """
  Answers "may this sandbox reach this destination?" for the per-namespace
  acceptors (005 T060a1, `contracts/egress.md`).

  ## Why the acceptor asks instead of knowing

  `ExSandbox.Egress.Acceptor` runs **inside** a sandbox's network namespace,
  which is where an `nft` `redirect` can land and the only place it can. Handing
  that process a copy of the allowlist would work, pass every conformance check,
  and put the policy one process away from the tenant — inside the blast radius
  the acceptor exists to bound.

  So the acceptor holds no policy. It reads `SO_ORIGINAL_DST`, asks here, and
  relays or refuses. `ExSandbox.Egress.Pool.decide/3` remains the single
  implementation of the rule, so moving the listener did not fork the decision.

  ## Why AF_UNIX

  A network namespace isolates the network stack, not the filesystem. Measured
  in the isolation image under unprivileged `docker run`: a socket bound on a
  host path is reachable from inside the sandbox netns, while the tenant —
  confined by `bwrap` to the runtime and its own storage — cannot see the path
  at all. Its connect fails `ENOENT`, not `EACCES`: for the tenant the socket
  does not exist rather than existing and being denied.

  That is what makes `FR-011b` structural here. There is no file to edit and no
  socket to reach, because neither is bound into the sandbox's mount view.

  ## ⚠️ Every failure is a refusal

  A verdict that cannot be produced is `DENY`. An unparseable request, an
  unknown source, a destination that does not resolve to a checkable pair — all
  refuse. The alternative reading, "allow when the check could not run", makes a
  malfunctioning platform indistinguishable from a permissive allowlist, and it
  is the one bug in this subsystem that widens the boundary instead of
  narrowing it.
  """

  use GenServer

  require Logger

  alias ExSandbox.Egress.Acceptor
  alias ExSandbox.Egress.Pool

  @default_path "/var/run/axonn-egress-verdict.sock"

  @doc """
  Where the verdict socket lives.

  ⚠️ Deliberately **not** under a sandbox's storage or any path
  `Hardening.Linux` binds into a tenant's mount view. The isolation of this
  socket is the isolation of the whole policy — a path a tenant can see is a
  control surface, and `FR-011b` requires there to be none.

  Configurable because the default is only writable on a deployment host, and
  a developer machine that cannot bind it would otherwise be unable to start
  the application at all.
  """
  @spec default_path() :: String.t()
  def default_path do
    :ex_sandbox
    |> Application.get_env(:egress, [])
    |> Keyword.get(:verdict_socket_path, @default_path)
  end

  @doc false
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl true
  def init(opts) do
    path = Keyword.get(opts, :path, default_path())
    registry = Keyword.get(opts, :registry, ExSandbox.Egress.Registry)

    # A stale socket file from a previous run makes `bind` fail with `:eaddrinuse`,
    # which reads as "another node is running" rather than "the last one died".
    _ = File.rm(path)
    _ = File.mkdir_p(Path.dirname(path))

    listen_opts = [
      :binary,
      ifaddr: {:local, path},
      active: false,
      reuseaddr: true,
      packet: :line
    ]

    case :gen_tcp.listen(0, listen_opts) do
      {:ok, listener} ->
        :ok = permit_acceptor(path)
        {:ok, %{listener: listener, path: path, registry: registry}, {:continue, :accept}}

      {:error, reason} ->
        # ⚠️ Refuse to start rather than run without a verdict channel. A
        # running platform with no verdict server would leave every acceptor
        # unable to obtain a verdict -- which fails closed, correctly, but
        # silently converts every sandbox's egress into blanket denial: the
        # exact state T060 exists to end, wearing the appearance of success.
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
  def handle_call(:path, _from, state), do: {:reply, state.path, state}

  # ⚠️ **The acceptor is NOT root, and without this every verdict fails.**
  #
  # `nsacceptor.py` runs inside the sandbox's namespace, which under the split
  # launch ordering (T060a4e) is entered *after* `setpriv` -- so it runs as the
  # sandbox uid. The BEAM binds this socket as root, and a unix socket inherits
  # mode `0755` from the process umask, which denies `connect(2)` to every other
  # uid.
  #
  # `ask_platform/4` treats any failure to obtain a verdict as a refusal, which
  # is correct and is what makes this so quiet: every destination is denied,
  # **every denial check passes**, and the only symptom is the permitted
  # destination being unreachable. Measured (`docker/verdict-socket-probe.py`):
  #
  #     mode 0755, uid 0  -> sandbox uid: PermissionError [Errno 13]
  #     mode 0666         -> sandbox uid: GOT:PERMIT
  #
  # ⚠️ **Why widening the mode is safe here, and where the isolation actually
  # comes from.** It is *not* the file mode -- it is the path. The socket lives
  # under `/var/run`, outside anything `bwrap` binds into the sandbox, so tenant
  # code cannot see it at all no matter what its mode says. The processes this
  # opens it to are ones already running on the host, which is where the
  # acceptor is. A tenant that could reach this path would already have escaped
  # the mount namespace, and at that point the mode is not what is protecting
  # anything.
  #
  # ⚠️ And reaching it grants nothing on its own: the protocol answers a
  # question, it does not take an instruction. A caller can ask whether a source
  # key may reach a destination; it cannot *widen* an allowlist, which is
  # `FR-011b` and is enforced by `Registry` holding the only copy.
  defp permit_acceptor(path) do
    case File.chmod(path, 0o666) do
      :ok ->
        :ok

      {:error, reason} ->
        # Refused rather than tolerated. Continuing would start a verdict server
        # no acceptor can reach, converting every sandbox's egress into blanket
        # denial while the platform reports itself healthy.
        raise "egress: could not make the verdict socket reachable by the " <>
                "acceptor at #{path}: #{inspect(reason)}"
    end
  end

  @doc "The path this verdict server is bound to."
  @spec path(GenServer.server()) :: String.t()
  def path(server \\ __MODULE__), do: GenServer.call(server, :path)

  defp accept_loop(listener, parent, registry) do
    case :gen_tcp.accept(listener) do
      {:ok, socket} ->
        Task.start(fn -> serve(socket, registry) end)
        accept_loop(listener, parent, registry)

      {:error, :closed} ->
        :ok

      {:error, reason} ->
        Logger.warning("egress verdict: accept failed (#{inspect(reason)})")
        :ok
    end
  end

  @doc """
  Answers one request on an open socket, then closes it.

  Public so the protocol is testable without a namespace, a redirect, or a
  tenant — every part of this that can be checked off Linux is checked off
  Linux, because the parts that cannot are already the expensive ones.
  """
  @spec serve(:gen_tcp.socket(), GenServer.server()) :: :ok
  def serve(socket, registry) do
    reply =
      case :gen_tcp.recv(socket, 0, 5_000) do
        {:ok, line} -> answer(line, registry)
        {:error, _reason} -> "DENY"
      end

    # ⚠️ The newline is not cosmetic. Both ends frame with `packet: :line`, so a
    # reply without a terminator is never delivered as a line: the caller blocks
    # until the socket closes and reads `{:error, :closed}`. The acceptor treats
    # any unreadable verdict as DENY, so the symptom would have been every
    # destination silently refused -- blanket denial wearing the appearance of a
    # working allowlist, which is the exact state T060 exists to end.
    _ = :gen_tcp.send(socket, reply <> "\n")
    :gen_tcp.close(socket)
  end

  @doc """
  The verdict for one request line, as the wire carries it.

  The request is `"<source-key> <host> <port>"`; the reply is `PERMIT` or
  `DENY`. ⚠️ Anything that does not parse into exactly that shape is `DENY` —
  a malformed request is not a reason to widen a boundary.
  """
  @spec answer(binary(), GenServer.server()) :: binary()
  def answer(line, registry \\ ExSandbox.Egress.Registry) do
    with [key_text, host, port_text] <- line |> String.trim() |> String.split(" ", parts: 3),
         {port, ""} <- Integer.parse(port_text),
         {:ok, source} <- parse_source(key_text) do
      case Pool.decide(source, {host, port}, registry) do
        :permitted ->
          "PERMIT"

        refusal ->
          # Logged at the acceptor's boundary rather than silently, because a
          # sandbox that cannot reach a destination it expects to reach is the
          # hardest thing in this subsystem to diagnose from inside.
          Logger.info("egress verdict: refused #{host}:#{port} (#{inspect(refusal)})")
          "DENY"
      end
    else
      _ -> "DENY"
    end
  end

  # The acceptor names its sandbox by the /30 it was started for. The address is
  # reconstructed so `Pool.decide/3` is reached with the identity the acceptor
  # was provisioned with -- never with one read off the connection, which is a
  # value the tenant partly controls.
  defp parse_source(key_text) do
    case String.split(key_text, ".") do
      [_, _, _, _] = octets ->
        parsed = Enum.map(octets, &Integer.parse/1)

        if Enum.all?(parsed, &match?({n, ""} when n >= 0 and n <= 255, &1)) do
          [a, b, c, d] = Enum.map(parsed, fn {n, ""} -> n end)
          {:ok, Acceptor.sandbox_address({a, b, c, d})}
        else
          :error
        end

      _ ->
        :error
    end
  end
end
