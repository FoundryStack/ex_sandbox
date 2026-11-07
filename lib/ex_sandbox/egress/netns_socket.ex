defmodule ExSandbox.Egress.NetnsSocket do
  @moduledoc """
  Sockets created inside a sandbox's network namespace and owned by this BEAM.

  ## The constraint this removes

  An `nft` `redirect` is DNAT to the local machine *as the redirecting namespace
  sees it*, so it can only ever land on a socket in that namespace. The BEAM runs
  in the host namespace and no option to `:gen_tcp.listen/2` changes a socket's
  namespace. That is the whole reason this project ran a separate helper process
  entered via `nsenter`, and the reason Egress.Pool's own listener
  was dead code: it bound the host namespace, and nothing redirected there.

  `setns(2)` with `CLONE_NEWNET` affects only the calling *thread*. So the
  descriptor can cross the boundary even though the process cannot: enter the
  namespace on a dedicated thread, create the socket there, hand back the fd,
  and adopt it with `{:fd, Fd}`. See `c_src/netns_nif.c` for why each job gets a
  thread of its own and why running one on a scheduler would be a defect.

  ## What this is not

  It is not an enforcement point and it holds no policy. It returns descriptors.
  `ExSandbox.Egress.Decision.decide/3` remains the single implementation of "may
  this sandbox reach this destination".

  ## ⚠️ Absence is refusal, not a fallback

  The NIF is built only on Linux, and only when a C compiler was present. When
  it is missing every function here returns `{:error, :unsupported}` and the
  caller must refuse. There is deliberately no host-namespace fallback: a
  listener that binds the host instead is precisely the silent no-op this module
  exists to replace, and it would read as a working enforcement point while
  enforcing nothing.

  ## ⚠️ A descriptor lives exactly as long as its port

  `:gen_tcp` and `:gen_udp` treat a socket adopted with `{:fd, fd}` as borrowed:
  closing it, a refused connect, a peer's EOF and the owner's exit, `:kill`
  included, all release the port and leave the descriptor open. `:erlang.ports/0`
  stays flat while the process runs out of descriptors, and the kernel socket
  stays up with no FIN sent. So every descriptor here is adopted through
  `adopt/3`, whose keeper closes it when the port goes down by any of those
  routes. Cleanup in the owner would miss the one where the owner is killed.
  """

  @typedoc "Path to a network namespace, e.g. `/var/run/netns/sandbox-7`."
  @type netns :: String.t()

  @typedoc """
  Why a descriptor could not be produced. The atom names the syscall that
  refused, so `:setns` (namespace gone, or no `CAP_SYS_ADMIN`) is distinguishable
  from `:setsockopt_mark` (no `CAP_NET_ADMIN`); the integer is `errno`.
  """
  @type failure :: {:error, atom(), integer()} | {:error, :unsupported}

  @on_load :load_nif

  @loaded_key {__MODULE__, :loaded}

  @doc false
  def load_nif do
    path = Path.join(:code.priv_dir(:ex_sandbox), ~c"netns_nif")
    result = :erlang.load_nif(path, 0)
    :persistent_term.put(@loaded_key, result == :ok)

    # ⚠️ Always `:ok`, even when the NIF is absent. `@on_load` returning
    # anything else makes the module permanently unloadable, which would turn
    # "not Linux" and "no C compiler at build time" into a crash at startup for
    # hosts that never touch egress at all -- `Mechanism.Docker` on macOS, for
    # one. The refusal belongs where the capability is actually wanted, so it is
    # recorded here and enforced in `listen/2` and `socket/2`.
    :ok
  end

  @doc """
  Whether namespace-local sockets are possible on this host.

  Recorded at load time rather than probed by calling, and read rather than
  derived from `:os.type/0`: a Linux host whose build had no C compiler is
  indistinguishable from macOS from here, and both must refuse.
  """
  @spec available?() :: boolean()
  def available?, do: :persistent_term.get(@loaded_key, false)

  @doc """
  A listening socket bound to `port` on `INADDR_ANY` inside `netns`.

  Bound to all addresses rather than loopback because the redirect rewrites the
  destination to the namespace's own primary address; measured, a connection
  arrived from `172.19.0.4`, so a loopback listener is never reached.

  Adopt the descriptor with `:gen_tcp.listen(0, [..., {:fd, fd}])`. The port
  argument to `:gen_tcp.listen/2` is ignored when `{:fd, _}` is given -- the
  bind already happened here.
  """
  @spec listen(netns(), :inet.port_number()) :: {:ok, non_neg_integer()} | failure()
  def listen(netns, port) when is_binary(netns) and is_integer(port) do
    if available?(), do: netns_listen(netns, port), else: {:error, :unsupported}
  end

  @doc """
  A bound UDP socket inside `netns`, for the DNS leg.

  Bound to `INADDR_ANY` on `port` for the same measured reason `listen/2` is:
  the redirect DNATs the tenant's port 53 traffic to the resolver's
  address:port, which is not loopback. Adopt with
  `:gen_udp.open(0, [..., {:fd, fd}])`.
  """
  @spec udp(netns(), :inet.port_number()) :: {:ok, non_neg_integer()} | failure()
  def udp(netns, port) when is_binary(netns) and is_integer(port) do
    if available?(), do: netns_udp(netns, port), else: {:error, :unsupported}
  end

  @doc """
  An unconnected socket inside `netns`, carrying `SO_MARK` set to `mark`.

  ⚠️ **The mark is written, read back, and compared inside the NIF before the
  descriptor is returned**, because setting it from Elixir fails open: with
  `CAP_NET_ADMIN` dropped, `:inet.setopts/2` reports `:ok` while the kernel
  refused and the option reads back as zero. The symptom of a lost mark is a
  *permitted* destination timing out, which every denial-focused check scores as
  green. There is no return path from the NIF that yields an unmarked socket.

  Adopt with `:gen_tcp.connect(address, port, [..., {:fd, fd}], timeout)`, which
  connects through the given descriptor and therefore out of `netns`.
  """
  @spec socket(netns(), non_neg_integer()) :: {:ok, non_neg_integer()} | failure()
  def socket(netns, mark) when is_binary(netns) and is_integer(mark) do
    if available?(), do: netns_socket(netns, mark), else: {:error, :unsupported}
  end

  @doc """
  Opens a descriptor with `open`, adopts it with `adopt`, and hands the socket
  to the caller.

  `open` is one of `listen/2`, `socket/2` or `udp/2` behind a closure, and
  `adopt` is the `module` call that takes the descriptor, such as
  `&:gen_tcp.connect(address, port, [{:fd, &1}], timeout)`. Both run in a keeper
  process, which owns the descriptor from the moment it exists and closes it
  once the socket's port goes down. The caller owns the port and closes it the
  ordinary way. A failed adoption returns `{:error, {:adopt, reason}}` with the
  descriptor already closed.
  """
  @spec adopt(
          (-> {:ok, non_neg_integer()} | failure()),
          :gen_tcp | :gen_udp,
          (non_neg_integer() -> {:ok, socket} | {:error, term()})
        ) :: {:ok, socket} | failure() | {:error, {:adopt, term()}}
        when socket: :gen_tcp.socket() | :gen_udp.socket()
  def adopt(open, module, adopt), do: adopt(open, module, adopt, &netns_close/1)

  @doc false
  # `release` is a parameter so `adopted_descriptor_test.exs` can run the keeper
  # where the NIF does not load.
  def adopt(open, module, adopt, release) do
    caller = self()
    reply = make_ref()

    {_keeper, keeper_down} =
      spawn_monitor(fn -> keep(caller, reply, open, module, adopt, release) end)

    receive do
      {^reply, result} ->
        Process.demonitor(keeper_down, [:flush])
        result

      {:DOWN, ^keeper_down, :process, _keeper, reason} ->
        exit(reason)
    end
  end

  # ⚠️ The keeper adopts, and the caller only receives a socket that is already
  # watched. Adopting in the caller and handing the keeper the descriptor after
  # would leave a window, as long as a connect's timeout, in which killing the
  # caller leaks it. The keeper is unlinked, so a kill does not reach it.
  #
  # The release waits for the port's `DOWN`, not the caller's, so it never runs
  # while the port could still be using the descriptor. Nothing else closes
  # one, so `release` runs exactly once, on one of two routes: the port going
  # down, or an adoption that never made a port.
  defp keep(caller, reply, open, module, adopt, release) do
    case open.() do
      {:ok, fd} -> keep_open(fd, adopt.(fd), caller, reply, module, release)
      failure -> send(caller, {reply, failure})
    end
  end

  defp keep_open(fd, {:ok, socket}, caller, reply, module, release) do
    port_down = :erlang.monitor(:port, socket)

    # Fails only when the caller is already gone, and then this process still
    # owns the port and closes it.
    case module.controlling_process(socket, caller) do
      :ok ->
        send(caller, {reply, {:ok, socket}})

      {:error, reason} ->
        module.close(socket)
        send(caller, {reply, {:error, {:adopt, reason}}})
    end

    receive do
      {:DOWN, ^port_down, :port, _socket, _reason} -> release.(fd)
    end
  end

  defp keep_open(fd, {:error, reason}, caller, reply, _module, release) do
    release.(fd)
    send(caller, {reply, {:error, {:adopt, reason}}})
  end

  # The NIF entry points. `ERL_NIF_INIT` replaces both at load time; these
  # bodies run only if something called them with the NIF absent, which
  # `listen/2` and `socket/2` prevent. They raise rather than return a value so
  # the compiler infers `no_return` and does not narrow every caller's type to
  # the stub's -- and so a bypass is loud instead of silently refusing.
  @doc false
  def netns_listen(_netns, _port), do: :erlang.nif_error(:netns_nif_not_loaded)

  @doc false
  def netns_socket(_netns, _mark), do: :erlang.nif_error(:netns_nif_not_loaded)

  @doc false
  def netns_udp(_netns, _port), do: :erlang.nif_error(:netns_nif_not_loaded)

  @doc false
  def netns_close(_fd), do: :erlang.nif_error(:netns_nif_not_loaded)
end
