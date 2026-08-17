defmodule ExSandbox.Egress.Relay do
  @moduledoc """
  Forwards a **permitted** connection to its destination (005 T060a9,
  `contracts/egress.md`).

  ## Why this is a module and not three lines in the pool

  `ExSandbox.Egress.Pool.relay/2` was a placeholder that logged and closed. That
  was the honest shape while the netns did not exist — it denies something the
  policy allows, which fails *closed* and is visible as the "permitted
  destination is reachable" check not passing. It was never a false pass.

  But it made two conformance checks unclosable, and separating the forwarding
  from the socket accept loop is what makes the forwarding testable. Off-Linux
  every connection to the pool dies at `OriginalDst.read/1`, so a test driving
  the listener never reaches this code at all — the same vacuity
  `pool_transport_test.exs` documents for the allowlist. `splice/3` takes two
  ordinary sockets, so its behaviour is reachable on any host.

  ## ⚠️ The bug direction that matters here

  Every other component in this subsystem fails safe when it fails: a broken
  decoder refuses, a missing policy denies, an unsupervised pool denies. The
  relay is the one place where the *natural* bug goes the other way. Code that
  forwards on an error path — a destination that could not be connected, a
  socket in an unexpected state, a `recv` that returned something unhandled —
  is a boundary that stops enforcing exactly when something is wrong with it.

  So: **this module never opens a socket it was not told to open, and never
  continues past an error.** `decide/3` has already permitted this one
  destination; the relay's only job is to carry bytes to it and to stop when
  anything at all goes wrong. There is no retry, no fallback destination, and
  no path where a failure results in more reachability than a success.

  ## Both halves, and why the pair is torn down together

  A half-duplex relay forwards the request and drops the response, which from
  inside the sandbox reads as a slow destination rather than a broken proxy —
  and passes every denial check. Both directions are carried, and either side
  closing tears down both, because a socket left open to a destination that is
  gone is a descriptor leak whose only symptom is the pool failing to accept
  long after and nowhere near the cause.
  """

  require Logger

  @typedoc "Where a permitted connection is headed."
  @type destination :: {:inet.ip4_address(), :inet.port_number()}

  # Bounded rather than `:infinity`: a destination that accepts the connection
  # and then never speaks would otherwise pin one process and two descriptors
  # per connection for the lifetime of the node.
  @connect_timeout_ms 5_000
  @idle_timeout_ms 120_000

  @doc """
  Connects to `destination` and carries bytes both ways until either side ends.

  Returns `:ok` once the pair is torn down, and `{:error, reason}` if the
  destination could not be reached — in which case `sandbox_socket` is closed
  before returning, so the sandbox sees a refusal rather than a hang.

  ⚠️ `sandbox_socket` is closed on **every** path out of this function. From
  inside the sandbox a closed socket is what a denied or unreachable
  destination looks like (`FR-011a`), and leaving it open on an error path
  turns a refusal into an indefinite hang that the conformance probe scores as
  a timeout rather than a refusal.
  """
  @spec splice(:gen_tcp.socket(), destination(), keyword()) :: :ok | {:error, term()}
  def splice(sandbox_socket, {address, port}, opts \\ []) do
    connect_timeout = Keyword.get(opts, :connect_timeout_ms, @connect_timeout_ms)

    case :gen_tcp.connect(address, port, [:binary, active: false], connect_timeout) do
      {:ok, destination_socket} ->
        pump(sandbox_socket, destination_socket, Keyword.get(opts, :idle_timeout_ms, @idle_timeout_ms))

      {:error, reason} ->
        # ⚠️ Closed, not left open. `decide/3` permitted this destination, so
        # this is not a policy denial -- but the sandbox must still see a
        # closed socket rather than a hang. Logged at `warning` for the same
        # reason denials are: at `debug` it is filtered out by every config
        # this project ships, and a permitted destination that cannot be
        # reached is precisely the event an operator needs to see.
        Logger.warning(
          "egress: permitted destination #{:inet.ntoa(address)}:#{port} unreachable (#{inspect(reason)})"
        )

        :gen_tcp.close(sandbox_socket)
        {:error, reason}
    end
  end

  # Both directions are driven by two processes over blocking `recv`, rather
  # than one process over `active: :once` messages.
  #
  # ⚠️ The `active` version is shorter and was written first. It is wrong here
  # in a way that is easy to miss: with both sockets active, a fast destination
  # and a slow sandbox fill this process's mailbox without bound -- the sandbox
  # controls neither end's rate, but it does control when it reads, so it can
  # make the pool buffer indefinitely on its behalf. Blocking `recv` gives
  # back-pressure by construction, which is the same reason the pool's own
  # listener does not use `active: true`.
  defp pump(sandbox_socket, destination_socket, idle_timeout) do
    parent = self()

    outbound = spawn_link(fn -> copy(sandbox_socket, destination_socket, idle_timeout, parent) end)
    inbound = spawn_link(fn -> copy(destination_socket, sandbox_socket, idle_timeout, parent) end)

    # Either direction ending ends the connection. Waiting for *both* would hold
    # the pair open while one side is already gone, which is the descriptor leak
    # described in the moduledoc.
    receive do
      {:copy_done, _which} -> :ok
    after
      idle_timeout -> :ok
    end

    Process.unlink(outbound)
    Process.unlink(inbound)
    Process.exit(outbound, :kill)
    Process.exit(inbound, :kill)

    :gen_tcp.close(sandbox_socket)
    :gen_tcp.close(destination_socket)

    :ok
  end

  # ⚠️ No catch-all that continues. Every non-`{:ok, data}` outcome -- a closed
  # socket, a timeout, an unexpected error -- ends this direction and therefore
  # the connection. A `_ -> copy(...)` clause here would keep a connection alive
  # through errors nobody enumerated, which is the "forwards on an error path"
  # shape the moduledoc rules out.
  defp copy(from, to, idle_timeout, parent) do
    case :gen_tcp.recv(from, 0, idle_timeout) do
      {:ok, data} ->
        case :gen_tcp.send(to, data) do
          :ok -> copy(from, to, idle_timeout, parent)
          {:error, reason} -> send(parent, {:copy_done, reason})
        end

      {:error, reason} ->
        send(parent, {:copy_done, reason})
    end
  end
end
