defmodule ExSandbox.Mechanism.Beam do
  @moduledoc """
  Runs a tenant's Elixir application on its own hardened OS-level BEAM node
  (005 T027).

  ## What makes this an isolation boundary

  Not the BEAM. A supervised process tree inside the platform's VM would give a
  tenant its own supervision, its own registry, and its own name — and none of
  `FR-001` through `FR-011`. It would share the platform's atom table (never
  garbage collected, so `FR-006` would be unachievable), its memory, its
  process list, its cluster, and its environment; and `:erlang.halt/0` in tenant
  code would take the platform down with it.

  The boundary is the **operating system**: a separate OS process, launched
  under `ExSandbox.Hardening`'s confinement wrapper, addressed over distribution
  with a per-sandbox cookie. `ExSandbox.Mechanism.Beam.NodeLauncher` holds that
  launch; this module is the `ExSandbox.Mechanism` face of it.

  ## Failures map into `003`'s closed set

  Every error returned here is one of `003`'s five `failure_reason` atoms, with
  the mechanism's own words carried separately in the detail. That closure is
  what lets a host route on cause without knowing which mechanism answered
  (`012-FR-008`) — and it is why `probe/1`'s `:unresponsive` becomes `:timeout`
  rather than a sixth atom that only this mechanism could produce.
  """

  @behaviour ExSandbox.Mechanism

  alias ExSandbox.Mechanism.Beam.NodeLauncher
  alias ExSandbox.Sandbox

  @registry __MODULE__.Registry

  @impl true
  def required_capabilities do
    # What the launch actually needs, rather than the union of everything the
    # hardening module can do: a caller checking capabilities before
    # provisioning should learn the real prerequisites.
    [:process_isolation, :filesystem_isolation, :memory_limit, :cpu_limit]
  end

  @impl true
  def provision(%Sandbox{} = sandbox) do
    # Provision launches the node. `003` allows a mechanism to defer work to
    # `start/1`, but deferring here would mean reporting `:provisioned` for a
    # sandbox whose host may be unable to confine it -- and `R9` requires that
    # refusal to surface before anything believes the sandbox exists.
    case NodeLauncher.launch(sandbox) do
      {:ok, launched} ->
        store(sandbox.id, launched)

        # Announced rather than written: `012-FR-001` forbids this library from
        # referencing a host module, so a host that tracks placements attaches a
        # handler and one that does not pays nothing. `cookie_ref` rather than
        # the cookie -- see `ExSandbox.Telemetry.sandbox_placed/3`.
        ExSandbox.Telemetry.sandbox_placed(__MODULE__, sandbox, %{
          gateway_id: gateway_id(),
          # `nil` for an undistributed sandbox, which is the ordinary case.
          node_name: launched[:node] && Atom.to_string(launched.node),
          cookie_ref: cookie_ref(sandbox),
          os_pid: launched[:os_pid]
        })

        # The sandbox's **id**, not its node name. Two reasons, and the second
        # is a bug this fixes:
        #
        #   1. A sandbox has no node name to speak of -- it boots undistributed
        #      (`:nonode@nohost`), because distribution cannot start without a
        #      network and a sandbox has none. See `NodeLauncher.start_peer/2`.
        #   2. `list_running/0` has always returned ids. With `mechanism_ref`
        #      set to a node name, reconciliation compared node names against a
        #      list of ids, so a running sandbox never appeared in it -- every
        #      one looked like an orphan to be reclaimed.
        {:ok, %{sandbox | mechanism_ref: sandbox.id}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def start(%Sandbox{} = sandbox) do
    case lookup(sandbox.id) do
      {:ok, launched} ->
        case NodeLauncher.probe(launched.peer) do
          :ok -> {:ok, sandbox}
          {:error, reason} -> {:error, translate(reason)}
        end

      :error ->
        # Starting a sandbox this mechanism never launched is not a transient
        # fault -- relaunching here would silently create a second node for an
        # id the caller believes is already placed.
        {:error, :mechanism_error}
    end
  end

  @impl true
  def stop(%Sandbox{} = sandbox) do
    case lookup(sandbox.id) do
      {:ok, launched} ->
        NodeLauncher.terminate(launched.peer)
        forget(sandbox.id)
        {:ok, sandbox}

      # Idempotent, per `003`: a sandbox that is already not running is in the
      # state the caller asked for.
      :error ->
        {:ok, sandbox}
    end
  end

  @impl true
  def destroy(%Sandbox{} = sandbox) do
    case lookup(sandbox.id) do
      {:ok, launched} ->
        NodeLauncher.terminate(launched.peer)
        forget(sandbox.id)
        :ok

      :error ->
        :ok
    end
  end

  @impl true
  def status(%Sandbox{} = sandbox) do
    # Reports what the node *actually* answers rather than what was recorded,
    # which is what makes `003`'s reconciliation possible: a status derived
    # from stored state can never disagree with stored state, so it could never
    # detect drift.
    case lookup(sandbox.id) do
      {:ok, launched} ->
        case NodeLauncher.probe(launched.peer) do
          :ok ->
            {:ok, :running}

          {:error, :down} ->
            # Classified on the way past rather than later: once the OS process
            # is reaped the evidence distinguishing a cap breach from a crash is
            # gone, and `provision_failure_reason/1` would have nothing to read.
            record_exit(sandbox.id, launched)
            {:ok, :absent}

          {:error, :unresponsive} ->
            {:ok, :unknown}
        end

      :error ->
        {:ok, :absent}
    end
  end

  # A cgroup that killed a process for exceeding `memory.max` records it in
  # `memory.events`. Reading the counter is what separates `:resource_cap` from
  # a generic crash -- the exit status alone cannot, because an OOM kill and a
  # `halt(1)` are both just a dead process to the parent.
  defp record_exit(id, launched) do
    reason =
      case oom_kills(launched.os_pid) do
        n when is_integer(n) and n > 0 -> :resource_cap
        _ -> :mechanism_error
      end

    store(id, Map.put(launched, :exit_reason, reason))
  end

  defp oom_kills(os_pid) do
    with {:ok, cgroup} <- File.read("/proc/#{os_pid}/cgroup"),
         [_, path] <- Regex.run(~r{^0::(.+)$}m, cgroup),
         {:ok, events} <- File.read("/sys/fs/cgroup#{path}/memory.events"),
         [_, count] <- Regex.run(~r/^oom_kill (\d+)$/m, events) do
      String.to_integer(count)
    else
      # The process is already reaped, or this host does not expose cgroup v2.
      # Either way the cause is unknown, and guessing `:resource_cap` would be
      # worse than admitting it.
      _ -> nil
    end
  end

  @impl true
  def list_running do
    {:ok, table() |> :ets.tab2list() |> Enum.map(fn {id, _launched} -> id end)}
  end

  @doc """
  Why a sandbox that is no longer running stopped (`FR-009`).

  Deliberately **not** an `ExSandbox.Mechanism` callback. `012`'s behaviour is a
  frozen contract shared by every mechanism, and widening it for one of them
  would oblige every future mechanism to answer a question only this one can.
  A host that wants this asks the Beam mechanism by name.

  The distinction it carries is the one an operator acts on: `:resource_cap`
  means the tenant hit its own limit, `:mechanism_error` means the platform
  broke. Reporting a cap breach as the latter sends someone debugging the
  platform for a tenant's memory leak.
  """
  @spec provision_failure_reason(Sandbox.t()) :: {:error, atom()} | :ok
  def provision_failure_reason(%Sandbox{} = sandbox) do
    case lookup(sandbox.id) do
      {:ok, %{exit_reason: reason}} when not is_nil(reason) -> {:error, reason}
      {:ok, _launched} -> :ok
      :error -> {:error, :mechanism_error}
    end
  end

  @doc """
  The **host's** OS pid for a running sandbox.

  ⚠️ Not what the sandbox reports about itself. Under `--unshare-pid` a sandbox's
  `:os.getpid()` returns its namespace-local pid — `2` — while the host knows it
  by an unrelated number. Anything that reads `/proc/<pid>` on the host and takes
  the sandbox's own answer is inspecting a different process entirely, and will
  happily report on one that is not confined.

  Exposed so that verification does not have to ask the thing being verified: a
  compromised sandbox cannot misreport this.
  """
  @spec host_pid(Sandbox.t()) :: {:ok, pos_integer()} | {:error, term()}
  def host_pid(%Sandbox{} = sandbox) do
    case lookup(sandbox.id) do
      {:ok, %{os_pid: os_pid}} when is_integer(os_pid) -> {:ok, os_pid}
      {:ok, _launched} -> {:error, :no_os_pid}
      :error -> {:error, :unknown_sandbox}
    end
  end

  @doc """
  Evaluates `{module, function, args}` inside a sandbox and returns the result.

  ⚠️ Routed over `:peer`'s **stdio** control channel, never Erlang distribution.
  A sandbox runs under `--unshare-net` and therefore has no network interfaces at
  all, so `:erpc.call/5` raises `{:erpc, :noconnection}` against a perfectly
  healthy sandbox — measured, not inferred. The failure is doubly misleading: it
  is indistinguishable from a crashed node, and it gets *more* likely the better
  the confinement works.

  Like `provision_failure_reason/1`, this is deliberately **not** an
  `ExSandbox.Mechanism` callback: "evaluate this in the sandbox's runtime" is
  meaningful for a BEAM node and meaningless for a mechanism whose tenant is a
  container running arbitrary code.

  Returns `{:error, :unknown_sandbox}` for an id this mechanism never launched
  rather than raising, since a caller racing `destroy/1` is an ordinary outcome.
  """
  @spec call(Sandbox.t(), module(), atom(), [term()], timeout()) ::
          {:ok, term()} | {:error, term()}
  def call(%Sandbox{} = sandbox, module, function, args, timeout \\ 10_000) do
    case lookup(sandbox.id) do
      {:ok, %{peer: peer}} ->
        try do
          {:ok, :peer.call(peer, module, function, args, timeout)}
        catch
          kind, reason -> {:error, {kind, reason}}
        end

      :error ->
        {:error, :unknown_sandbox}
    end
  end

  @doc """
  Evaluates `{module, function, args}` in a sandbox without waiting for a result.

  For work whose *effect* is the point and whose reply will never arrive —
  halting the node being the motivating case. A blocking `call/5` there waits out
  its full timeout on a node that is already gone, turning a fast assertion into
  a slow one and reporting a timeout for an operation that did exactly what was
  asked.

  Same stdio routing, and the same reason, as `call/5`.
  """
  @spec cast(Sandbox.t(), module(), atom(), [term()]) :: :ok | {:error, term()}
  def cast(%Sandbox{} = sandbox, module, function, args) do
    case lookup(sandbox.id) do
      {:ok, %{peer: peer}} ->
        _ = :peer.cast(peer, module, function, args)
        :ok

      :error ->
        {:error, :unknown_sandbox}
    end
  end

  @impl true
  def usage(%Sandbox{} = sandbox) do
    case lookup(sandbox.id) do
      {:ok, launched} ->
        read_usage(launched.node)

      :error ->
        {:error, :mechanism_error}
    end
  end

  defp read_usage(node) do
    memory = :erpc.call(node, :erlang, :memory, [:total], probe_timeout())
    {:ok, %{memory_mb: div(memory, 1024 * 1024)}}
  rescue
    _ -> {:error, :host_unreachable}
  catch
    :exit, {:erpc, :timeout} -> {:error, :timeout}
    :exit, _ -> {:error, :host_unreachable}
  end

  # `:unresponsive` folds into `:timeout` rather than becoming a sixth atom.
  # `003`'s set is closed so hosts can route on cause without knowing the
  # mechanism; a mechanism-specific atom would make that routing incomplete for
  # every host that had not heard of this mechanism.
  defp translate(:unresponsive), do: :timeout
  defp translate(:down), do: :host_unreachable

  # Launched nodes are tracked in ETS rather than in the sandbox struct because
  # `peer` pids do not survive the struct's round trip through the host's
  # registry -- the host stores `mechanism_ref`, a string, and nothing more.
  defp table do
    case :ets.whereis(@registry) do
      :undefined -> :ets.new(@registry, [:named_table, :public, :set])
      tid -> tid
    end
  end

  defp store(id, launched), do: :ets.insert(table(), {id, launched})
  defp forget(id), do: :ets.delete(table(), id)

  defp lookup(id) do
    case :ets.lookup(table(), id) do
      [{^id, launched}] -> {:ok, launched}
      [] -> :error
    end
  end

  # The gateway this mechanism runs on. Configured rather than discovered: a
  # library cannot ask a host's schema which gateway it is, and `012-FR-001`
  # forbids it from trying.
  defp gateway_id do
    :ex_sandbox
    |> Application.get_env(:beam, [])
    |> Keyword.get(:gateway_id)
  end

  # ⚠️ A **reference**, never the cookie. The cookie is defence in depth for
  # `FR-003` and telemetry metadata reaches log aggregators and APM vendors;
  # emitting it there would scatter it across systems chosen for searchability.
  # Derived from the sandbox id so a host can correlate without this library
  # knowing anything about the host's secret store.
  defp cookie_ref(sandbox), do: "sandbox:" <> sandbox.id

  defp probe_timeout do
    :ex_sandbox
    |> Application.get_env(:beam, [])
    |> Keyword.get(:probe_timeout_ms, 5_000)
  end
end
