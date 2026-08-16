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
        {:ok, %{sandbox | mechanism_ref: Atom.to_string(launched.node)}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def start(%Sandbox{} = sandbox) do
    case lookup(sandbox.id) do
      {:ok, launched} ->
        case NodeLauncher.probe(launched.node) do
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
        case NodeLauncher.probe(launched.node) do
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

  defp probe_timeout do
    :ex_sandbox
    |> Application.get_env(:beam, [])
    |> Keyword.get(:probe_timeout_ms, 5_000)
  end
end
