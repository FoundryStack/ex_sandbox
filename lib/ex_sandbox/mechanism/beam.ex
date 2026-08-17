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
    #
    # ⚠️ Names from `ExSandbox.Capability.known/0`, not invented ones. These were
    # `:process_isolation`, `:filesystem_isolation`, `:memory_limit`, and
    # `:cpu_limit` -- none of which that module recognises, so every caller that
    # checked them crashed rather than got a report. The conformance suite died
    # with a `FunctionClauseError` instead of reporting host capability
    # unavailable, which is the outcome `FR-012b` requires.
    #
    # The mapping is not lossy: `:resource_limits` covers the memory and CPU
    # caps (both come from the same cgroup scope, and a host with one has the
    # other), `:filesystem_confinement` is the mount namespace,
    # `:privilege_separation` is the dropped uid that makes process isolation
    # mean anything, and `:network_restriction` is the network namespace.
    #
    # ⚠️ `:network_restriction` was missing here for as long as this list has
    # existed (005 T060c), and its absence was not benign. `build_command/2`
    # composes `--unshare-net` unconditionally, so on a host that cannot create
    # a network namespace the launch either fails for an unexplained reason or
    # -- worse -- succeeds without one. `005-SC-002` (cluster isolation) rests
    # entirely on that namespace, so a sandbox launched here without it is
    # reachable by distribution from every other sandbox on the host.
    #
    # Declaring it means `ExSandbox.provision/2` refuses on such a host instead,
    # naming what is missing. That refusal is the guarantee working (Principle
    # II): the host never provided the boundary, it was only never asked.
    [
      :resource_limits,
      :filesystem_confinement,
      :privilege_separation,
      :network_restriction
    ]
  end

  @impl true
  def provision(%Sandbox{} = sandbox) do
    # ⚠️ The template is resolved **before** anything is launched. Without this
    # the mechanism ignored `template_ref` entirely, so a caller who typo'd a
    # template name got a running sandbox built from something they did not
    # choose -- and `provision_failure_reason/1` could never report
    # `:template_missing`, because nothing had ever noticed. Caught by `003`'s
    # conformance suite (`FR-027`), which is exactly what it is for.
    with {:ok, _template} <- resolve_template(sandbox.template_ref) do
      do_provision(sandbox)
    end
  end

  # Templates name the runtime a sandbox launches with (`FR-022`). The registry
  # is configuration rather than a resource: `012-FR-009` keeps Ash resources out
  # of this library, and a host that manages templates in its own schema
  # supplies the list.
  #
  # An empty registry accepts nothing. That is the safe direction -- a mechanism
  # that accepts every name when unconfigured is the fail-open shape this check
  # exists to catch -- but it means a host must configure templates before
  # provisioning succeeds.
  defp resolve_template(template_ref) do
    known =
      :ex_sandbox
      |> Application.get_env(:beam, [])
      |> Keyword.get(:templates, [])

    cond do
      template_ref in known ->
        {:ok, template_ref}

      # A wildcard for hosts that manage template existence themselves and do
      # not want this library second-guessing them. Explicit, so it cannot
      # happen by forgetting to configure anything.
      known == :any ->
        {:ok, template_ref}

      true ->
        {:error, {:template_missing, template_ref}}
    end
  end

  defp do_provision(%Sandbox{} = sandbox) do
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
        {:ok, %{sandbox | mechanism_ref: sandbox.id, context: build_context(sandbox)}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def start(%Sandbox{} = sandbox) do
    case lookup_sandbox(sandbox) do
      # ⚠️ Relaunch is permitted **only** for a row explicitly marked stopped.
      # That marker is the entire safety property here: without it, `start/1` on
      # a live sandbox would launch a second node for an id the caller believes
      # is already placed, and two runtimes for one sandbox is worse than a
      # failed start. A row with no marker is running, and running is what the
      # caller asked for.
      {:ok, %{stopped: true} = stopped} ->
        relaunch(sandbox, stopped)

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
    case lookup_sandbox(sandbox) do
      {:ok, launched} ->
        NodeLauncher.terminate(launched.peer)

        # ⚠️ The row is **retained**, marked stopped, rather than forgotten.
        # `forget/1` here made stop a destroy: `status/1` answered `:absent`,
        # `list_running/0` dropped the id, and `start/1` refused to bring it
        # back -- so `003-FR-012` (stop preserves, start restores) was
        # unreachable, and three `FR-024` checks plus one `FR-015` failed
        # because a stopped sandbox is a *state*, not an absence.
        # ⚠️ Keyed by the row's **own** key, not `sandbox.id`. Since
        # `lookup_sandbox/1` also resolves by `mechanism_ref`, a reconciler can
        # reach this with a struct whose `id` was never stored -- and writing
        # under that id would leave the original row running while creating a
        # second, stopped one for the same sandbox.
        store(registry_key(sandbox), Map.merge(launched, %{stopped: true, peer: nil}))
        {:ok, sandbox}

      # Idempotent, per `003`: a sandbox that is already not running is in the
      # state the caller asked for.
      :error ->
        {:ok, sandbox}
    end
  end

  @impl true
  def destroy(%Sandbox{} = sandbox) do
    case lookup_sandbox(sandbox) do
      {:ok, launched} ->
        # A stopped sandbox has no peer to terminate -- `stop/1` cleared it --
        # but its row must still go. Destroy is the only operation that forgets,
        # which is what keeps `stop` recoverable and `destroy` final.
        if launched[:peer], do: NodeLauncher.terminate(launched.peer)
        # The key the row was found under -- see `stop/1`. Forgetting
        # `sandbox.id` for a ref-resolved struct would terminate the node and
        # leave its row behind, which reconciliation would then see as an orphan
        # forever.
        forget(registry_key(sandbox))
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
    case lookup_sandbox(sandbox) do
      # Reported before probing, because there is nothing to probe: `stop/1`
      # cleared the peer. `:stopped` is distinct from `:absent` -- the sandbox
      # exists and can be started again, which is what `FR-024` asks the
      # mechanism to distinguish.
      {:ok, %{stopped: true}} ->
        {:ok, :stopped}

      {:ok, launched} ->
        case NodeLauncher.probe(launched.peer) do
          :ok ->
            {:ok, :running}

          {:error, :down} ->
            # Classified on the way past rather than later: once the OS process
            # is reaped the evidence distinguishing a cap breach from a crash is
            # gone, and `provision_failure_reason/1` would have nothing to read.
            record_exit(registry_key(sandbox), launched)
            {:ok, :absent}

          # ⚠️ Classified here too, for the same reason as `:down`.
          #
          # A sandbox OOM-killed mid-allocation does not always present as
          # `:down`: the peer process can survive its BEAM long enough to be
          # probed, answering nothing, which is `:unresponsive`. Measured on a
          # 128 MB sandbox allocating 2 GB -- status settled at `:unknown` while
          # systemd already held `Result=oom-kill`, and because only the `:down`
          # branch recorded anything, `provision_failure_reason/1` reported `:ok`
          # for a sandbox killed by its own cap.
          #
          # `:unknown` is still the honest status -- the mechanism genuinely
          # cannot say whether the node is coming back -- but the *cause* is
          # legible right now and unrecoverable once the unit is reset, so a cap
          # verdict is recorded on the way past rather than inferred later.
          #
          # ⚠️ Only a **positive** verdict is recorded. Unlike `:down`, an
          # unresponsive sandbox may simply be busy and answer the next probe;
          # writing `:mechanism_error` here would permanently mark a healthy
          # sandbox as failed -- and because a recorded reason takes precedence,
          # nothing would ever correct it.
          {:error, :unresponsive} ->
            if cap_breached?(launched) do
              record_exit(registry_key(sandbox), launched)
            end

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
  # ⚠️ An already-recorded reason **wins**. This runs on every status probe of a
  # dead sandbox, and it infers the cause from systemd's verdict on the scope --
  # which only ever names an OOM kill. A reason recorded by whoever actually did
  # the stopping is strictly better evidence than that inference.
  #
  # Without this precedence, a sandbox terminated for exceeding its **time**
  # budget was immediately relabelled `:mechanism_error` by the next status
  # read: systemd reports no `oom-kill`, quite correctly, because memory was
  # never the reason. A deliberate stop was thereby reported as a platform
  # fault, which is the same ambiguity `record_exit/2` exists to remove, just
  # pointing the other way.
  defp record_exit(_id, %{exit_reason: reason}) when not is_nil(reason), do: :ok

  defp record_exit(id, launched) do
    reason =
      if cap_breached?(launched) do
        :resource_cap
      else
        :mechanism_error
      end

    store(id, Map.put(launched, :exit_reason, reason))
  end

  # ⚠️ Reads systemd's own verdict on the scope, not the cgroup (R7e).
  #
  # The cgroup directory is destroyed the instant the sandbox's last process
  # exits, taking `memory.events` with it -- a poll as tight as the runtime
  # allows never once caught it. But the **unit object survives in `failed`
  # state**, and `Result` names the cause exactly, per sandbox, with no delta
  # arithmetic and no cross-tenant pollution.
  #
  # Three earlier readings were all wrong, each measured: deriving the cgroup
  # from `/proc/<pid>/cgroup` at death (the process is gone), reading the
  # sandbox's own `memory.events` (the directory is gone), and a delta on the
  # parent slice (which aggregates every sandbox, so a concurrent breach
  # elsewhere misattributes).
  defp cap_breached?(launched) do
    case scope_result(launched) do
      {:ok, "oom-kill"} -> true
      _ -> false
    end
  end

  # ⚠️ The `LoadState` guard is **load-bearing**, not defensive.
  #
  # A unit that never existed reports `Result=success` -- identical to a clean
  # exit. Reading `Result` alone would therefore report "no cap breach" for a
  # sandbox that never launched, which is the same fail-open shape as an
  # `:undef` that reads like a refused operation. `not-found` must be
  # distinguished from a real verdict rather than defaulting to one.
  defp scope_result(launched) do
    with unit when is_binary(unit) <- Map.get(launched, :scope_unit),
         {output, 0} <-
           System.cmd("systemctl", systemctl_scope_args(unit), stderr_to_stdout: true),
         %{"LoadState" => "loaded", "Result" => result} <- parse_properties(output) do
      {:ok, result}
    else
      _ -> :unknown
    end
  rescue
    _ -> :unknown
  end

  # ⚠️ A **system** query, matching the scope the launcher actually creates.
  #
  # `systemd_run_args/2` passes no `--user`, so the scope is a system unit. This
  # read was `--user` and therefore asked the wrong manager: it returned
  # `LoadState=not-found` with `Result=success` for every sandbox, live or dead.
  #
  # That pairing is the whole reason `scope_result/1` guards on `LoadState`. A
  # missing unit reports `Result=success` -- indistinguishable from a clean exit
  # -- so without the guard this mismatch would have silently reported "no cap
  # breach" for every OOM kill, and the memory cap would have looked enforced on
  # a host where nothing was ever attributed. Measured against a live breach:
  #
  #     systemctl --user show sandbox-<id>.scope   =>  LoadState=not-found
  #                                                    Result=success
  #     systemctl        show sandbox-<id>.scope   =>  LoadState=loaded
  #                                                    Result=oom-kill
  #                                                    ActiveState=failed
  #
  # If the launcher ever moves to `--user`, this must move with it; the guard
  # will turn the disagreement into `:mechanism_error` rather than a false pass,
  # but a cap that cannot be attributed is still a cap that is not demonstrated.
  defp systemctl_scope_args(unit),
    do: ["show", unit, "-p", "LoadState", "-p", "Result"]

  defp parse_properties(output) do
    output
    |> String.split("\n", trim: true)
    |> Map.new(fn line ->
      case String.split(line, "=", parts: 2) do
        [key, value] -> {key, String.trim(value)}
        [key] -> {key, ""}
      end
    end)
  end

  @impl true
  def list_running do
    # ⚠️ **Running**, not "known". A stopped sandbox is recorded but is not
    # running, and including it would make `list_running/0` disagree with
    # `status/1` -- which is precisely the drift `003-FR-015`'s reconciliation
    # check exists to catch, since it enumerates this list and asks `status/1`
    # to confirm each entry.
    ids =
      table()
      |> :ets.tab2list()
      |> Enum.reject(fn {_id, launched} -> launched[:stopped] end)
      |> Enum.map(fn {id, _launched} -> id end)

    {:ok, ids}
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
    case lookup_sandbox(sandbox) do
      {:ok, %{exit_reason: reason}} when not is_nil(reason) -> {:error, reason}
      {:ok, _launched} -> :ok
      :error -> {:error, :mechanism_error}
    end
  end

  # Brings a stopped sandbox back (`003-FR-012`).
  #
  # A **fresh launch**, not a resume: the OS process is gone, so there is nothing
  # to resume. What survives is the sandbox's storage, which is bound by id and
  # therefore reattaches to the new node -- which is exactly what `FR-012` asks
  # for, since "start restores its data" is a claim about the *filesystem*, not
  # about process state.
  #
  # The stopped row is replaced only on success. A failed relaunch leaves the
  # sandbox stopped rather than absent, so a caller can retry instead of
  # discovering the record has vanished under them.
  defp relaunch(%Sandbox{} = sandbox, _stopped) do
    case NodeLauncher.launch(sandbox) do
      {:ok, launched} ->
        store(sandbox.id, launched)
        {:ok, %{sandbox | mechanism_ref: sandbox.id, context: build_context(sandbox)}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # What `003`'s conformance suite needs to interrogate a sandbox (T048a, T048c).
  #
  # ## `exec` — without it, no isolation guarantee is ever *demonstrated*
  #
  # The suite establishes isolation by **attempting** each hostile act inside the
  # sandbox and observing it refused. With no runner it reports `{:no_runner, _}`
  # and attempts nothing — and `FR-012b` is explicit that a guarantee which
  # cannot be attempted is unavailable, never satisfied. Four `FR-006` checks and
  # three resource-limit checks were reporting exactly that.
  #
  # This grants **no new access**: `call/5` already reaches the sandbox over the
  # stdio channel, and this only hands the suite the same door.
  #
  # ## `address` — a handle, not a network address
  #
  # `003-FR-022` asks that a started sandbox carry an address. A `005` sandbox
  # runs undistributed under `--unshare-net` by design, so it has no network
  # address at all — the better the isolation, the less it has one. The suite
  # deliberately does not assert the address's *form* (Principle VI), only that
  # one comes back, so a mechanism-shaped handle conforms.
  #
  # ⚠️ This must never become a reason to start distribution. That would trade
  # `FR-003`'s cluster boundary for a string nobody parses.
  defp build_context(sandbox) do
    %{
      address: "peer:" <> sandbox.id,
      exec: fn command -> exec_in_sandbox(sandbox, command) end
    }
  end

  # ⚠️ `PATH` is set explicitly. The sandbox's environment is built by `env -i`
  # with an ERTS-only allowlist (`FR-004`), so `:os.cmd/1` there inherits no
  # `PATH` and every bare command name fails `:enoent` — which reads exactly like
  # the sandbox refusing the operation. That ambiguity is the failure mode this
  # whole seam exists to avoid, so the runner names the directories rather than
  # hoping.
  defp exec_in_sandbox(sandbox, command) do
    shell = "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin export PATH; " <> command

    case call(sandbox, :os, :cmd, [String.to_charlist(shell)], exec_timeout(sandbox)) do
      {:ok, output} ->
        {:ok, to_string(output)}

      # ⚠️ A timeout is translated rather than passed through. A sandbox killed
      # mid-command — which is precisely what a breached cap looks like — leaves
      # `:peer.call/4` waiting, and reporting that as an unclassified error makes
      # the suite read "stopped" as "could not be demonstrated". The whole point
      # of the resource-limit checks is that a breach was *stopped*.
      #
      # ⚠️ A sandbox that overran its **own** budget is *stopped*, not merely
      # reported slow. Leaving it running would satisfy every inspection of the
      # configuration while the work continued indefinitely — the `005` R9b shape
      # again, where the limiter is invoked with the right number and silently
      # does nothing. Measured before this: a sandbox given `timeout_ms: 2_000`
      # ran a 60s sleep for the full global 15s timeout and was still `:running`.
      {:error, {:exit, {:timeout, _}}} ->
        enforce_time_budget(sandbox)
        {:error, :sandbox_unresponsive}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Stops a sandbox that exceeded a budget **it asked for**, leaving one that
  # merely hit the global ceiling alone.
  #
  # The distinction matters: the global timeout is this library's own guard
  # against waiting forever on a call, and tripping it says nothing about the
  # tenant. A per-sandbox `timeout_ms` is a declared limit on the tenant's work,
  # and a declared limit that does not stop anything is not a limit.
  #
  # ⚠️ The reason is recorded **before** the node is torn down, and the row is
  # kept. `destroy/1` forgets the row, which erases the very verdict
  # `provision_failure_reason/1` exists to report -- a caller would then see the
  # sandbox stopped with no way to learn it was a budget breach rather than a
  # platform fault, which is the ambiguity `record_exit/2` was written to close.
  defp enforce_time_budget(sandbox) do
    with ms when is_integer(ms) <- time_budget(sandbox),
         {:ok, launched} <- lookup_sandbox(sandbox) do
      store(registry_key(sandbox), Map.put(launched, :exit_reason, :resource_cap))
      if launched[:peer], do: NodeLauncher.terminate(launched.peer)
    end

    :ok
  end

  # The sandbox's own budget takes precedence; the configured value is a
  # fallback ceiling, never a cap on what a caller may request.
  defp exec_timeout(sandbox) do
    time_budget(sandbox) || configured_exec_timeout()
  end

  defp time_budget(%Sandbox{context: %{timeout_ms: ms}}) when is_integer(ms) and ms > 0, do: ms
  defp time_budget(_sandbox), do: nil

  defp configured_exec_timeout do
    :ex_sandbox
    |> Application.get_env(:beam, [])
    |> Keyword.get(:exec_timeout_ms, 15_000)
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
        with :ok <- check_funs_loadable(peer, args, timeout) do
          try do
            {:ok, :peer.call(peer, module, function, args, timeout)}
          catch
            kind, reason -> {:error, {kind, reason}}
          end
        end

      :error ->
        {:error, :unknown_sandbox}
    end
  end

  # ⚠️ Refuses a fun the sandbox cannot load, **before** running anything (R7d).
  #
  # Without this the call returns `{:error, {:error, :undef}}`, which is
  # indistinguishable from the sandbox refusing the operation -- and that
  # ambiguity fails toward a *passing* test. Measured: a memory hog shipped as a
  # closure died with `:undef` having allocated nothing, so the sandbox survived
  # and the cap test concluded "the cap is not in force", accusing the mechanism
  # of the exact fail-open defect the suite exists to detect.
  #
  # A fun is loadable iff its **defining module** is loadable on the far side, so
  # the question is asked *there* rather than here.
  #
  # ⚠️ `:erlang.fun_info(f, :type)` is **not** a valid check: `&Enum.sum/1`
  # reports `:external` and still fails when its module is absent. Only
  # `:code.which/1` on the sandbox answers the real question.
  defp check_funs_loadable(peer, args, timeout) do
    args
    |> Enum.filter(&is_function/1)
    |> Enum.reduce_while(:ok, fn fun, :ok ->
      case fun_module_loadable?(peer, fun, timeout) do
        {:ok, true} -> {:cont, :ok}
        {:ok, {false, module}} -> {:halt, {:error, {:fun_not_loadable, module}}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp fun_module_loadable?(peer, fun, timeout) do
    {:module, module} = :erlang.fun_info(fun, :module)

    case :peer.call(peer, :code, :which, [module], timeout) do
      :non_existing -> {:ok, {false, module}}
      _path -> {:ok, true}
    end
  catch
    kind, reason -> {:error, {kind, reason}}
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
    case lookup_sandbox(sandbox) do
      {:ok, _launched} ->
        read_usage(sandbox)

      :error ->
        {:error, :mechanism_error}
    end
  end

  # ⚠️ Over the **peer's stdio channel**, never `:erpc`.
  #
  # This called `:erpc.call(node, ...)` -- the same defect already fixed in
  # `probe/1`, left behind here. A sandbox launched under `--unshare-net` has no
  # network interfaces and never starts distribution, so `:erpc` cannot reach a
  # perfectly healthy node and every call fell into the `:exit` clause as
  # `:host_unreachable`. `FR-026` asks that usage be reported for a running
  # sandbox, and it could not be, for any of them.
  #
  # It surfaced only as flakiness because it fails toward an *error* rather than
  # a false pass -- the safe direction, but the guarantee was still unmet.
  # `:peer.call/5` is the one channel that survives the network namespace.
  defp read_usage(sandbox) do
    case call(sandbox, :erlang, :memory, [:total], probe_timeout()) do
      {:ok, memory} when is_integer(memory) ->
        {:ok, %{memory_mb: div(memory, 1024 * 1024)}}

      {:error, {:exit, {:timeout, _}}} ->
        {:error, :timeout}

      {:error, _reason} ->
        {:error, :host_unreachable}
    end
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

  # The key a sandbox's row is actually stored under. Mirrors
  # `lookup_sandbox/1`'s resolution order, so a write lands on the row the
  # matching read found.
  defp registry_key(%Sandbox{} = sandbox) do
    case lookup(sandbox.id) do
      {:ok, _} -> sandbox.id
      :error -> sandbox.mechanism_ref || sandbox.id
    end
  end

  # ⚠️ Resolves by **`mechanism_ref` as well as `id`**, and the second path is
  # what makes reconciliation implementable (`003-FR-015`).
  #
  # A reconciler examining an unrecorded orphan has **only the ref** this
  # mechanism handed out -- there is no registry row to look an id up in. Keying
  # solely on `sandbox.id` meant a sandbox reconstructed from its own ref missed
  # the table and reported `:absent`, so the reconciler could not confirm what it
  # had found. Terminating on that guess is worse than the leak it fixes.
  #
  # For this mechanism the two are the same string, so the second clause is
  # reached only for a struct built from a ref alone. Both are tried rather than
  # assuming they always agree.
  defp lookup_sandbox(%Sandbox{} = sandbox) do
    with :error <- lookup(sandbox.id) do
      if sandbox.mechanism_ref, do: lookup(sandbox.mechanism_ref), else: :error
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
