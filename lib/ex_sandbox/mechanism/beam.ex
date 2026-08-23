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

  alias ExSandbox.Mechanism.Beam.Exec
  alias ExSandbox.Mechanism.Beam.NodeLauncher
  alias ExSandbox.Sandbox

  @registry __MODULE__.Registry

  # ⚠️ Declared here, with the other module attributes, and that placement is
  # load-bearing. Defined further down beside the function using it, Elixir
  # resolved it to `nil` at the use site -- `:gen_tcp.connect/4` with a `nil`
  # timeout, and a compiler type warning was the only sign.
  #
  # Shorter than the exec timeout: three denied destinations at the exec budget
  # would read as a hang, which is what the shell probe originally did.
  @connect_probe_timeout_ms 3_000

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
      # ⚠️ The wildcard is checked FIRST, and the order is the whole fix.
      #
      # It used to be second, behind `template_ref in known`. With `known` the
      # atom `:any`, `in` reaches `Enumerable.impl_for!/1` and RAISES --
      # `protocol Enumerable not implemented for Atom` -- so the wildcard branch
      # below it was unreachable and every provision crashed before it.
      #
      # `config/config.exs` sets exactly that value for `:dev` and `:prod`
      # (`templates: :any`, with a comment explaining that the host takes on the
      # obligation to reject unknown templates). `config/test.exs` sets a real
      # list, so the whole suite exercised the one shape that worked. MEASURED
      # in the studio container (D33) at the first real `ExSandbox.provision/2`
      # on the configured dev host: a capability map with all five available,
      # and a `Protocol.UndefinedError` from `resolve_template/1`.
      #
      # A wildcard for hosts that manage template existence themselves and do
      # not want this library second-guessing them. Explicit, so it cannot
      # happen by forgetting to configure anything.
      known == :any ->
        {:ok, template_ref}

      template_ref in known ->
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
        {:ok, %{sandbox | mechanism_ref: sandbox.id, context: context_for(sandbox)}}

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

        # ⚠️ After the peer is terminated, and unconditionally. Releasing before
        # the tenant is dead would hand the /30 and its policy to the next
        # sandbox while this one is still running on it -- the reuse crossing
        # `003-FR-002` forbids, arriving through the reclaim path rather than
        # through the allocator.
        #
        # `nil` for a sandbox launched with no allowlist, and for every sandbox
        # on a host with no egress path, so the absence is ordinary rather than
        # exceptional. `Binding.release/2` is itself idempotent (`003-FR-013`),
        # which is what makes a second destroy safe.
        if launched[:binding], do: :ok = ExSandbox.Egress.Binding.release(launched.binding)

        # ⚠️ The acceptor does NOT die with the namespace it serves, and that is
        # measured rather than assumed: after `kill -9` on the namespace holder
        # the acceptor was still alive and `/proc/<acc>/ns/net` still named the
        # same namespace -- so it was keeping a dead netns open. Without this,
        # every destroy leaks one process and one namespace, forever.
        #
        # Idempotent like `Binding.release/2` (`003-FR-013`): killing a pid that
        # is already gone is not an error, and a second destroy must be safe.
        if launched[:acceptor_os_pid], do: NodeLauncher.stop_acceptor(launched.acceptor_os_pid)
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
        {:ok, %{sandbox | mechanism_ref: sandbox.id, context: context_for(sandbox)}}

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
  @doc false
  # Public only so `ExSandbox.Mechanism.BeamContextTest` can pin the propagation
  # contract on a host where the launch path refuses before this is reached.
  # Not part of the mechanism interface -- `@doc false`, and no consumer calls it.
  def context_for(sandbox) do
    # ⚠️ **Merged onto the caller's context, not substituted for it.**
    #
    # This returned a bare map of the three keys below until 005 T060a2 gave a
    # caller something to lose. `ExSandbox.Sandbox` documents `context` as
    # "stored, compared, and propagated -- never parsed"; replacing it propagates
    # nothing. `Axonn.Sandbox.Provision` resolves a tenant's `network_allowlist`
    # before calling `provision/1` -- refusing malformed entries, aborting the
    # provision on an unreadable one -- and passes it here, where it was dropped.
    #
    # Nothing failed. The parse was correct, every test of it passed, and the
    # sandbox came back `:provisioned` enforcing no policy at all. That is the
    # `--unshare-net` shape again: a boundary that permits nothing reads exactly
    # like a correct one under checks that only test denial. Here the policy was
    # not even wrong, it was absent, having been validated and discarded.
    #
    # The mechanism's own keys win the merge deliberately: a host must not be
    # able to supply an `:address` or a `:connect` and have the conformance
    # suite probe something other than this sandbox.
    host_context = if is_map(sandbox.context), do: sandbox.context, else: %{}

    published = %{
      # ⚠️ A string, and deliberately **not** the `{host, port}` tuple the
      # network group pattern-matches on (005 T060a4).
      #
      # `Conformance.Reachability.addressed?/1` accepts any non-empty value and
      # `Conformance.Network.sandbox_address/2` matches only `{host, port}`, so
      # the census reports "carries no `:address`" for a mechanism that does
      # publish one. That mismatch is real, and the obvious fix -- make it a
      # tuple -- is a **false pass**:
      #
      #   1. `sandbox_address/2` matches and returns `{:ok, {"peer", id}}`,
      #   2. the group hands both halves to `connect_from_sandbox/3`,
      #   3. `:gen_tcp.connect(~c"peer", id, ...)` fails to resolve them,
      #   4. the clause returns `:refused`,
      #   5. `:refused` is scored as **the boundary holding**.
      #
      # `003-FR-002` would read as demonstrated against a mechanism that never
      # attempted a crossing.
      #
      # ⚠️ **Corrected (T060a4, 2026-08-18): a real listener does NOT make the
      # tuple honest, and the reasoning above stopped one step short.** It reads
      # as "publish the tuple once the sandbox has a listener", and measurement
      # says otherwise: **pasta assigns every netns the host's own address**.
      # Two sandboxes both come up as `172.17.0.2`, so a connect to that address
      # from sandbox A lands on **A's own listener** while B never accepts
      # (measured twice, `egress-path-measurements.md`).
      #
      # So the tuple would not be a handle naming *this* sandbox from anywhere
      # else, and the peer check's verdict -- either way -- would describe a
      # sandbox talking to itself. `:refused` scored as the boundary holding is
      # the same false pass as before, arriving by a different route.
      #
      # This is not a gap awaiting work. `FR-011c` is satisfied **structurally**:
      # sandbox B's address is not an address sandbox A can name, which is a
      # stronger guarantee than a rule that must stay correct. The check
      # correctly reports the third outcome, because the crossing it wants to
      # attempt is not merely forbidden -- it is unnameable. `BeamContextTest`
      # pins the tuple out.
      address: "peer:" <> sandbox.id,
      exec: fn command -> exec_in_sandbox(sandbox, command) end,
      connect: fn host, port -> connect_from_sandbox(sandbox, host, port) end,
      # ⚠️ A **UDP** probe alongside the TCP one, and its absence is what made
      # `029-FR-013` invisible to the conformance suite (029 T005).
      #
      # The redirect this mechanism installs is `meta l4proto tcp`, so UDP is
      # not policed at all -- but every probe the network group had was
      # `:gen_tcp`, so no check could ever observe that. The suite reported a
      # boundary that a tenant bypasses by choosing a transport.
      #
      # Declared here rather than inferred by the suite for the same reason
      # `connect` is: there is no host-neutral way to send a datagram from
      # inside someone else's network namespace, and a probe that could not run
      # would report "we did not try" as "the boundary held".
      udp_probe: fn host, port -> udp_probe_from_sandbox(sandbox, host, port) end
    }

    host_context
    |> Map.merge(published)
    |> put_permitted()
    |> put_policy_handle(sandbox)
    |> put_gateway(sandbox)
    |> put_resolver(sandbox)
  end

  # ⚠️ Published so the UDP check can tell the ONE destination the policy is
  # meant to permit from every destination it is meant to drop (029 T015,
  # `FR-013`).
  #
  # Without it `attempt_udp_egress/2` probes `127.0.0.1:53` and reads an answer
  # as "the datagram left the namespace unpoliced". Since T015 that address is
  # the sandbox's own resolver, served from *inside* its namespace by
  # `nsacceptor.py`, so the answer means the opposite of what the check says --
  # measured: the leg failed on a sandbox whose egress policy was working.
  #
  # Gated on `binding` for the same reason `put_gateway/2` is: a sandbox with
  # no egress policy has no resolver exemption either, and publishing one would
  # hand the check a control that cannot hold.
  defp put_resolver(context, %Sandbox{} = sandbox) do
    with {:ok, launched} <- lookup(sandbox.id),
         binding when not is_nil(binding) <- launched[:binding],
         {address, port} when is_integer(port) <- ExSandbox.Egress.Resolver.resolver_address() do
      Map.put(context, :resolver, {resolver_literal(address), port})
    else
      _ -> Map.delete(context, :resolver)
    end
  end

  defp resolver_literal(address) when is_tuple(address), do: to_string(:inet.ntoa(address))
  defp resolver_literal(address) when is_binary(address), do: address

  # ⚠️ Published **only for a sandbox that actually has a binding**, on exactly
  # the same reasoning as `put_policy_handle/2` above.
  #
  # `SC-003` names the namespace's gateway as one of the addresses a sandbox
  # must not reach, and the suite cannot guess it -- pasta assigns a /30 per
  # sandbox, so a hardcoded address would belong to nothing and its silence
  # would score as a boundary holding. A sandbox launched under `--unshare-net`
  # has no gateway at all, and the key is absent rather than invented.
  defp put_gateway(context, %Sandbox{} = sandbox) do
    with {:ok, launched} <- lookup(sandbox.id),
         binding when not is_nil(binding) <- launched[:binding] do
      Map.put(context, :gateway, binding.gateway_address)
    else
      _ -> Map.delete(context, :gateway)
    end
  end

  # ⚠️ `:policy_handle` is published **only for a sandbox that actually has a
  # policy**, and that condition is the whole correctness of the check it feeds
  # (005 T060a4, `FR-011b`).
  #
  # `Conformance.Network.attempt_widen_allowlist/2` scores an *absent* handle
  # inside the sandbox as `{:refused, {:policy_not_visible, handle}}` -- the
  # boundary holding. So publishing a path unconditionally would score
  # `FR-011b` as demonstrated for a sandbox launched under `--unshare-net`,
  # which has no egress policy to widen in the first place. The check would be
  # reporting that an unwritable policy is unwritable, having never established
  # that a policy exists. That is the `--unshare-net` false pass in its purest
  # form: the *absence* of a mechanism scoring as the presence of a boundary.
  #
  # Gating on `binding` is what makes it honest -- the row carries one only when
  # `policed/2` installed a real allowlist. Without it the key is absent and the
  # census keeps reporting the third outcome, which is the true state.
  #
  # ⚠️ The handle names the **verdict socket**, not a config file, because that
  # is where the allowlist is actually enforced: `nsacceptor.py` holds no policy
  # and asks `Egress.Verdict` over it for every connection. A tenant that could
  # write there could answer its own questions. Measured in the isolation
  # container against the real bind set (`/usr`, `/lib`, `/bin`, `/sbin`, plus
  # the sandbox's own storage): the path reports ABSENT inside, and WIDENED when
  # deliberately bound in -- so the check discriminates rather than passing
  # because every write fails on an unprivileged host.
  defp put_policy_handle(context, %Sandbox{} = sandbox) do
    with {:ok, launched} <- lookup(sandbox.id),
         true <- not is_nil(launched[:binding]),
         {:ok, path} <- verdict_path() do
      Map.put(context, :policy_handle, path)
    else
      _ -> Map.delete(context, :policy_handle)
    end
  end

  # ⚠️ Asks the **running** server rather than reading config, for the same
  # reason `af82afa` changed the acceptor: config records what the server was
  # asked to bind, and a handle naming a path nothing listens on is a handle
  # that is absent inside the sandbox for the wrong reason. `Verdict.path/1` is
  # a `GenServer.call`, so it is guarded -- `context_for/1` runs on macOS too,
  # where the egress supervision tree may not be up, and a crash there would
  # fail the provision rather than omit a key.
  defp verdict_path do
    {:ok, ExSandbox.Egress.Verdict.path()}
  catch
    :exit, _ -> :error
  end

  # ⚠️ `:permitted` is published **only when the tenant's allowlist names a
  # destination that can actually be dialled**, and its absence is deliberate
  # (005 T060a4, `FR-011a`).
  #
  # The network group probes this destination and expects it to *succeed*. Three
  # ways to get that wrong, all of which report a failure against a mechanism
  # that did nothing wrong:
  #
  #   1. publishing a placeholder when the allowlist is empty -- the probe dials
  #      something that was never permitted and scores its failure as a boundary
  #      that is too tight,
  #   2. publishing an `:any_port` entry verbatim -- it matches the suite's
  #      `{host, port}` pattern, so the check proceeds and hands `:any_port` to
  #      `:gen_tcp.connect/4`, which cannot dial it,
  #   3. publishing the first entry regardless of shape -- same as (2), but only
  #      for allowlists that happen to begin with a wildcard, which is the
  #      version that passes in testing and fails for one tenant in production.
  #
  # When nothing dialable is listed the key is left out, and the group reports
  # `:no_allowlist` -- the third outcome, visible in the census as a gap rather
  # than counted as a demonstrated guarantee.
  #
  # ⚠️ `:permitted` is **derived here or absent**, never taken from the caller.
  # `Map.delete/2` before the derivation is what enforces that, and it closes the
  # same provenance hole 673373b closed for `:address` and `:connect` -- in the
  # one field that fix did not cover.
  #
  # Measured: a host passing `permitted: {"evil.example.com", 443}` alongside an
  # **empty** allowlist had it published verbatim. The network group would dial
  # that destination and score the result as `FR-011a` evidence -- a check
  # reporting on a destination this mechanism never authorized, supplied by the
  # party the check exists to constrain.
  #
  # Found by a surviving sabotage, not by a failing test: reordering the merge
  # so the host could win was invisible, because `published` carries no
  # `:permitted` for the merge to protect.
  defp put_permitted(context) do
    context
    |> Map.get(:network_allowlist, [])
    |> List.wrap()
    |> Enum.find(&dialable?/1)
    |> case do
      nil -> Map.delete(context, :permitted)
      destination -> Map.put(context, :permitted, destination)
    end
  end

  defp dialable?({host, port}) when is_binary(host) and is_integer(port), do: true
  defp dialable?(_), do: false

  # ⚠️ A native connect probe, because the shell one cannot work here (005
  # T060b/T060d).
  #
  # The network conformance group probes a connection from inside the sandbox.
  # Its shell probe needs `nc` or a bash `/dev/tcp`, and the isolation container
  # has neither -- no netcat installed, and Debian's `/bin/sh` is `dash`, which
  # has no `/dev/tcp` builtin. Measured: all three denial checks reported
  # `{:no_probe, _}` and failed as inconclusive, which was the right verdict for
  # the wrong question. A BEAM sandbox opens sockets fine; it just cannot do it
  # through a shell.
  #
  # `:gen_tcp` is OTP, so it is present in the bare `erl` a sandbox runs -- the
  # same constraint that rules out `Node` and every Elixir module here.
  #
  # ⚠️ Three verdicts, not two. `:etimedout` is what a DROP policy looks like
  # from inside, and it must stay distinct from a rejection so the suite does
  # not have to rank REJECT above DROP (`005-FR-011f`).
  # ⚠️ **A completed handshake is NOT evidence the destination was reached, and
  # scoring it as such reported two breaches that never happened.**
  #
  # `Egress.Acceptor` is a *transparent* proxy: the redirect sends every
  # outbound connection to it, so the TCP handshake always completes -- against
  # the acceptor -- whether the destination is permitted or denied. On a
  # refusal the acceptor closes the socket **without answering**, which is the
  # required behaviour (`FR-011a`: a denied destination must be
  # indistinguishable from an unreachable one, and `FR-011f` forbids ranking
  # REJECT above DROP). Measured:
  #
  #     # a listener that accepts and immediately closes -- the refusal path
  #     :gen_tcp.connect(~c"127.0.0.1", port, [], 2000)  #=> {:ok, #Port<0.4>}
  #
  # So the question has to change from "did the handshake complete?" to "did
  # any DATA cross?" A permitted connection is relayed to the real destination
  # and can carry bytes; a refused one is closed having carried none.
  #
  # ⚠️ The old probe was correct for every configuration it had been measured
  # against. Under `--unshare-net` there was no acceptor and no listener, so
  # `connect` genuinely failed and `:connected` genuinely meant reached. It
  # became wrong the moment the boundary started *enforcing* rather than
  # *isolating* -- the permit direction again.
  defp connect_from_sandbox(sandbox, host, port) do
    address = String.to_charlist(host)
    timeout = @connect_probe_timeout_ms

    # ⚠️ **Connect, probe and close happen inside ONE `:peer.call`, and that is
    # not a tidiness preference -- splitting them makes the probe report
    # `:refused` for every destination on earth.**
    #
    # Each `:peer.call` runs in a *fresh process* on the sandbox node, and a
    # `gen_tcp` socket is owned by the process that opened it: when that process
    # exits, the socket is closed. So a connect in one call followed by a recv
    # in the next always sees `{:error, :closed}` -- not because the peer closed
    # anything, but because the owner died between the two calls.
    #
    # Measured against a genuinely reachable, genuinely permitted destination
    # with the boundary working end to end:
    #
    #     connect in call A, recv in call B  -> {:error, :closed}   (WRONG)
    #     connect and recv in ONE call       -> {:error, :timeout}  (reached)
    #
    # A direct connect from the same namespace succeeded at the same moment
    # (`DIRECT-OK`), and the verdict server answered `PERMIT` for the same
    # source key -- so every layer was working and only the probe disagreed.
    case call(sandbox, :erl_eval, :exprs, [probe_exprs(address, port, timeout), []], timeout * 3) do
      {:ok, {:value, verdict, _bindings}} when verdict in [:connected, :refused, :timeout] ->
        verdict

      # The sandbox itself became unreachable, which says nothing about the
      # destination. Reported as neither, so the group's inconclusive clause
      # fails rather than scoring a dead sandbox as a held boundary.
      {:error, reason} ->
        {:sandbox_unreachable, reason}

      other ->
        {:sandbox_unreachable, other}
    end
  end

  # ⚠️ The UDP counterpart, and its verdict vocabulary is deliberately NOT
  # `:connected | :refused | :timeout` (029 T005).
  #
  # For TCP, `timeout` means REACHED: a destination that accepts and stays
  # silent is genuinely reached, and only an immediate close says the
  # enforcement point refused. **That reasoning inverts for UDP.** A datagram
  # has no handshake, so silence is the single most likely outcome of a probe
  # that was dropped, a probe nothing was listening for, and a probe that was
  # filtered -- three states no receiver can tell apart.
  #
  # So only a datagram coming *back* counts. `:answered` means something on the
  # far side received the query and replied, which is unambiguous evidence that
  # the datagram left the namespace; `:unanswered` covers everything else and
  # the suite scores it as a refusal. That is the conservative direction and it
  # under-claims leaks rather than over-claiming them.
  #
  # ⚠️ `econnrefused` is `:unanswered`, not `:answered`. An ICMP port-unreachable
  # can be generated by the namespace's own loopback, so treating it as a
  # crossing would report a leak that never left.
  defp udp_probe_from_sandbox(sandbox, host, port) do
    address = String.to_charlist(host)
    timeout = @connect_probe_timeout_ms

    # One `:peer.call`, for the same reason the TCP probe is: each call runs in
    # a fresh process on the sandbox node, and a `gen_udp` socket dies with the
    # process that opened it, so a send in one call and a recv in the next
    # always reports a closed socket rather than a boundary.
    case call(
           sandbox,
           :erl_eval,
           :exprs,
           [udp_probe_exprs(address, port, timeout), []],
           timeout * 3
         ) do
      {:ok, {:value, verdict, _bindings}} when verdict in [:answered, :unanswered] ->
        verdict

      {:error, reason} ->
        {:sandbox_unreachable, reason}

      other ->
        {:sandbox_unreachable, other}
    end
  end

  @doc false
  # Public for the same reason `probe_exprs/3` is: the expression is built here
  # and evaluated on the sandbox node, so nothing else can check that the two
  # agree.
  #
  # ⚠️ The payload is a **real DNS query** (`example.com IN A`, recursion
  # desired), not arbitrary bytes. A resolver discards a malformed datagram
  # without replying, so a junk payload would report `:unanswered` against a
  # resolver that is answering perfectly well -- silence attributed to a
  # boundary that had nothing to do with it.
  def udp_probe_exprs(address, port, timeout) do
    source = """
    case gen_udp:open(0, [binary, {active, false}]) of
      {ok, S} ->
        Q = <<16#AB,16#CD,1,0,0,1,0,0,0,0,0,0,7,"example",3,"com",0,0,1,0,1>>,
        V = case gen_udp:send(S, #{:io_lib.format(~c"~w", [address])}, #{port}, Q) of
              ok ->
                case gen_udp:recv(S, 0, #{timeout}) of
                  {ok, _} -> answered;
                  {error, _} -> unanswered
                end;
              {error, _} -> unanswered
            end,
        gen_udp:close(S),
        V;
      {error, _} -> unanswered
    end.
    """

    {:ok, tokens, _} = source |> String.to_charlist() |> :erl_scan.string()
    {:ok, exprs} = :erl_parse.parse_exprs(tokens)
    exprs
  end

  # The probe, as an expression the sandbox node evaluates in one process.
  #
  # ⚠️ **Not a fun.** A closure defined here belongs to `ExSandbox.Mechanism.Beam`,
  # and the sandbox runs a bare `erl` that cannot load this project's modules --
  # `check_funs_loadable/3` correctly refuses it with `{:fun_not_loadable, _}`,
  # which the suite then reports as the sandbox becoming unreachable. Measured:
  # shipping this probe as a fun turned all three network checks into
  # `{:sandbox_unreachable, {:fun_not_loadable, ExSandbox.Mechanism.Beam}}`.
  #
  # Parsed and evaluated on the far side instead, so nothing but OTP is needed
  # there -- the same constraint that rules out `Node` and every Elixir module
  # in this probe.
  #
  # ⚠️ **A completed handshake is NOT evidence the destination was reached.**
  # `Egress.Acceptor` is a *transparent* proxy: the redirect sends every
  # outbound connection to it, so the handshake always completes -- against the
  # acceptor -- whether the destination is permitted or denied. On a refusal the
  # acceptor closes without answering, which is what `FR-011a` requires (a
  # denied destination must be indistinguishable from an unreachable one) and
  # what `FR-011f` protects (no ranking REJECT above DROP). Measured:
  #
  #     # a listener that accepts and immediately closes -- the refusal path
  #     :gen_tcp.connect(~c"127.0.0.1", port, [], 2000)  #=> {:ok, #Port<0.4>}
  #
  # So the question is "did anything cross?", not "did the handshake complete?"
  #
  # ⚠️ The probe **speaks first**. Most services -- 1.1.1.1:443 among them --
  # wait for the client before saying anything, so a read-only probe cannot
  # distinguish a reached-but-quiet destination from a refused one within its
  # bound.
  #
  # ⚠️ `timeout` counts as REACHED, deliberately. A destination that accepts and
  # stays silent is genuinely reached; only an immediate close says the
  # enforcement point refused. Scoring silence as a refusal would be the false
  # pass -- a real breach against a quiet service would read as a held boundary.
  @doc false
  # Public only so `connect_probe_verdict_test.exs` can evaluate the probe
  # against real listeners on the host. The expression is built here and
  # evaluated on the sandbox node, so nothing else can check that the two agree
  # -- and this probe has already shipped wrong twice (as a fun the sandbox
  # cannot load, and split across two calls so the socket's owner died between
  # them), both times found in a container rather than here.
  def probe_exprs(address, port, timeout) do
    source = """
    case gen_tcp:connect(#{:io_lib.format(~c"~w", [address])}, #{port}, \
    [binary, {active, false}], #{timeout}) of
      {ok, S} ->
        gen_tcp:send(S, <<0>>),
        V = case gen_tcp:recv(S, 0, #{timeout}) of
              {error, closed} -> refused;
              {error, econnreset} -> refused;
              {ok, _} -> connected;
              {error, timeout} -> connected;
              {error, _} -> connected
            end,
        gen_tcp:close(S),
        V;
      {error, timeout} -> timeout;
      {error, etimedout} -> timeout;
      {error, _} -> refused
    end.
    """

    {:ok, tokens, _} = source |> String.to_charlist() |> :erl_scan.string()
    {:ok, exprs} = :erl_parse.parse_exprs(tokens)
    exprs
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
  def execute(%Sandbox{} = sandbox, {cmd, args}, opts \\ [])
      when is_binary(cmd) and is_list(args) and is_list(opts) do
    budget = time_budget(sandbox)
    timeout = Keyword.get(opts, :timeout) || budget || configured_exec_timeout()

    exprs =
      Exec.runner_exprs(cmd, args,
        limit_bytes: Keyword.get(opts, :limit_bytes, Exec.capture_limit_bytes()),
        env: Keyword.get(opts, :env, Exec.default_env())
      )

    sandbox
    |> call(:erl_eval, :exprs, [exprs, []], timeout)
    |> interpret_execution(sandbox, budget, timeout)
    |> emit_output(opts[:on_output])
  end

  # ⚠️ Three outcomes in, three outcomes out, and the mapping is the whole
  # requirement. `008-FR-016`/`FR-026` say an attempt that could not be
  # performed is not a failed attempt, so nothing here may invent an exit
  # status for a command that never ran.
  defp interpret_execution({:ok, value}, _sandbox, _budget, _timeout) do
    case Exec.decode(value) do
      {:ok, completion} -> {:ok, completion}
      {:could_not_run, reason} -> {:error, {:could_not_run, reason}}
    end
  end

  # A sandbox that never existed here, or that has been destroyed. THE case
  # `008` quickstart Scenario 1 turns on: a destroyed sandbox must answer
  # `:could_not_run`, not a non-zero status.
  defp interpret_execution({:error, :unknown_sandbox}, _sandbox, _budget, _timeout) do
    {:error, {:could_not_run, :unknown_sandbox}}
  end

  # The call waited out its ceiling. Which ceiling decides what this means, and
  # the distinction is the same one `exec_in_sandbox/2` already draws:
  #
  #   * the sandbox's OWN declared `timeout_ms` is a limit on the tenant's work.
  #     A declared limit that stops nothing is not a limit, so the sandbox is
  #     terminated and the caller is told the limit was exceeded.
  #   * this library's configured ceiling is its guard against waiting forever.
  #     Tripping it says nothing whatever about the tenant, so it is
  #     `:could_not_run` -- we have no result and no limit to attribute one to.
  #
  # ⚠️ **"Nothing to attribute it to" has to be CHECKED, not assumed** (Q17).
  #
  # A memory cap that works arrives here, not at the clause below. The OOM kill
  # takes the whole systemd scope -- the sandbox's BEAM with it -- so the peer
  # call has nobody left to answer it and waits out the ceiling. The result is a
  # `:timeout`, which matched here and returned `:could_not_run` while the
  # positive attribution sitting in the next clause was never consulted.
  #
  # Measured in the isolation container (`docker/compose.memtiming.yml`), one
  # 64 MB sandbox against `memory_hog_command(192)`:
  #
  #     launch chain (provision + start)          207 ms
  #     control `echo` round trip                  53 ms
  #     scope Result=oom-kill first observed        55 ms after the exec started
  #     execute/3 returned                      15001 ms  {:could_not_run, {:timeout, 15000}}
  #     status/1 then provision_failure_reason/1  8 ms   {:error, :resource_cap}
  #
  # So the cap fired in 55 ms, the caller then waited 14.9 s on a dead node, and
  # the answer it gave was that the command could not be run -- of a cap that
  # had already killed it. `ExSandbox.Conformance.Execution.classify/4` scores
  # `:could_not_run` `:inconclusive`, quite correctly, so a working memory cap
  # reported as UNDEMONSTRATED. The same breach down `exec_in_sandbox/2`
  # resolved to `{:limit_exceeded, :reported_by_mechanism}` in the same run,
  # which is why one conformance group passed while the other did not.
  #
  # ⚠️ Still a **positive** attribution, and ordered after the tenant's own
  # budget. `killed_by_memory_cap?/1` demands that the node be gone AND that
  # systemd's verdict on this sandbox's own scope be `oom-kill`; a call that
  # timed out for any other reason falls through to `:could_not_run` exactly as
  # before. A sandbox that overran a budget it declared is still reported
  # against that budget -- it asked for the limit, and the limit is the honest
  # attribution even where memory also gave out.
  defp interpret_execution({:error, {:exit, {:timeout, _}}}, sandbox, budget, timeout) do
    cond do
      is_integer(budget) and timeout <= budget ->
        enforce_time_budget(sandbox)
        {:error, {:limit_exceeded, :wall_clock}}

      killed_by_memory_cap?(sandbox) ->
        {:error, {:limit_exceeded, :memory}}

      true ->
        {:error, {:could_not_run, {:timeout, timeout}}}
    end
  end

  defp interpret_execution({:error, reason}, sandbox, _budget, _timeout) do
    # The sandbox died under us. It may have died BECAUSE of a cap, and the
    # mechanism is the only thing that can tell: `status/1` probes the node and
    # records why, `provision_failure_reason/1` reads that verdict, and the
    # verdict for a dead sandbox that was not stopped by us comes from systemd's
    # `oom-kill` on the scope (`cap_breached?/1`). Only that positive
    # attribution becomes `:limit_exceeded`; everything else stays
    # `:could_not_run`, because a process that died of something unrelated has
    # demonstrated nothing about a cap.
    if killed_by_memory_cap?(sandbox) do
      {:error, {:limit_exceeded, :memory}}
    else
      {:error, {:could_not_run, reason}}
    end
  end

  defp killed_by_memory_cap?(sandbox) do
    # `status/1` first, and not as a formality: `provision_failure_reason/1`
    # reads a *recorded* verdict, and nothing records one until something looks.
    # Asking for the reason without a preceding status read answers `:ok` ("no
    # failure recorded") for a sandbox that is already dead.
    case status(sandbox) do
      {:ok, state} when state in [:running, :unknown] -> false
      _ -> provision_failure_reason(sandbox) == {:error, :resource_cap}
    end
  end

  # A2's sink, and it is fed AFTER completion for this mechanism -- honestly
  # rather than pretending.
  #
  # ⚠️ `:peer.call/5` is a request/response channel: the sandbox-side runner
  # cannot push a chunk back mid-command over it without a second channel this
  # mechanism does not have. So a caller passing `:on_output` gets the same
  # chunks, in order, at completion. That is A1's timing with A2's *interface*,
  # which is what makes a later change to genuine streaming a change to this
  # mechanism rather than to the behaviour every mechanism implements -- the
  # second breaking change the seam note exists to avoid.
  defp emit_output(result, nil), do: result

  defp emit_output({:ok, completion} = result, sink) when is_function(sink, 1) do
    if completion.stdout != <<>>, do: sink.({:stdout, completion.stdout})
    if completion.stderr != <<>>, do: sink.({:stderr, completion.stderr})
    result
  end

  defp emit_output(result, _sink), do: result

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
