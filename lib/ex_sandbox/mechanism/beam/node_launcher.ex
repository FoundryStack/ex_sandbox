defmodule ExSandbox.Mechanism.Beam.NodeLauncher do
  @moduledoc """
  Starts, probes, and terminates one hardened sandbox node (005 T020-T026).

  ## `:peer` is the launcher, not the boundary

  `:peer.start_link/1` starts an OS-level BEAM node and gives us a supervised
  handle on it. That is all it gives us. It does **not** confine the filesystem,
  drop privileges, cap memory, or clear the environment — every one of
  `FR-007` - `FR-011` is satisfied by the command in `exec`, built by
  `ExSandbox.Hardening`, and by nothing in this module.

  Stated plainly because the option map below reads like configuration, and it
  would be easy to add an option here believing it tightened something. The two
  options that actually carry weight are `exec` (the boundary) and the
  per-sandbox `-setcookie` (`FR-003`); the rest bound failure.
  """

  alias ExSandbox.Sandbox

  require Logger

  # Resolved through configuration rather than aliased directly. `005`'s
  # hardening contract is per-platform, and a compile-time reference to the
  # Linux module would mean every non-Linux host carries a hard dependency on
  # code that refuses to run there -- and, more practically, that the launch
  # path could not be tested anywhere but Linux.
  #
  # ⚠️ This is NOT `ExSandbox.Hardening`, which is `012`'s *behaviour* for
  # applying limits. This names `005`'s host-confinement module, whose API is
  # `available?/0`, `build_command/2`, and `verify_applied/1`.
  defp hardening do
    Application.get_env(:ex_sandbox, :hardening_module, ExSandbox.Hardening.Linux)
  end

  @typedoc "What a caller needs to address and later reclaim a launched node."
  @type launched :: %{
          node: node(),
          os_pid: integer(),
          peer: pid(),
          cookie: atom(),
          # ⚠️ The egress binding, carried here because `destroy/1` has no other
          # route to it. `Binding.release/2` needs the struct, and the struct is
          # created inside `launch/2` -- so without a field on the row that
          # outlives this frame, the `/30` and its policy leak silently. See
          # `ExSandbox.Egress.BindingLifecycleTest` for what that costs.
          #
          # `nil` on a host with no egress path, which is the ordinary case on
          # macOS and the reason `destroy/1` must tolerate its absence.
          binding: ExSandbox.Egress.Binding.t() | nil
        }

  @doc """
  Launch one hardened sandbox node.

  Refuses when the host hardening module reports it is unavailable (R9, Principle II): a host that
  cannot confine must not run tenant code unconfined. Returns
  `{:error, :mechanism_error}` after recording *why*, so an operator reads the
  missing capability rather than a bare atom.
  """
  @spec launch(Sandbox.t(), keyword()) :: {:ok, launched()} | {:error, atom()}
  def launch(%Sandbox{} = sandbox, opts \\ []) do
    granted_env = Keyword.get(opts, :granted_env, [])

    with :ok <- require_hardening(),
         :ok <- prepare_storage(sandbox),
         :ok <- clear_stale_scope(sandbox),
         {:ok, exec} <- hardening().build_command(sandbox, granted_env),
         {:ok, exec, binding, plan} <- policed(sandbox, exec),
         {:ok, launched} <- start_peer_releasing(sandbox, exec, binding),
         # ⚠️ Between `start_peer_releasing/3` and here the tenant is running
         # and unpoliced. The window cannot be closed by reordering -- the
         # namespace does not exist until `pasta` starts the tenant in it -- so
         # it is closed by failing toward termination instead. See `police/2`.
         :ok <- police_or_terminate(plan, launched, binding),
         :ok <- verify_or_terminate(launched, sandbox) do
      {:ok, Map.put(launched, :binding, binding)}
    end
  end

  # Puts the tenant inside a policed namespace, or leaves the command alone.
  #
  # ⚠️ **There is no third answer, and in particular no silent fallback.** The
  # tempting one is: if the egress path cannot be built, launch under
  # `--unshare-net` anyway, because an empty namespace reaches nothing and no
  # tenant is exposed. That is precisely the state `contracts/egress.md` names
  # as worse than failing -- a sandbox that denies everything passes every
  # denial check in the conformance suite and is recorded as a demonstrated
  # network boundary, while the tenant's allowlist is not enforced but
  # *unreachable*, and nothing reports it.
  #
  # So the two outcomes are: policed (allowlist enforced), or refused. A host
  # that can confine but cannot police returns `{:error, :mechanism_error}`
  # from `LaunchPlan.build/4` rather than a weaker sandbox.
  #
  # Hosts with no egress path at all -- macOS, where `--unshare-net` is not in
  # the command because `Hardening.Linux` never ran -- take the passthrough
  # clause. That is not a fallback: nothing was confined to begin with, and
  # `require_hardening/0` above has already refused if confinement was required.
  defp policed(%Sandbox{} = sandbox, exec) do
    case egress_allowlist(sandbox) do
      [] ->
        # No allowlist means no policy to install. The tenant keeps whatever
        # confinement `build_command/2` produced -- today `--unshare-net`, which
        # denies everything. ⚠️ Correct only because it is *also* what the
        # census reports as the third outcome rather than a pass: `:permitted`
        # is absent, so `require_permitted_reachable/2` reports
        # `capability_unavailable` instead of scoring a boundary it never saw.
        {:ok, exec, nil, nil}

      allowed ->
        install_policy(exec, allowed)
    end
  end

  defp install_policy(exec, allowed) do
    with {:ok, binding} <- acquire_binding(allowed),
         {:ok, rewritten, plan} <- build_plan(binding, exec) do
      {:ok, rewritten, binding, plan}
    end
  end

  defp acquire_binding(allowed) do
    case ExSandbox.Egress.Binding.acquire(allowed) do
      {:ok, binding} ->
        {:ok, binding}

      {:error, reason} ->
        # ⚠️ Refused, not downgraded. `:pool_exhausted` means this host cannot
        # give the tenant a policy -- and a tenant who cannot be given a policy
        # must not be given a sandbox that reaches everything instead, nor one
        # that reaches nothing while the census calls it policed.
        Logger.error("""
        sandbox launch refused: no egress binding available (#{inspect(reason)}).

        Launching without one would produce a sandbox whose allowlist is not
        enforced. Refusing is the only outcome that cannot be mistaken for a
        working boundary.
        """)

        {:error, :mechanism_error}
    end
  end

  # ⚠️ `exec` is `{prog, args}` -- what `Hardening.Linux.compose/3` returns and
  # what `:peer` needs -- while `LaunchPlan.build/4` works on a flat command
  # list, because the flag it removes and the prefix it adds can appear at any
  # position. So the tuple is flattened on the way in and reassembled on the way
  # out, with the plan's own head becoming the new program.
  #
  # The reassembly matters: the plan prefixes `ip netns exec <name>`, so the
  # program `:peer` spawns is now `ip`, not `systemd-run`. Rebuilding the tuple
  # from `plan.tenant_command` rather than keeping the original `prog` is what
  # makes that true -- keeping it would exec `systemd-run` with `ip`'s arguments.
  defp build_plan(binding, {prog, args}) do
    flat = [prog | args]

    case ExSandbox.Egress.LaunchPlan.build(binding.source_key, acceptor_port(), flat) do
      {:ok, plan} ->
        # ⚠️ Nothing is *run* here any more, and that inversion is the whole of
        # the T060a3 rework. The old code executed `setup_steps` at this point,
        # creating and configuring a namespace before the tenant existed. That
        # order is not reachable: `pasta` cannot attach to a namespace made by
        # `ip netns add` (measured -- `Failed to join network namespace:
        # Permission denied`), and a tenant inside `pasta`'s namespace has no
        # `CAP_NET_ADMIN` to configure it from within.
        #
        # So the namespace is created *by starting the tenant in it*, and the
        # policy is installed afterwards by `police/2`. See
        # `egress-path-measurements.md` defects 3 and 4.
        {:ok, exec_from_plan(plan), plan}

      {:error, reason} ->
        # The binding is already held at this point, so it has to go back before
        # this returns -- otherwise a host that consistently fails to build a
        # plan burns one /30 per attempt until the pool is empty, and reports
        # `:pool_exhausted` for a cause that has nothing to do with capacity.
        :ok = ExSandbox.Egress.Binding.release(binding)

        Logger.error("""
        sandbox launch refused: could not build the egress path (#{inspect(reason)}).

        `:no_network_confinement` means the hardening command did not confine
        the network, so there is nothing to convert -- rewriting it would launch
        a tenant with the host's own network. `:no_pool_port` means the acceptor
        is not listening, so the redirect would point at a dead port, which
        from inside the sandbox is indistinguishable from a correctly denied
        destination.
        """)

        {:error, :mechanism_error}
    end
  end

  @doc """
  Installs the redirect into a launched tenant's namespace.

  ⚠️ This runs **after** the tenant is already executing, and that is forced by
  the mechanism rather than chosen: the namespace does not exist until `pasta`
  creates it, and `pasta` creates it by starting the tenant inside it. There is
  a real window in which the tenant runs unpoliced.

  The window fails *closed*. Until the redirect lands there is no NAT rule
  sending the tenant's traffic anywhere, and the acceptor it would be sent to
  is not listening -- so a connection attempted in the window reaches nothing.
  That is asserted rather than assumed: a failure here **terminates the
  tenant**, because the alternative is a running sandbox whose allowlist is not
  enforced, and which passes every denial check in the conformance suite.

  Public because it is the ordering rule that cannot be exercised off Linux --
  left private it would be verified only where the whole launch works, which is
  the arrangement that let the context-discard defect survive.
  """
  @spec police(ExSandbox.Egress.LaunchPlan.t(), keyword()) :: :ok | {:error, atom()}
  def police(%ExSandbox.Egress.LaunchPlan{} = plan, opts \\ []) do
    pasta_pid = Keyword.fetch!(opts, :pasta_pid)
    finder = Keyword.get(opts, :finder, &ExSandbox.Egress.Pasta.find/2)
    runner = Keyword.get(opts, :runner, &run_steps/1)

    starter = Keyword.get(opts, :acceptor_starter, &start_acceptor/3)

    case finder.(pasta_pid, opts) do
      {:ok, holder_pid} ->
        # ⚠️ The acceptor starts BEFORE the redirect, and the order is the whole
        # of it. A redirect installed first points at a port nothing is
        # listening on, and from inside the sandbox that is indistinguishable
        # from a destination correctly denied by policy -- every denial check
        # passes while the allowlist is enforced by nothing.
        #
        # Measured directly while building `docker/acceptor-e2e.sh`: with the
        # acceptor bound in the wrong namespace the tenant got `ECONNREFUSED`,
        # which reads exactly like a working boundary.
        with :ok <- starter.(plan, holder_pid, opts) do
          runner.(ExSandbox.Egress.LaunchPlan.redirect_steps(plan, holder_pid))
        end

      {:error, reason} ->
        # ⚠️ Refused, never defaulted to `pasta_pid`. That fallback is available,
        # reads as robustness, and installs the sandbox's redirect into the HOST
        # namespace -- succeeding, warning about nothing, and leaving the tenant
        # unpoliced. See `ExSandbox.Egress.Pasta`.
        Logger.error("""
        egress: could not identify the sandbox's namespace holder (#{inspect(reason)}).

        The tenant is running but unpoliced and must not be left that way.
        Falling back to pasta's own pid would install the redirect into the
        host's network namespace, which succeeds silently.
        """)

        {:error, :mechanism_error}
    end
  end

  # ⚠️ A tenant that could not be policed is **terminated**, not left running.
  #
  # The tempting alternative is to log and continue: the sandbox exists, the
  # tenant is confined in every other respect, and the network is at worst
  # unrestricted. That is exactly the outcome `contracts/egress.md` names as
  # worse than failing -- an unenforced allowlist that the census records as a
  # demonstrated boundary, because every denial check passes for reasons that
  # have nothing to do with policy.
  defp police_or_terminate(nil, _launched, _binding), do: :ok

  defp police_or_terminate(plan, launched, binding) do
    case police(plan, pasta_pid: pasta_pid(plan)) do
      :ok ->
        :ok

      {:error, reason} ->
        _ = terminate(launched)
        if binding, do: :ok = ExSandbox.Egress.Binding.release(binding)
        {:error, reason}
    end
  end

  # `pasta` writes its host-side pid here. ⚠️ That pid is NOT the namespace
  # holder -- `police/2` searches its children for the one whose network
  # namespace differs from ours. See `ExSandbox.Egress.Pasta`.
  defp pasta_pid(%ExSandbox.Egress.LaunchPlan{pidfile: pidfile}) do
    case File.read(pidfile) do
      {:ok, contents} ->
        case Integer.parse(String.trim(contents)) do
          {pid, _} -> pid
          :error -> 0
        end

      {:error, _} ->
        0
    end
  end

  # Starts this sandbox's acceptor inside its network namespace.
  #
  # ⚠️ One acceptor per namespace, not one pool for all sandboxes. That is not
  # the design `013-FR-014c` first argued for, and the reason it changed is
  # measured rather than preferred: an `nft` `redirect` is DNAT **to the local
  # machine as the namespace sees it**, so it can only ever reach a socket in
  # that namespace. A host-side pool cannot be reached by it at all -- measured,
  # the tenant's connect returned OK and the pool never saw the connection.
  #
  # The blast-radius argument survives in substance: the acceptor holds no
  # platform credential and **no policy**. It asks `ExSandbox.Egress.Verdict`
  # over a socket the tenant cannot see, so `Pool.decide/3` remains the single
  # implementation of the rule.
  defp start_acceptor(plan, holder_pid, opts) do
    helper = Keyword.get(opts, :acceptor_helper, acceptor_helper_path())
    verdict = Keyword.get(opts, :verdict_path, ExSandbox.Egress.Verdict.default_path())

    command =
      ExSandbox.Egress.Acceptor.listener_command(
        holder_pid,
        plan.pool_port,
        helper,
        verdict,
        plan.source_key
      )

    [prog | args] = command

    # Started detached: the acceptor outlives this call by design -- it serves
    # the namespace for the sandbox's whole life. `System.cmd/3` would block
    # until it exited, which is never.
    port =
      Port.open({:spawn_executable, System.find_executable(prog)}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        line: 256,
        args: args
      ])

    await_acceptor(port, plan)
  end

  # ⚠️ Waits for the acceptor to say it is listening rather than assuming it.
  # Returning `:ok` optimistically would install the redirect against a port
  # that may never open, which fails closed but silently -- the sandbox loses
  # egress entirely and every denial check still passes.
  defp await_acceptor(port, plan) do
    receive do
      {^port, {:data, {:eol, line}}} ->
        if String.starts_with?(line, "ACCEPTOR listening") do
          :ok
        else
          await_acceptor(port, plan)
        end

      {^port, {:exit_status, status}} ->
        Logger.error("""
        egress: the acceptor for #{inspect(plan.source_key)} exited before it \
        began listening (status #{status}).

        The tenant is running but nothing is listening at the address its
        redirect would name, so it would lose egress entirely while every
        denial check in the conformance suite still passed.
        """)

        {:error, :mechanism_error}
    after
      5_000 ->
        _ = Port.close(port)

        Logger.error("""
        egress: the acceptor for #{inspect(plan.source_key)} did not begin \
        listening within 5s.

        Installing the redirect anyway would point it at a dead port, which from
        inside the sandbox is indistinguishable from a correctly denied
        destination.
        """)

        {:error, :mechanism_error}
    end
  end

  @doc """
  Where the namespace acceptor helper lives.

  Public because a release that ships without it produces a launch failure whose
  cause is a missing file, and naming that file is the difference between a
  one-line fix and a namespace investigation.
  """
  @spec acceptor_helper_path() :: String.t()
  def acceptor_helper_path do
    Application.app_dir(:ex_sandbox, ["priv", "egress", "nsacceptor.py"])
  end

  defp run_steps(steps) do
    Enum.reduce_while(steps, :ok, fn [prog | args], :ok ->
      case System.cmd(prog, args, stderr_to_stdout: true) do
        {_out, 0} ->
          {:cont, :ok}

        {out, code} ->
          # Named rather than swallowed. A failed setup step means the sandbox
          # cannot be policed, and the tenant must not launch -- but an operator
          # needs the command and its output, because the causes (missing
          # `/dev/net/tun`, no `CAP_SYS_ADMIN`, a stale namespace of the same
          # name) are host facts this library cannot fix and can only report.
          Logger.error("""
          egress setup step failed (exit #{code}): #{Enum.join([prog | args], " ")}

          #{String.trim(out)}
          """)

          {:halt, {:error, :mechanism_error}}
      end
    end)
  end

  # The port this sandbox's acceptor will listen on, inside its own namespace.
  #
  # ⚠️ This used to read `ExSandbox.Egress.Pool.port()`, a HOST socket, and that
  # was wrong in a way no host-side test could see. An `nft` `redirect` is DNAT
  # to the local machine *as the namespace sees it*, so it can only ever reach a
  # socket in that namespace -- measured, the tenant's connect returned OK and
  # the host pool never saw the connection. The redirect must name a port in the
  # sandbox's own namespace, which is where `start_acceptor/3` binds it.
  #
  # A fixed port is correct **because** each acceptor is alone in its namespace:
  # nothing else can bind there and nothing else can route to it, so there is no
  # collision to avoid between sandboxes. Allocating a distinct host port per
  # sandbox would suggest a shared address space that does not exist here.
  @acceptor_port 18_080

  defp acceptor_port, do: @acceptor_port

  @doc """
  The allowlist a sandbox was provisioned with, or `[]`.

  Public because it is a *decision* -- whether this sandbox gets a policy at
  all -- and `launch/2` cannot run on any host that is not Linux. Left private,
  the rule would be verifiable only where the whole launch works, which is the
  arrangement that let the earlier context-discard defect survive: the
  allowlist was parsed correctly, then dropped, and every test asserted on the
  parse.
  """
  @spec egress_allowlist(Sandbox.t()) :: [ExSandbox.Egress.Policy.destination()]
  def egress_allowlist(%Sandbox{context: context}) when is_map(context) do
    context |> Map.get(:network_allowlist, []) |> List.wrap()
  end

  def egress_allowlist(_sandbox), do: []

  @doc """
  Rebuilds `{prog, args}` from a plan's `pasta_command`.

  ⚠️ The program becomes `pasta`, not `systemd-run` and not `bwrap`. Keeping
  the original program while taking the plan's arguments produces a command
  that reads correctly in a log line and execs the wrong binary -- and because
  the arguments still *contain* every hardening flag, a test that greps the
  joined string for `--unshare-net` or the scope name would pass.
  """
  @spec exec_from_plan(ExSandbox.Egress.LaunchPlan.t()) :: {String.t(), [String.t()]}
  def exec_from_plan(%ExSandbox.Egress.LaunchPlan{pasta_command: [prog | args]}) do
    {prog, args}
  end

  # ⚠️ A binding acquired but never launched is a leak, and the failure that
  # produces it -- `start_peer/2` refusing -- is the ordinary one, not the rare
  # one: a missing image, a bad exec, a host out of memory. Releasing here keeps
  # the pool's occupancy tied to sandboxes that actually exist.
  defp start_peer_releasing(sandbox, exec, binding) do
    case start_peer(sandbox, exec) do
      {:ok, launched} ->
        {:ok, launched}

      {:error, reason} ->
        if binding, do: :ok = ExSandbox.Egress.Binding.release(binding)
        {:error, reason}
    end
  end

  # ⚠️ The same property that makes a cap breach attributable makes a sandbox id
  # unreusable, and this is the price of R7e.
  #
  # A named scope's unit object **survives the death of its processes** in
  # `failed` state -- that is precisely why `Result=oom-kill` can still be read
  # after the cgroup directory is gone. But systemd then refuses to create a new
  # scope under that name:
  #
  #     Failed to start transient scope unit: Unit sandbox-<id>.scope
  #     was already loaded or has a fragment file.
  #
  # so the *next* sandbox with that id fails to boot, reported as
  # `:mechanism_error` — a platform fault raised by a previous tenant's breach.
  # Ids collide in practice: `System.unique_integer/1` restarts per VM, so a
  # rerun of a suite reuses them.
  #
  # `reset-failed` discards the spent unit. It runs before launch rather than
  # after death deliberately: a reset at teardown would erase the verdict
  # `provision_failure_reason/1` exists to read, and would be skipped entirely
  # whenever the host that created the scope crashed.
  #
  # Failure is not propagated. `reset-failed` on a name that was never used is a
  # no-op, and on a host without systemd there is no scope to clear; letting
  # either abort a launch would break hosts that this never concerned.
  defp clear_stale_scope(sandbox) do
    if function_exported?(hardening(), :scope_unit_name, 1) do
      unit = hardening().scope_unit_name(sandbox)
      _ = System.cmd("systemctl", ["reset-failed", unit], stderr_to_stdout: true)
    end

    :ok
  rescue
    _ -> :ok
  end

  defp require_hardening do
    if hardening().available?() do
      :ok
    else
      # Logged with the capability map rather than a bare boolean: "hardening
      # unavailable" sends an operator looking at everything, and the map names
      # the one thing to install.
      Logger.error("""
      refusing to launch a sandbox: this host cannot enforce confinement (005 R9).
      capabilities: #{inspect(hardening().capabilities())}
      """)

      {:error, :mechanism_error}
    end
  end

  defp start_peer(%Sandbox{} = sandbox, exec) do
    cookie = generate_cookie()

    options = %{
      # ⚠️ **No `name:`**, deliberately. Naming a peer makes `:peer` start it
      # distributed, and distribution cannot start inside `--unshare-net`: with
      # no interfaces there is no host to resolve, so `net_kernel` fails with
      # "Can't set long node name!" and the kernel aborts with `nodistribution`
      # before the sandbox runs a single instruction. The launch failed *because*
      # the network isolation worked -- the same shape as the `:erpc` bug, one
      # layer deeper.
      #
      # Unnamed, the sandbox boots as `:nonode@nohost` and `:peer.call/4` still
      # works, because the control channel is stdio rather than distribution.
      # This is also the stronger position for `FR-003`: a node that never starts
      # distribution cannot connect to the platform or to another sandbox
      # whatever cookie it holds, so cluster isolation no longer rests on the
      # cookie alone.
      #
      # THE security boundary (R2). `:peer` runs whatever this names; the
      # hardening wrapper is what makes that something confined.
      #
      # The `{Prog, Args}` form matters: it execs directly, so `env -i` runs
      # before `erlexec` and clears the environment (verified at `peer.erl:1151`).
      # Charlists again, per `verify_args/1`.
      exec: to_exec(exec),
      args: args(cookie),
      # ⚠️ `env: []` does NOT clear the environment (R3, verified in `peer.erl`).
      # `:peer`'s `env` is *additive* — it adds to what the origin already has.
      # The empty list is documentation that this channel grants nothing, and a
      # guard against a future edit adding one variable here and concluding the
      # environment is therefore controlled. `env -i`, inside `exec`, is what
      # actually clears it.
      env: [],
      # NEVER `:crash` (R6, `peer.erl:250`, `:962-968`). `:crash` terminates the
      # *origin* process with the sandbox's exit reason, which would let tenant
      # code kill platform processes by halting itself — the exact inversion of
      # `FR-005`.
      peer_down: :continue,
      shutdown: {:halt, shutdown_timeout()},
      wait_boot: wait_boot_timeout(),
      connection: :standard_io
    }

    # `:peer.start_link/1` **exits** on a failed boot (`peer.erl:934`) rather
    # than returning an error tuple, so a bare `case` would propagate a crash to
    # whoever asked to provision a sandbox. A failed launch is an ordinary,
    # expected outcome here -- the host was misconfigured, the image was
    # missing -- and it has to come back as a value.
    try do
      do_start_peer(options, cookie, sandbox)
    catch
      :exit, reason ->
        Logger.error("sandbox node failed to boot: #{inspect(reason)}")
        {:error, :mechanism_error}
    end
  end

  defp do_start_peer(options, cookie, sandbox) do
    case :peer.start_link(options) do
      {:ok, peer, node} ->
        case os_pid(peer) do
          {:ok, os_pid} ->
            # ⚠️ Captured **now**, while the process is alive. Once a sandbox
            # dies, `/proc/<pid>` is gone and the path is unrecoverable -- which
            # is why every cap breach was reported as `:mechanism_error` rather
            # than `:resource_cap`.
            {:ok,
             %{
               node: node,
               os_pid: os_pid,
               peer: peer,
               cookie: cookie,
               cgroup_path: read_cgroup_path(os_pid),
               # The scope unit systemd created, recorded so the cause of death
               # can be read after the sandbox is gone (R7e). Taken from the
               # hardening module that built the launch command, so the name the
               # reader queries cannot drift from the name systemd was given.
               scope_unit: scope_unit_name(sandbox),
               # The parent slice's `oom_kill` count as of launch. The sandbox's
               # own scope is destroyed by systemd the instant it dies -- a 200ms
               # poll never once caught it -- but the parent slice persists and
               # its counter aggregates children, so a delta against this
               # baseline is what distinguishes a cap breach from a crash.
               oom_baseline: read_parent_oom_kills(read_cgroup_path(os_pid))
             }}

          {:error, reason} ->
            # No os_pid means nothing downstream can verify confinement, so this
            # is a failed launch rather than a degraded one.
            _ = :peer.stop(peer)

            Logger.error(
              "launched node #{node} but could not read its OS pid: #{inspect(reason)}"
            )

            {:error, :mechanism_error}
        end

      {:error, reason} ->
        Logger.error("could not launch a sandbox node: #{inspect(reason)}")
        {:error, :mechanism_error}
    end
  end

  # A distinct cookie per sandbox is what actually enforces `FR-003` (R4).
  # `-hidden` and `-connect_all false` only reduce discoverability: with the
  # platform's cookie, any sandbox could `Node.connect/1` to the platform and
  # call `:erlang.halt/0` on it, and the flags would not have stopped it.
  defp generate_cookie do
    :crypto.strong_rand_bytes(24)
    |> Base.url_encode64(padding: false)
    |> String.to_atom()
  end

  # Charlists, not binaries: `peer.erl:858` rejects anything failing
  # `io_lib:char_list/1`, so an Elixir string here raises `{:invalid_arg, ...}`
  # at launch rather than at compile time.
  defp args(cookie) do
    ["-setcookie", Atom.to_string(cookie), "-hidden", "-connect_all", "false"]
    |> Kernel.++(elixir_code_path())
    |> Enum.map(&String.to_charlist/1)
  end

  # ⚠️ Elixir's stdlib, made loadable inside the sandbox (R7d).
  #
  # Without this a sandbox boots a bare `erl`: `:code.which(Enum)` answers
  # `:non_existing`, and every call naming an Elixir module returns `:undef`.
  # That failure is dangerous rather than inconvenient, because `{:error, :undef}`
  # satisfies "the sandbox could not do this" exactly as convincingly as a real
  # boundary -- three isolation tests were passing on it while attempting
  # nothing.
  #
  # **This grants no new access.** `runtime_ro_binds/0` already ro-binds `/usr`,
  # and Elixir lives under it, so the files were always in the sandbox's mount
  # view; only the code path was empty. Read-only, and inside the existing
  # confinement rather than a hole in it.
  #
  # ⚠️ It does **not** make arbitrary funs crossable. A fun is loadable iff its
  # *defining module* is, so `&Enum.sum/1` crosses and a closure written in a
  # test script never does -- its module exists only in the writer's VM. See
  # `fun_loadable?/2`.
  defp elixir_code_path do
    case elixir_ebin() do
      nil -> []
      path -> ["-pa", path]
    end
  end

  # Derived from the running VM rather than hardcoded: the path differs between
  # a Debian image, a Homebrew install, and an asdf shim, and a wrong literal
  # would silently leave the code path empty again.
  defp elixir_ebin do
    case :code.which(Enum) do
      path when is_list(path) -> path |> to_string() |> Path.dirname()
      _ -> nil
    end
  end

  # `Hardening.build_command/2` returns binaries, as its spec says; `:peer`
  # requires charlists. Converted at the seam rather than changing the hardening
  # contract, which several callers share and none of the others need this for.
  defp to_exec({prog, args}) do
    {String.to_charlist(prog), Enum.map(args, &String.to_charlist/1)}
  end

  # The storage the command is about to bind read-write must exist first: `bwrap`
  # refuses a bind whose source is missing ("Can't find source path ..."), so
  # every launch exited 1 while `build_command/2` was producing a correct
  # command.
  #
  # Guarded by `function_exported?/3` rather than called outright, because
  # `prepare_storage/1` is **not** part of the `ExSandbox.Hardening` behaviour --
  # it is specific to how the Linux implementation constructs confinement. A
  # mechanism whose hardening needs no pre-created directory should not be
  # obliged to define a no-op, and the substitutable fakes that make this launch
  # path testable off Linux implement only the three behaviour functions.
  defp prepare_storage(sandbox) do
    module = hardening()
    Code.ensure_loaded(module)

    if function_exported?(module, :prepare_storage, 1) do
      module.prepare_storage(sandbox)
    else
      :ok
    end
  end

  @doc false
  # Public only so it can be tested without a bootable hardened node. On a
  # non-Linux host the launch fails before reaching this gate, which left the
  # terminate-on-unverified path silently untested -- caught by mutation, where
  # replacing the whole check with `:ok` kept every test green.
  def verify_or_terminate(launched, sandbox \\ nil)

  def verify_or_terminate(%{os_pid: os_pid, node: node, peer: peer}, sandbox) do
    outcome = hardening().verify_applied(os_pid)

    # Emitted on **both** outcomes. A failure-only event leaves an operator
    # unable to tell "confinement is being verified and holding" from
    # "verification stopped running" -- identical in any dashboard that only
    # plots failures.
    if sandbox do
      ExSandbox.Telemetry.hardening_verified(
        __MODULE__,
        sandbox,
        outcome,
        case outcome do
          {:ok, applied} when is_map(applied) -> applied
          _ -> %{}
        end
      )
    end

    case outcome do
      # `{:ok, applied}` carries the limits actually in force -- the uid, the
      # cgroup's effective `memory.max` and `cpu.max`, the namespace comparisons.
      # A bare `:ok` is accepted too because the substitutable fakes return it,
      # and widening here is safer than requiring every fake to build a map it
      # has no way to populate.
      #
      # ⚠️ This clause went unreached for the whole life of the module: the pid
      # being checked was `bwrap`'s outer supervisor, so `verify_applied/1`
      # always answered `{:error, :not_applied}` and the success path was dead
      # code. Matching only `:ok` therefore crashed the first launch that
      # actually verified. Confinement failing closed is what kept that
      # invisible -- and is also why it was never a security hole.
      {:ok, applied} ->
        Logger.debug("#{node} verified confined: #{inspect(applied)}")
        :ok

      :ok ->
        :ok

      {:error, reason} ->
        # Between "we asked for confinement" and "this process is confined"
        # sits an assumption, and the entire threat model rests on it. A node
        # that asked and did not get it is more dangerous than one that never
        # launched, because everything downstream now believes it is contained.
        Logger.error("terminating #{node}: hardening did not apply (#{inspect(reason)})")
        terminate(peer, shutdown_timeout())
        {:error, :mechanism_error}
    end
  end

  @doc """
  Application-level liveness (`FR-021`).

  Separate from process monitoring because `:unresponsive` — process alive,
  control channel up, application wedged — is invisible to `:peer` (R6). A hung
  sandbox reported healthy is worse than a crashed one: it holds memory, blocks
  placement, and serves nothing.

  ⚠️ Takes the **peer pid**, not the node name, because the probe rides the stdio
  control channel. An earlier version called `:erpc.call(node, ...)`, which
  cannot reach a sandbox running under `--unshare-net` — it has no network
  interfaces — so every healthy sandbox answered `{:error, :down}` and
  `status/1` reported `:absent`.

  That was the most dangerous form of this bug: reconciliation treats `:absent`
  as "reclaim it", so the better the network isolation worked, the more certainly
  a live tenant would be torn down as an orphan. Measured: two sandboxes that had
  just provisioned successfully, with nothing else running, both reported
  `:absent` immediately.
  """
  @spec probe(pid()) :: :ok | {:error, :unresponsive | :down}
  def probe(peer) when is_pid(peer) do
    # Both checks, in this order. `Process.alive?/1` alone is not enough: after
    # the sandbox halts, the `:peer` gen_server can still be alive while its port
    # is closed, and `:peer.call/4` then raises `ArgumentError` from
    # `:erlang.port_command/2` **inside the gen_server**. That kills the peer
    # process, and the EXIT reaches anything linked to it -- so the crash lands
    # on the caller rather than in a `rescue` here, which is why the guard has to
    # come first rather than being caught after the fact.
    cond do
      not Process.alive?(peer) -> {:error, :down}
      not peer_port_open?(peer) -> {:error, :down}
      true -> do_probe(peer)
    end
  end

  defp do_probe(peer) do
    # The **return value is deliberately discarded**. A sandbox is undistributed,
    # so `is_alive/0` answers `false` on a perfectly healthy one; what this
    # probes is whether the call comes back at all, which is exactly the
    # application-level liveness `FR-021` asks for. Asserting on the result here
    # would report every healthy sandbox as dead.
    _ = :peer.call(peer, :erlang, :is_alive, [], probe_timeout())
    :ok
  rescue
    # Distinguished deliberately: `:down` is reclaimable, `:unresponsive` needs
    # terminating. Collapsing them would let wedged sandboxes accumulate.
    #
    # `ArgumentError` belongs here with the rest: once the sandbox halts, its
    # port closes, and `:peer.call/4` fails inside `:erlang.port_command/2`
    # rather than exiting. Probing a dead sandbox is an ordinary thing to do --
    # it is what `status/1` does on every reconciliation pass -- so it has to
    # come back as a value. Letting it raise would crash the caller for asking a
    # question with a perfectly good answer.
    _ in [ErlangError, ArgumentError] -> {:error, :down}
  catch
    :exit, {:timeout, _} -> {:error, :unresponsive}
    :exit, :timeout -> {:error, :unresponsive}
    :exit, _ -> {:error, :down}
  end

  @doc """
  Stop a sandbox node, releasing all its memory including its atom table
  (`FR-006`).

  Always returns `:ok`: an already-dead node is success, matching `003`'s
  idempotency rule. Escalates to an OS kill after the timeout so a wedged
  sandbox cannot block reclamation — a sandbox that ignores a graceful stop is
  precisely the one that must not be able to hold capacity forever.
  """
  @spec terminate(pid(), timeout()) :: :ok
  def terminate(peer, timeout \\ nil) do
    timeout = timeout || shutdown_timeout()

    if Process.alive?(peer) do
      # `:peer.stop/1` goes through `proc_lib.stop/3`, which blocks until the
      # target replies -- with no timeout of its own. Calling it inline would
      # mean a wedged sandbox hangs the reclamation that exists to clean it up,
      # which is the failure this function is supposed to prevent. So the
      # graceful stop runs in a task we can abandon.
      stopper =
        Task.async(fn ->
          try do
            :peer.stop(peer)
          catch
            # Already dead is already the state we wanted.
            _, _ -> :ok
          end
        end)

      case Task.yield(stopper, timeout) do
        {:ok, _} ->
          :ok

        nil ->
          Task.shutdown(stopper, :brutal_kill)
          # Escalation, per the contract: graceful first, OS kill after the
          # deadline, never an unbounded wait.
          Process.exit(peer, :kill)
      end

      await_exit(peer, timeout)
    end

    :ok
  end

  defp await_exit(peer, timeout) do
    ref = Process.monitor(peer)

    receive do
      {:DOWN, ^ref, :process, ^peer, _reason} -> :ok
    after
      timeout ->
        Process.demonitor(ref, [:flush])
        Process.exit(peer, :kill)
        :ok
    end
  end

  @doc """
  The host's pid for a sandbox spawned through `port`.

  ⚠️ Read from the **port**, never by asking the sandbox. The sandbox runs under
  `--unshare-pid`, so `:os.getpid()` inside it returns the namespace-local pid
  (`2`) while the host knows it by something else entirely (`1565` in the run
  that found this). `verify_applied/1` reads `/proc/<pid>` on the host, so the
  sandbox's own answer sends it to an unrelated process and it reports
  `:unverifiable` for a perfectly confined sandbox.

  Taking it from the port also means verification needs no cooperation from the
  thing being verified: a compromised sandbox cannot misreport its pid to escape
  the check.
  """
  @spec host_os_pid(port()) :: {:ok, pos_integer()} | {:error, term()}
  def host_os_pid(port) when is_port(port) do
    case Port.info(port, :os_pid) do
      {:os_pid, os_pid} when is_integer(os_pid) -> {:ok, os_pid}
      {:os_pid, :undefined} -> {:error, :no_os_pid}
      nil -> {:error, :port_closed}
    end
  end

  @doc """
  The host pid of the confined BEAM below `root_pid`.

  ⚠️ The port's own pid is **not** the thing to verify. The command is a chain --
  `systemd-run` execs `setpriv` execs `bwrap` -- and `bwrap` *forks*: an outer
  process stays in the origin's namespaces to supervise, and only its child
  enters the new ones. So the pid the port reports is the outer supervisor, whose
  `/proc/<pid>/ns/mnt` and `ns/net` are identical to ours.

  That made `verify_applied/1` return `:not_applied` for a sandbox that was in
  fact fully confined -- measured: the port's pid reported the origin's
  namespaces, while its grandchild `beam.smp` reported `mnt:[4026533087]`,
  `net:[4026533091]`, uid 117068, `memory.max` 268435456, and `cpu.max`
  `50000 100000`, all correct.

  This is the same class of mistake as reading `:os.getpid()` from inside the
  sandbox, one level out: a pid that is correct in one frame of reference used in
  another.

  ## Why `beam.smp` specifically, and not "a confined descendant"

  Selecting the first descendant that *looks* confined would accept a short-lived
  helper while the actual sandbox ran unconfined -- the check would pass for a
  process nobody cares about. The sandbox **is** the BEAM, so that is what must
  be named. Exactly one `beam.smp` exists in the chain; more than one means the
  tree is not the shape this reasoning assumes, and guessing between them is
  precisely what must not happen, so it is an error rather than a choice.
  """
  @spec confined_beam_pid(pos_integer()) :: {:ok, pos_integer()} | {:error, term()}
  def confined_beam_pid(root_pid) when is_integer(root_pid) do
    case Enum.filter(process_tree(root_pid), &beam?/1) do
      [pid] -> {:ok, pid}
      [] -> {:error, :no_beam_process}
      many -> {:error, {:ambiguous_beam_processes, many}}
    end
  end

  # Walks `/proc/<pid>/task/<pid>/children`, which lists direct children only.
  # Depth is bounded by the wrapper chain rather than by a guess, and a pid that
  # exits mid-walk simply contributes no children.
  defp process_tree(pid) do
    [pid | pid |> child_pids() |> Enum.flat_map(&process_tree/1)]
  end

  defp child_pids(pid) do
    case File.read("/proc/#{pid}/task/#{pid}/children") do
      {:ok, contents} -> contents |> String.split() |> Enum.map(&String.to_integer/1)
      {:error, _} -> []
    end
  end

  defp beam?(pid) do
    case File.read("/proc/#{pid}/comm") do
      {:ok, comm} -> String.trim(comm) == "beam.smp"
      {:error, _} -> false
    end
  end

  # `:peer` does not expose the port it spawned, so it comes out of the
  # `gen_server` state. Fragile by nature -- it depends on OTP's internal record
  # shape -- so it searches for *a port* rather than indexing a fixed position,
  # and every caller treats failure as a failed launch rather than assuming.
  defp peer_port(peer) do
    peer
    |> :sys.get_state()
    |> Tuple.to_list()
    |> Enum.find(&is_port/1)
    |> case do
      nil -> {:error, :no_port}
      port -> {:ok, port}
    end
  rescue
    error -> {:error, error}
  catch
    :exit, reason -> {:error, reason}
  end

  # Two steps, and both are load-bearing. The port names the head of the wrapper
  # chain on the host; `confined_beam_pid/1` walks down to the BEAM that actually
  # entered the namespaces. Neither the sandbox's own view nor the port's pid
  # alone identifies the process whose confinement must be verified -- see
  # `host_os_pid/1` and `confined_beam_pid/1`.
  #
  # Read after `:peer.start_link/1` returns, so the BEAM has booted and is
  # present in the tree; a launch that never got that far has already failed.
  # `nil` when the hardening implementation does not name its scopes -- an
  # optional capability rather than part of the behaviour, for the same reason
  # `prepare_storage/1` is: a mechanism confining by other means owes no scope.
  defp scope_unit_name(sandbox) do
    module = hardening()
    Code.ensure_loaded(module)

    if function_exported?(module, :scope_unit_name, 1) do
      module.scope_unit_name(sandbox)
    end
  end

  # The `oom_kill` count on the **parent slice** of `cgroup_path`.
  #
  # ⚠️ The parent rather than the scope itself, and that is the whole trick.
  # systemd removes a transient scope the moment its last process exits, taking
  # its `memory.events` with it -- so by the time anything notices the sandbox
  # died, the file recording *why* is gone. Measured: a tight poll never once
  # read it. The parent slice survives and its counter includes children, so the
  # cause is recoverable as a delta.
  def read_parent_oom_kills(nil), do: nil

  def read_parent_oom_kills(cgroup_path) do
    parent = Path.dirname(Path.join("/sys/fs/cgroup", cgroup_path))

    with {:ok, events} <- File.read(Path.join(parent, "memory.events")),
         [_, count] <- Regex.run(~r/^oom_kill (\d+)$/m, events) do
      String.to_integer(count)
    else
      _ -> nil
    end
  end

  # The sandbox's cgroup scope, read while it still has a `/proc` entry. Returns
  # `nil` rather than raising: a host without cgroup v2 has no path to record,
  # and that is an ordinary outcome rather than a failed launch.
  defp read_cgroup_path(os_pid) do
    with {:ok, contents} <- File.read("/proc/#{os_pid}/cgroup"),
         [_, path] <- Regex.run(~r{^0::(.+)$}m, String.trim(contents)) do
      path
    else
      _ -> nil
    end
  end

  # A `:peer` gen_server outlives its port when the sandbox halts, so liveness of
  # the process says nothing about whether the control channel still exists.
  defp peer_port_open?(peer) do
    case peer_port(peer) do
      {:ok, port} -> Port.info(port) != nil
      {:error, _} -> false
    end
  end

  defp os_pid(peer) do
    with {:ok, port} <- peer_port(peer),
         {:ok, root_pid} <- host_os_pid(port) do
      confined_beam_pid(root_pid)
    end
  end

  defp beam_config, do: Application.get_env(:ex_sandbox, :beam, [])
  defp wait_boot_timeout, do: Keyword.get(beam_config(), :wait_boot_timeout_ms, 15_000)
  defp shutdown_timeout, do: Keyword.get(beam_config(), :shutdown_timeout_ms, 5_000)
  defp probe_timeout, do: Keyword.get(beam_config(), :probe_timeout_ms, 5_000)
end
