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
  @type launched :: %{node: node(), os_pid: integer(), peer: pid(), cookie: atom()}

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
         {:ok, exec} <- hardening().build_command(sandbox, granted_env),
         {:ok, launched} <- start_peer(sandbox, exec),
         :ok <- verify_or_terminate(launched) do
      {:ok, launched}
    end
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
      name: node_name(sandbox),
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
      do_start_peer(options, cookie)
    catch
      :exit, reason ->
        Logger.error("sandbox node failed to boot: #{inspect(reason)}")
        {:error, :mechanism_error}
    end
  end

  defp do_start_peer(options, cookie) do
    case :peer.start_link(options) do
      {:ok, peer, node} ->
        case os_pid(node) do
          {:ok, os_pid} ->
            {:ok, %{node: node, os_pid: os_pid, peer: peer, cookie: cookie}}

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
    Enum.map(
      ["-setcookie", Atom.to_string(cookie), "-hidden", "-connect_all", "false"],
      &String.to_charlist/1
    )
  end

  # `Hardening.build_command/2` returns binaries, as its spec says; `:peer`
  # requires charlists. Converted at the seam rather than changing the hardening
  # contract, which several callers share and none of the others need this for.
  defp to_exec({prog, args}) do
    {String.to_charlist(prog), Enum.map(args, &String.to_charlist/1)}
  end

  defp node_name(%Sandbox{id: id}), do: :"sandbox-#{id}"

  @doc false
  # Public only so it can be tested without a bootable hardened node. On a
  # non-Linux host the launch fails before reaching this gate, which left the
  # terminate-on-unverified path silently untested -- caught by mutation, where
  # replacing the whole check with `:ok` kept every test green.
  def verify_or_terminate(%{os_pid: os_pid, node: node, peer: peer}) do
    case hardening().verify_applied(os_pid) do
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
  distribution up, application wedged — is invisible to `:peer` (R6). A hung
  sandbox reported healthy is worse than a crashed one: it holds memory, blocks
  placement, and serves nothing.
  """
  @spec probe(node()) :: :ok | {:error, :unresponsive | :down}
  def probe(node) do
    :erpc.call(node, :erlang, :is_alive, [], probe_timeout())
    :ok
  rescue
    # Distinguished deliberately: `:down` is reclaimable, `:unresponsive` needs
    # terminating. Collapsing them would let wedged sandboxes accumulate.
    _ in ErlangError -> {:error, :down}
  catch
    :exit, {:erpc, :timeout} -> {:error, :unresponsive}
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

  defp os_pid(node) do
    case :erpc.call(node, :os, :getpid, [], probe_timeout()) do
      pid when is_list(pid) -> {:ok, List.to_integer(pid)}
      other -> {:error, {:unexpected_pid, other}}
    end
  rescue
    error -> {:error, error}
  catch
    :exit, reason -> {:error, reason}
  end

  defp beam_config, do: Application.get_env(:ex_sandbox, :beam, [])
  defp wait_boot_timeout, do: Keyword.get(beam_config(), :wait_boot_timeout_ms, 15_000)
  defp shutdown_timeout, do: Keyword.get(beam_config(), :shutdown_timeout_ms, 5_000)
  defp probe_timeout, do: Keyword.get(beam_config(), :probe_timeout_ms, 5_000)
end
