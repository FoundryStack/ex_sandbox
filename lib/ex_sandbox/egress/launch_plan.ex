defmodule ExSandbox.Egress.LaunchPlan do
  @moduledoc """
  The ordered steps that put a tenant process inside a policed namespace
  (005 T060a3, `contracts/egress.md` §Lifecycle).

  ## The order, and why it inverted

  The first version of this module created a named namespace, configured it,
  and had the tenant join it — all before the tenant started. **That order is
  not reachable**: `pasta` cannot join a namespace made by `ip netns add`
  (measured, `egress-path-measurements.md` defect 3), and a tenant inside
  `pasta`'s namespace has no `CAP_NET_ADMIN` to configure it from within
  (defect 4). The reachable order is:

  1. **launch** — `pasta` creates the namespace, configures it, and starts the
     tenant inside it,
  2. **find the holder** — the tenant's pid, *not* pasta's (see
     `ExSandbox.Egress.Pasta`),
  3. **police** — the host installs the redirect into that namespace.

  ⚠️ **The tenant is running, unpoliced, between steps 1 and 3.** That window
  is real and cannot be closed by reordering, because the namespace does not
  exist until the tenant is in it. It is closed instead by what `pasta` gives
  the namespace: the tenant's only route out is `pasta` itself, and until the
  redirect lands, `Egress.Acceptor` is not listening, so a connection in that
  window reaches nothing. The window fails *closed*, and
  `ExSandbox.Egress.Verification` exists to confirm that rather than assume it.

  ## Why this is a plan rather than a launch

  It composes commands and does not run them. The value of stopping here is
  that the *ordering* — the part that cannot be checked by inspecting any
  single command — becomes testable on a host where none of these commands can
  execute, which is every developer machine that is not Linux.

  ## Why a missing `--unshare-net` is refused

  This module *replaces* an existing confinement. Handed a command that never
  confined the network, it has no way to tell "already converted" from "never
  confined", and the second is a command that would launch a tenant with the
  host's own network. Refusing is the only answer that cannot be wrong.

  ⚠️ `--unshare-net` is *removed*, not supplemented. Keeping it would put the
  tenant in a fresh **empty** namespace while `pasta` configured a different
  one — isolation restored silently, policy discarded, and every denial check
  still green, because an empty namespace denies everything too.
  """

  alias ExSandbox.Egress.Netns
  alias ExSandbox.Egress.Policy
  alias ExSandbox.Egress.Resolver

  @typedoc "Why a plan could not be built."
  @type refusal :: :no_network_confinement | :no_pool_port | :no_privilege_drop

  @type t :: %__MODULE__{
          source_key: Policy.source_key(),
          pidfile: String.t(),
          pasta_command: [String.t()],
          tenant_command: [String.t()],
          pool_port: :inet.port_number(),
          resolver: Netns.resolver()
        }

  defstruct [:source_key, :pidfile, :pasta_command, :tenant_command, :pool_port, :resolver]

  @doc """
  Builds the plan for one sandbox, or refuses.

  `tenant_command` is the fully composed confinement command — the output of
  `ExSandbox.Hardening.Linux.build_command/2` — which this rewrites to run
  under `pasta` instead of unsharing an empty namespace.

  ## Options

    * `:pidfile` — where `pasta` records its host-side pid.
    * `:resolver` — `{address, port}` a sandbox may send UDP to, or `nil` for
      none. Defaults to `ExSandbox.Egress.Resolver.resolver_address/0`.
      ⚠️ **`nil` drops all UDP**, which includes DNS. That is default-deny and
      not a degradation, but it is not a resolver either: pass `nil` only when
      the sandbox is meant to have no name resolution at all.
      ⚠️ An address that cannot be read **raises** — see the note at the call
      site.
  """
  @spec build(Policy.source_key(), :inet.port_number(), [String.t()], keyword()) ::
          {:ok, t()} | {:error, refusal()}
  def build(source_key, pool_port, tenant_command, opts \\ [])

  def build(_source_key, pool_port, _tenant_command, _opts)
      when not is_integer(pool_port) or pool_port <= 0 do
    # ⚠️ An acceptor that failed to bind reports port 0. A redirect to port 0
    # sends the namespace's traffic nowhere, which from inside the sandbox is
    # indistinguishable from a correctly denied destination -- so the denial
    # checks pass and the reachability checks fail for a reason no one would
    # look for here.
    {:error, :no_pool_port}
  end

  def build(source_key, pool_port, tenant_command, opts) when is_list(tenant_command) do
    with true <- "--unshare-net" in tenant_command,
         inner = Enum.reject(tenant_command, &(&1 == "--unshare-net")),
         {:ok, {outer, uid, rest}} <- split_at_privilege_drop(inner) do
      pidfile = Keyword.get(opts, :pidfile, default_pidfile(source_key))
      runas = Netns.runas_for_uid(uid)

      # ⚠️ **Validated HERE, at build time, and it raises.** The address is read
      # from configuration, so a typo in it is a deployment mistake rather than
      # a tenant input -- and the two available wrong answers are both worse
      # than an exception. Degrading to "no exemption" produces a sandbox with
      # **no DNS** whose rules all installed cleanly, which is indistinguishable
      # from one that was never given a resolver and reads as a working launch.
      # Deferring the check to `redirect_steps/2` would raise *after* the tenant
      # is already running, converting a configuration error into a terminated
      # sandbox.
      resolver = Netns.validate_resolver!(Keyword.get_lazy(opts, :resolver, &default_resolver/0))

      {:ok,
       %__MODULE__{
         source_key: source_key,
         pidfile: pidfile,
         pasta_command: outer ++ Netns.pasta_command(pidfile, rest, runas),
         tenant_command: inner,
         pool_port: pool_port,
         resolver: resolver
       }}
    else
      false -> {:error, :no_network_confinement}
      {:error, reason} -> {:error, reason}
    end
  end

  # The split, and why `pasta` is inserted rather than prefixed.
  #
  # ⚠️ This function exists because the obvious shape -- wrapping the whole
  # confined command in `pasta` -- **cannot boot a tenant**, measured:
  #
  #     pasta -- systemd-run --scope setpriv --reuid=N bwrap … erlexec
  #     -> Couldn't write to /proc/self/uid_map: Operation not permitted
  #     -> setpriv: setresuid failed: Invalid argument
  #     -> {:boot_failed, {:exit_status, 127}}
  #
  # `pasta` in spawn mode always creates its own user namespace, and as root
  # with no subuid range it cannot write that namespace's `uid_map`. The map is
  # left **empty**, so every process inside is uid 65534 and `setpriv --reuid`
  # fails with `EINVAL` for *any* uid -- there is no other uid to become.
  #
  # So `pasta` goes **after** the privilege drop and **inside** the scope:
  #
  #     systemd-run --scope -p MemoryMax=… -- setpriv --reuid=N …
  #       pasta --config-net --runas N:N -- bwrap … erlexec
  #
  # ⚠️ Both halves of that were measured, not reasoned, because both failure
  # modes are invisible to a suite that tests only denial
  # (`docker/launch-ordering-probe.sh`, recorded in
  # `egress-path-measurements.md`):
  #
  #   * `pasta` composes after the drop: `uid_map = 0 112526 1`, its own netns.
  #   * the scope's caps still bind across **two** intervening execs: a 192MB
  #     allocation under a 64M cap is SIGKILLed. `005` R9b is the recorded case
  #     of a cap applied with the right number and silently lost across an exec,
  #     and this shape adds two more of them.
  #
  # ⚠️ A command with no privilege drop is **refused**, never prefixed as a
  # fallback. Falling back would reintroduce the unbootable ordering on exactly
  # the hosts where the split failed, and it would do so silently -- and a
  # command that never dropped privilege is one whose tenant runs as root, which
  # is a worse thing to launch than nothing at all.
  defp split_at_privilege_drop(inner) do
    case Enum.split_while(inner, &(&1 != "setpriv")) do
      {_outer, []} ->
        {:error, :no_privilege_drop}

      {outer, ["setpriv" | _] = drop_and_rest} ->
        case split_after_drop_args(drop_and_rest) do
          {:ok, drop_args, rest, uid} -> {:ok, {outer ++ drop_args, uid, rest}}
          :error -> {:error, :no_privilege_drop}
        end
    end
  end

  # `setpriv`'s own flags all begin with `-`; the first argument that does not is
  # the program it execs, which is where `pasta` must be inserted.
  #
  # The uid is read back out of `--reuid=N` rather than passed in, so `--runas`
  # cannot disagree with the uid actually being dropped to. A mismatch there does
  # not fail loudly: `pasta` would map a uid the tenant never becomes, and the
  # namespace would come up owned by nobody in particular.
  defp split_after_drop_args(["setpriv" | rest]) do
    {flags, program} = Enum.split_while(rest, &String.starts_with?(&1, "-"))

    with [_ | _] <- program,
         {:ok, uid} <- reuid_from(flags) do
      {:ok, ["setpriv" | flags], program, uid}
    else
      _ -> :error
    end
  end

  defp reuid_from(flags) do
    Enum.find_value(flags, :error, fn flag ->
      case flag do
        "--reuid=" <> value ->
          case Integer.parse(value) do
            {uid, ""} -> {:ok, uid}
            _ -> nil
          end

        _ ->
          nil
      end
    end)
  end

  @doc """
  The redirect steps for a plan, once the namespace holder is known.

  ⚠️ Deliberately **not** a field on the struct. The holder pid does not exist
  when the plan is built — the namespace it names is created by running the
  plan. A field would have to be `nil` at build time and filled in later, and
  the failure mode of that shape is a plan whose steps were composed against
  `nil` and quietly target the wrong namespace.

  Requiring the pid as an argument means there is no way to ask for these
  commands without having one.
  """
  @spec redirect_steps(t(), pos_integer()) :: [[String.t()]]
  def redirect_steps(%__MODULE__{pool_port: pool_port, resolver: resolver}, holder_pid) do
    Netns.redirect_commands(holder_pid, pool_port, resolver)
  end

  # ⚠️ Read through `ExSandbox.Egress.Resolver` rather than from configuration
  # directly, so the address the rule permits and the address the resolver is
  # actually served at are **one** value. Two reads of the same config key are
  # two things that must agree forever, and the symptom of them drifting is a
  # sandbox whose only permitted UDP destination is not where anything is
  # listening -- every denial check green, DNS silently dead.
  defp default_resolver, do: Resolver.resolver_address()

  @doc """
  Where `pasta` records its host-side pid for this sandbox.

  ⚠️ The file contains **pasta's** pid, not the tenant's. See
  `ExSandbox.Egress.Pasta` for why the difference is a silent catastrophe
  rather than a detail.
  """
  @spec default_pidfile(Policy.source_key()) :: String.t()
  def default_pidfile({a, b, c, d}),
    do: Path.join(pidfile_dir(), "axonn-pasta-#{a}-#{b}-#{c}-#{d}.pid")

  # ⚠️ NOT `/var/run`, and the reason is a direct consequence of the split
  # ordering (T060a4e).
  #
  # While `pasta` wrapped the whole command it ran **as root**, so a root-owned
  # `/var/run` was writable and this path worked. Inserting `pasta` after
  # `setpriv` means it now runs as the *sandbox uid*, and the first container run
  # after the reorder failed with:
  #
  #     Couldn't open PID file /var/run/axonn-pasta-10-0-0-0.pid: Permission denied
  #     [error] sandbox node failed to boot: {:boot_failed, {:exit_status, 1}}
  #
  # ⚠️ This is exactly the class of consequence that command inspection cannot
  # find. Every ordering assertion in the egress suite passed against the
  # command that produced this, because the command was *right* -- what changed
  # was which uid executed one of its parts, and no amount of reading the
  # argument list reveals that. It took running the launch.
  #
  # `/tmp` is world-writable with the sticky bit, so the dropped uid can create
  # its file and no other uid can replace it. The BEAM (still root) reads it
  # back. `Policy.source_key/1` makes the name unique per sandbox, so two
  # sandboxes cannot collide on one file -- which would be worse than a
  # permission error, since the host would then search the wrong process's
  # children and find nothing, reading as an architectural refusal.
  defp pidfile_dir do
    Application.get_env(:ex_sandbox, :egress, [])
    |> Keyword.get(:pidfile_dir, "/tmp")
  end
end
