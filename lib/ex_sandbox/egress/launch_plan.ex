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

  @typedoc "Why a plan could not be built."
  @type refusal :: :no_network_confinement | :no_pool_port

  @type t :: %__MODULE__{
          source_key: Policy.source_key(),
          pidfile: String.t(),
          pasta_command: [String.t()],
          tenant_command: [String.t()],
          pool_port: :inet.port_number()
        }

  defstruct [:source_key, :pidfile, :pasta_command, :tenant_command, :pool_port]

  @doc """
  Builds the plan for one sandbox, or refuses.

  `tenant_command` is the fully composed confinement command — the output of
  `ExSandbox.Hardening.Linux.build_command/2` — which this rewrites to run
  under `pasta` instead of unsharing an empty namespace.
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
    if "--unshare-net" in tenant_command do
      inner = Enum.reject(tenant_command, &(&1 == "--unshare-net"))
      pidfile = Keyword.get(opts, :pidfile, default_pidfile(source_key))

      {:ok,
       %__MODULE__{
         source_key: source_key,
         pidfile: pidfile,
         pasta_command: Netns.pasta_command(pidfile, inner),
         tenant_command: inner,
         pool_port: pool_port
       }}
    else
      {:error, :no_network_confinement}
    end
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
  def redirect_steps(%__MODULE__{pool_port: pool_port}, holder_pid) do
    Netns.redirect_commands(holder_pid, pool_port)
  end

  @doc """
  Where `pasta` records its host-side pid for this sandbox.

  ⚠️ The file contains **pasta's** pid, not the tenant's. See
  `ExSandbox.Egress.Pasta` for why the difference is a silent catastrophe
  rather than a detail.
  """
  @spec default_pidfile(Policy.source_key()) :: String.t()
  def default_pidfile({a, b, c, d}), do: "/var/run/axonn-pasta-#{a}-#{b}-#{c}-#{d}.pid"
end
