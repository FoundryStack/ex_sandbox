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
          namespace: String.t(),
          setup_steps: [[String.t()]],
          teardown_steps: [[String.t()]],
          tenant_command: [String.t()],
          pool_port: :inet.port_number()
        }

  defstruct [
    :source_key,
    :namespace,
    :setup_steps,
    :teardown_steps,
    :tenant_command,
    :pool_port
  ]

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
      # ⚠️ Removed, not supplemented. Keeping it would put the tenant in a fresh
      # **empty** namespace while the policy sat on the configured one --
      # isolation restored silently, policy discarded, and every denial check
      # still green, because an empty namespace denies everything too.
      inner = Enum.reject(tenant_command, &(&1 == "--unshare-net"))
      name = Keyword.get(opts, :name, Netns.namespace_name(source_key))

      {:ok,
       %__MODULE__{
         source_key: source_key,
         namespace: name,
         setup_steps: Netns.setup_commands(source_key, pool_port, name: name),
         teardown_steps: Netns.teardown_commands(source_key, name: name),
         tenant_command: Netns.in_namespace(source_key, inner, name: name),
         pool_port: pool_port
       }}
    else
      {:error, :no_network_confinement}
    end
  end

  @doc """
  Whether every setup step runs against this plan's own namespace.

  ⚠️ A step that names a different namespace -- or none -- configures the
  **host**. On a developer machine that fails; on the isolation host it
  *succeeds*, and the sandbox is policed by rules installed on the wrong
  network stack while the host acquires a NAT rule redirecting its own traffic.

  Exposed as a predicate rather than left implicit so the property is testable
  where the commands cannot run, which is every host that is not Linux.
  """
  @spec namespaced?(t()) :: boolean()
  def namespaced?(%__MODULE__{namespace: name, setup_steps: steps}) do
    Enum.all?(steps, fn step ->
      case step do
        ["ip", "netns", "add", ^name] -> true
        ["ip", "netns", "exec", ^name | _] -> true
        # The veth pair and the host-side address are created in the host
        # namespace by necessity -- the pair must exist before either end can
        # be moved -- so they are the deliberate exceptions.
        ["ip", "link", "add" | _] -> true
        ["ip", "link", "set", _if, "netns", ^name] -> true
        ["ip", "addr", "add", _addr, "dev", _if] -> true
        ["ip", "link", "set", _if, "up"] -> true
        _ -> false
      end
    end)
  end
end
