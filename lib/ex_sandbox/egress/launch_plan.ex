defmodule ExSandbox.Egress.LaunchPlan do
  @moduledoc """
  The ordered steps that put a tenant process inside a policed namespace
  (005 T060a3, `contracts/egress.md` §Lifecycle).

  ## Why this is a plan rather than a launch

  `ExSandbox.Egress.Netns` builds commands and deliberately does not run them.
  This composes them into an order and deliberately does not run them either.
  The value of stopping here is that the *ordering* — the part that cannot be
  checked by inspecting any single command — becomes testable on a host where
  none of these commands can execute, which is every developer machine that is
  not Linux.

  ## What replaces `--unshare-net`, and why it is not simply dropped

  `--unshare-net` gives the tenant a namespace with **no interfaces**. The
  policed namespace is configured *before* the tenant starts, so the tenant
  must **join** it rather than unshare a new one.

  ⚠️ Leaving `--unshare-net` in place alongside the join is the failure worth
  naming: `bwrap` would put the tenant in a fresh empty namespace instead of the
  configured one. The policy would be installed correctly, on a namespace
  nothing uses, and every denial check would still pass — because an empty
  namespace denies everything too. `build/3` therefore removes the flag rather
  than expecting a caller to have done it.

  ## Why a missing `--unshare-net` is refused

  This module *replaces* an existing confinement. Handed a command that never
  confined the network, it has no way to tell "already converted" from "never
  confined", and the second is a command that would launch a tenant with the
  host's own network. Refusing is the only answer that cannot be wrong.
  """

  alias ExSandbox.Egress.Netns
  alias ExSandbox.Egress.Policy

  @typedoc "Why a plan could not be built."
  @type refusal :: :no_network_confinement | :no_pool_port

  @type t :: %__MODULE__{
          netns_name: String.t(),
          source_key: Policy.source_key(),
          setup_steps: [[String.t()]],
          pasta_command: [String.t()],
          tenant_command: [String.t()]
        }

  defstruct [:netns_name, :source_key, :setup_steps, :pasta_command, :tenant_command]

  @doc """
  Builds the ordered plan for one sandbox, or refuses.

  `tenant_command` is the fully composed confinement command — the output of
  `ExSandbox.Hardening.Linux.build_command/2` — which this rewrites to join the
  policed namespace instead of unsharing an empty one.
  """
  @spec build(Policy.source_key(), :inet.port_number(), [String.t()], keyword()) ::
          {:ok, t()} | {:error, refusal()}
  def build(source_key, pool_port, tenant_command, opts \\ [])

  def build(_source_key, pool_port, _tenant_command, _opts)
      when not is_integer(pool_port) or pool_port <= 0 do
    # ⚠️ A pool that failed to bind reports port 0. A redirect to port 0 sends
    # the namespace's traffic nowhere, which from inside the sandbox is
    # indistinguishable from a correctly denied destination -- so the denial
    # checks pass and the reachability checks fail for a reason no one would
    # look for here.
    {:error, :no_pool_port}
  end

  def build(source_key, pool_port, tenant_command, opts) when is_list(tenant_command) do
    if "--unshare-net" in tenant_command do
      name = Keyword.get(opts, :netns_name, netns_name(source_key))

      {:ok,
       %__MODULE__{
         netns_name: name,
         source_key: source_key,
         setup_steps: setup_steps(name, source_key, pool_port, opts),
         pasta_command: Netns.pasta_command(netns_path(name), opts),
         tenant_command: join_netns(tenant_command, name)
       }}
    else
      {:error, :no_network_confinement}
    end
  end

  @doc """
  The namespace name for a sandbox's /30.

  Derived from the address rather than from the sandbox id: the /30 is what the
  policy is keyed by, so a name derived from it cannot drift from the identity
  the pool enforces against.
  """
  @spec netns_name(Policy.source_key()) :: String.t()
  def netns_name({a, b, c, d}), do: "sb-#{a}-#{b}-#{c}-#{d}"

  @doc "Where the kernel exposes a named namespace."
  @spec netns_path(String.t()) :: String.t()
  def netns_path(name), do: "/var/run/netns/#{name}"

  # Each step is run *inside* the namespace, so every one carries the name --
  # which is also what the test asserts, because a plan that configures one
  # namespace and launches into another installs a correct policy on a
  # namespace nothing uses.
  defp setup_steps(name, source_key, pool_port, opts) do
    [["ip", "netns", "add", name]] ++
      Enum.map(Netns.setup_commands(source_key, pool_port, opts), fn command ->
        ["ip", "netns", "exec", name] ++ command
      end)
  end

  # ⚠️ `--unshare-net` is *removed*, not merely supplemented. See the moduledoc:
  # keeping it would place the tenant in a fresh empty namespace while the
  # policy sat on the configured one, and nothing downstream could tell.
  defp join_netns(tenant_command, name) do
    tenant_command
    |> Enum.reject(&(&1 == "--unshare-net"))
    |> replace_bwrap_netns(name)
  end

  # `bwrap` joins an existing namespace with `--userns-block-fd`-style plumbing
  # in some versions; the portable spelling is to run the whole confinement
  # under `ip netns exec`, which sets the namespace before `bwrap` starts.
  #
  # Chosen over a `bwrap`-native flag deliberately: `--netns` is not present in
  # every packaged `bwrap`, and a flag that is silently ignored by an older
  # build would leave the tenant in the host's namespace while the command
  # still looked correct.
  defp replace_bwrap_netns(tenant_command, name) do
    ["ip", "netns", "exec", name] ++ tenant_command
  end
end
