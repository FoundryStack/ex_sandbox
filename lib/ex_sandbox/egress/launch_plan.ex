defmodule ExSandbox.Egress.LaunchPlan do
  @moduledoc """
  The ordered steps that put a tenant process inside a policed namespace
  (005 T060a3, `contracts/egress.md`; D6 of `let-sandboxes-outlive-a-deploy`).

  1. **launch** -- the confinement command runs unchanged, so `bwrap
     --unshare-net` starts the tenant in a namespace with loopback only and no
     route out,
  2. **find the holder** -- the confined BEAM, whose host pid the launcher
     already reads, refused if it shares our network namespace,
  3. **police** -- the gateway binds the acceptor and the resolver inside that
     namespace, installs the redirect, and adds the default route last.

  Until the route lands every outbound connect fails with `enetunreach`, so the
  window between launch and policing fails closed by construction. The
  connections themselves leave from the gateway's own namespace: the acceptor
  reads `SO_ORIGINAL_DST`, `ExSandbox.Egress.Decision` judges it, and
  `ExSandbox.Egress.Relay` dials the destination from the host.

  ## Why this is a plan rather than a launch

  It composes commands and does not run them, so the ordering is testable on a
  host where none of these commands can execute.

  ## Why a missing `--unshare-net` is refused

  Handed a command that never confined the network, this module has no way to
  police it: the tenant would run with the host's own network. Refusing is the
  only answer that cannot be wrong.
  """

  alias ExSandbox.Egress.Netns
  alias ExSandbox.Egress.Policy
  alias ExSandbox.Egress.Resolver

  @typedoc "Why a plan could not be built."
  @type refusal :: :no_network_confinement | :no_pool_port | :no_privilege_drop

  @type t :: %__MODULE__{
          source_key: Policy.source_key(),
          tenant_command: [String.t()],
          pool_port: :inet.port_number(),
          resolver: Netns.resolver(),
          forward: Netns.forward()
        }

  defstruct [
    :source_key,
    :tenant_command,
    :pool_port,
    :resolver,
    :forward
  ]

  @doc """
  Builds the plan for one sandbox, or refuses.

  `tenant_command` is the fully composed confinement command -- the output of
  `ExSandbox.Hardening.Linux.build_command/2` -- and is launched as it is.

  ## Options

    * `:resolver` -- `{address, port}` a sandbox may send UDP to, or `nil` for
      none. Defaults to `ExSandbox.Egress.Resolver.resolver_address/0`.
      ⚠️ **`nil` drops all UDP**, which includes DNS.
      ⚠️ An address that cannot be read **raises**, at build time rather than
      after the tenant is running.
    * `:forward` -- `{host_port, ns_port}` pairs, primary first, published on
      host loopback by the acceptor, or `nil` (the default) for none. A single
      legacy pair is accepted too.
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
         :ok <- require_privilege_drop(tenant_command) do
      resolver = Netns.validate_resolver!(Keyword.get_lazy(opts, :resolver, &default_resolver/0))

      {:ok,
       %__MODULE__{
         source_key: source_key,
         tenant_command: tenant_command,
         pool_port: pool_port,
         resolver: resolver,
         forward: Keyword.get(opts, :forward)
       }}
    else
      false -> {:error, :no_network_confinement}
      {:error, reason} -> {:error, reason}
    end
  end

  # A command with no privilege drop runs its tenant as root, which is a worse
  # thing to launch than nothing at all.
  defp require_privilege_drop(command) do
    case Enum.drop_while(command, &(&1 != "setpriv")) do
      ["setpriv" | rest] ->
        if Enum.any?(Enum.take_while(rest, &String.starts_with?(&1, "-")), &reuid?/1),
          do: :ok,
          else: {:error, :no_privilege_drop}

      [] ->
        {:error, :no_privilege_drop}
    end
  end

  defp reuid?("--reuid=" <> value), do: match?({uid, ""} when uid >= 0, Integer.parse(value))
  defp reuid?(_flag), do: false

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
  def redirect_steps(
        %__MODULE__{
          source_key: source_key,
          pool_port: pool_port,
          resolver: resolver,
          forward: forward
        },
        holder_pid
      ) do
    Netns.redirect_commands(holder_pid, pool_port, resolver, forward) ++
      Netns.route_commands(holder_pid, Netns.addresses(source_key).sandbox)
  end

  # ⚠️ Read through `ExSandbox.Egress.Resolver` rather than from configuration
  # directly, so the address the rule permits and the address the resolver is
  # actually served at are **one** value. Two reads of the same config key are
  # two things that must agree forever, and the symptom of them drifting is a
  # sandbox whose only permitted UDP destination is not where anything is
  # listening -- every denial check green, DNS silently dead.
  defp default_resolver, do: Resolver.resolver_address()
end
