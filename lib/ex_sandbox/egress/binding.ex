defmodule ExSandbox.Egress.Binding do
  @moduledoc """
  Ties one sandbox's resolved allowlist to the `/30` its traffic arrives from,
  and takes both back together (005 T060a2/T060a6, `005-FR-011a`–`FR-011e`).

  ## Why the pair is a module rather than two calls

  Acquiring an address and registering a policy are two operations that must
  succeed or fail as one. Split across a caller they are two lines that read
  independently and can be reordered, half-applied, or partly rolled back — and
  every one of those states is *silent*:

    * address without policy: the sandbox is denied everything, which is
      indistinguishable from correct operation under checks that test denial,
    * policy without address: the entry is filed under a `/30` no sandbox will
      ever send from, so it enforces nothing and never expires,
    * released address with a live policy: the next tenant to receive that
      `/30` inherits it (`ExSandbox.Egress.Registry`'s reuse race).

  `acquire/2` rolls the address back if registration fails, so the pool never
  holds an entry the caller does not know about.

  ## Ordering on the way out

  `release/2` drops the **policy first**, then the address — and passes the
  registry check to `ExSandbox.Egress.Allocator.release/3` as a predicate
  rather than relying on having done it. If a later refactor reorders these two
  lines the allocator still refuses to recycle a `/30` whose policy stands, and
  the address stays out rather than being handed to the next tenant. That is
  the difference between an invariant and a comment.
  """

  alias ExSandbox.Egress.Allocator
  alias ExSandbox.Egress.Netns
  alias ExSandbox.Egress.Policy
  alias ExSandbox.Egress.Registry, as: EgressRegistry

  @typedoc """
  What a launched sandbox needs to build its namespace, and what a destroyed
  one needs to give back.
  """
  @type t :: %__MODULE__{
          source_key: Policy.source_key(),
          sandbox_address: String.t(),
          gateway_address: String.t()
        }

  @enforce_keys [:source_key, :sandbox_address, :gateway_address]
  defstruct [:source_key, :sandbox_address, :gateway_address]

  @doc """
  Takes a `/30` and files `allowed` under it.

  Refuses with `{:error, :pool_exhausted}` rather than issuing an unpoliced
  sandbox: a tenant who cannot be given a policy must not be given a sandbox
  that reaches everything instead.
  """
  @spec acquire([Policy.destination()], keyword()) :: {:ok, t()} | {:error, Allocator.refusal()}
  def acquire(allowed, opts \\ []) when is_list(allowed) do
    allocator = Keyword.get(opts, :allocator, Allocator)
    registry = Keyword.get(opts, :registry, EgressRegistry)

    with {:ok, source_key} <- Allocator.acquire(allocator) do
      case EgressRegistry.assign(source_key, allowed, registry) do
        :ok ->
          %{gateway: gateway, sandbox: sandbox} = Netns.addresses(source_key)

          {:ok,
           %__MODULE__{
             source_key: source_key,
             sandbox_address: sandbox,
             gateway_address: gateway
           }}

        {:error, reason} ->
          # ⚠️ Rolled back rather than left held. A `/30` the caller never
          # learned about is one the pool can never reissue -- a leak that looks
          # like a capacity problem 64 provisions later. The predicate still
          # guards the recycle, so a genuinely-registered address stays out.
          _ = Allocator.release(source_key, &policy_gone?(&1, registry), allocator)
          {:error, reason}
      end
    end
  end

  @doc """
  Gives back the policy and then the `/30`.

  Idempotent, and safe for a binding this host never issued (`003-FR-013`):
  destroy runs for sandboxes that failed to provision, and runs twice for
  sandboxes that did.
  """
  @spec release(t(), keyword()) :: :ok
  def release(%__MODULE__{source_key: source_key}, opts \\ []) do
    allocator = Keyword.get(opts, :allocator, Allocator)
    registry = Keyword.get(opts, :registry, EgressRegistry)

    # Policy first. The allocator re-checks rather than trusting this line --
    # see the moduledoc on why the ordering is a predicate, not a convention.
    :ok = EgressRegistry.release(source_key, registry)
    Allocator.release(source_key, &policy_gone?(&1, registry), allocator)
  end

  defp policy_gone?(source_key, registry) do
    not EgressRegistry.registered?(source_key, registry)
  end
end
