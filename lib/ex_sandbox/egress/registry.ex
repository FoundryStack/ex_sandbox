defmodule ExSandbox.Egress.Registry do
  @moduledoc """
  Holds each running sandbox's egress policy, keyed by its source /30
  (005 T060a1/T060a6, `005-FR-011a`–`FR-011e`).

  ## The one way this design can leak across tenants

  Everything else here is protected by topology: no sandbox has a route to any
  other, and identity is the kernel's view of the source address. Those hold
  continuously. **Address reuse does not** — it is a lifecycle race, and it is
  the single point where one tenant can inherit another's allowlist.

  The sequence is:

    1. sandbox A holds `10.0.0.0/30` with A's allowlist,
    2. A is destroyed and its /30 returns to the pool,
    3. sandbox B is provisioned and assigned `10.0.0.0/30`,
    4. B connects — and if A's entry is still registered, **B gets A's
       allowlist**.

  ⚠️ Note what makes this dangerous rather than merely wrong: every outward
  check still passes. B reaches destinations, denied destinations are refused,
  the policy is not editable from inside. The allowlist being enforced is simply
  the *wrong tenant's*. Nothing outward-facing distinguishes that from correct
  operation, which is why it is enforced structurally below rather than by an
  ordering convention in `destroy`.

  ## The invariant

  **A /30 is not available for assignment until its policy entry is gone.**
  `release/1` deletes the entry and only then returns the /30 to the pool;
  `assign/2` refuses a /30 that still carries one. Both are enforced here rather
  than left to callers, because the correct ordering in a `destroy` callback is
  exactly the kind of thing a later refactor reorders without knowing why it was
  written that way.
  """

  use GenServer

  alias ExSandbox.Egress.Policy

  @typedoc "Why an assignment was refused. Distinguishable by construction."
  @type refusal :: {:still_registered, Policy.source_key()} | :pool_exhausted

  @name __MODULE__

  # -- Public interface -----------------------------------------------------

  @doc false
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, @name))
  end

  @doc """
  Assigns `source_key` to a sandbox with the given allowlist.

  Refuses with `{:error, {:still_registered, key}}` when the /30 still carries a
  previous tenant's policy — see the invariant above.
  """
  @spec assign(Policy.source_key(), [Policy.destination()], GenServer.server()) ::
          :ok | {:error, refusal()}
  def assign(source_key, allowed, server \\ @name) do
    GenServer.call(server, {:assign, source_key, allowed})
  end

  @doc """
  Returns the allowlist for `source_key`, or `[]` when none is registered.

  ⚠️ `[]` rather than an error, and rather than `nil`. An unregistered source
  must be *denied*, and `Policy.permits?/2` denies `[]` — so the miss path and
  the deny path are the same path. Returning an error would invite a caller to
  handle it, and the tempting handling is to let the connection through while
  logging.
  """
  @spec lookup(Policy.source_key(), GenServer.server()) :: [Policy.destination()]
  def lookup(source_key, server \\ @name) do
    GenServer.call(server, {:lookup, source_key})
  end

  @doc """
  Removes the policy for `source_key`. Idempotent (`003-FR-013`).
  """
  @spec release(Policy.source_key(), GenServer.server()) :: :ok
  def release(source_key, server \\ @name) do
    GenServer.call(server, {:release, source_key})
  end

  @doc "True when `source_key` currently carries a policy."
  @spec registered?(Policy.source_key(), GenServer.server()) :: boolean()
  def registered?(source_key, server \\ @name) do
    GenServer.call(server, {:registered?, source_key})
  end

  # -- Callbacks ------------------------------------------------------------

  @impl true
  def init(_opts), do: {:ok, %{}}

  @impl true
  def handle_call({:assign, key, allowed}, _from, policies) do
    case Map.fetch(policies, key) do
      {:ok, _existing} ->
        # ⚠️ Refuse rather than overwrite. Overwriting would make the common
        # case work and leave the race silent: a caller that assigns before
        # releasing gets correct behaviour, so nothing ever reveals that the
        # ordering mattered -- until a destroy path is reordered and a tenant
        # inherits a stale allowlist.
        {:reply, {:error, {:still_registered, key}}, policies}

      :error ->
        {:reply, :ok, Map.put(policies, key, allowed)}
    end
  end

  def handle_call({:lookup, key}, _from, policies) do
    {:reply, Map.get(policies, key, []), policies}
  end

  def handle_call({:release, key}, _from, policies) do
    {:reply, :ok, Map.delete(policies, key)}
  end

  def handle_call({:registered?, key}, _from, policies) do
    {:reply, Map.has_key?(policies, key), policies}
  end
end
