defmodule ExSandbox.Egress.Allocator do
  @moduledoc """
  Hands out the `/30` a sandbox's netns is built on, and takes it back only
  when the sandbox's policy is gone (005 T060a3, `contracts/egress.md`).

  ## Why this exists as its own module

  `ExSandbox.Egress.Registry`'s moduledoc has always stated the invariant in
  two halves — "`release/1` deletes the entry and only then returns the /30 to
  the pool; `assign/2` refuses a /30 that still carries one". Only the second
  half was enforced. There was no pool: `assign/2` takes whatever `source_key`
  its caller supplies, and `:pool_exhausted` sat in the `refusal` type from the
  first commit without any code path able to produce it.

  ⚠️ **A documented invariant with one half missing is worse than an undocumented
  one**, because it reads as settled. Every reviewer since has seen "returns the
  /30 to the pool" and had no reason to check whether a pool existed.

  ## The ordering, and why it is a callback rather than a convention

  `release/3` takes a predicate that answers "is this /30's policy gone?" and
  puts the address back **only if it answers true**. The alternative — document
  that callers must release the policy first — is the ordering convention the
  `Registry` moduledoc explicitly refuses to rely on, for the reason given
  there: the correct ordering in a `destroy` callback is exactly what a later
  refactor reorders without knowing why it was written that way.

  Passing the check in means the allocator cannot be wrong about it. A caller
  who releases the address while the policy stands does not corrupt the pool;
  the /30 simply stays out until someone releases it again with the policy
  actually gone.

  ## Why a free list rather than a counter

  A counter that recycles on release makes the reuse race trivially reachable
  and passes every "distinct sandboxes get distinct addresses" test — see
  `ExSandbox.Egress.AllocatorTest`, which is written against exactly that
  implementation.
  """

  use GenServer

  alias ExSandbox.Egress.Policy

  @typedoc "Why an acquisition was refused."
  @type refusal :: :pool_exhausted | {:still_registered, Policy.source_key()}

  @name __MODULE__

  # 10.0.0.0/24 as /30s: 64 sandboxes per host. Sized to be visibly finite --
  # `:pool_exhausted` is a real outcome an operator can hit and read, rather
  # than a theoretical branch that never executes and so is never right.
  @default_base {10, 0, 0, 0}
  @default_count 64

  # -- Public interface -----------------------------------------------------

  @doc false
  def start_link(opts) do
    # ⚠️ `name: nil` means **anonymous**, not "use the default". Passing the
    # `nil` straight through to `GenServer.start_link/3` registers the process
    # under the module name anyway, so two supposedly-isolated allocators in
    # one test run collide on the second `start_link` -- which is how this was
    # found.
    case Keyword.fetch(opts, :name) do
      {:ok, nil} -> GenServer.start_link(__MODULE__, opts)
      {:ok, name} -> GenServer.start_link(__MODULE__, opts, name: name)
      :error -> GenServer.start_link(__MODULE__, opts, name: @name)
    end
  end

  @doc """
  Takes the next free `/30`, or refuses.

  `{:error, {:still_registered, key}}` means the only remaining addresses are
  ones whose policy has not been released — see the ordering note above.
  """
  @spec acquire(GenServer.server()) :: {:ok, Policy.source_key()} | {:error, refusal()}
  def acquire(server \\ @name) do
    GenServer.call(server, :acquire)
  end

  @doc """
  Returns `key` to the pool if `policy_gone?.(key)` says its policy is gone.

  Idempotent, and safe for a `/30` this allocator never issued (`003-FR-013`):
  destroy is reached twice for the same sandbox and must not fault the second
  time.
  """
  @spec release(Policy.source_key(), (Policy.source_key() -> boolean()), GenServer.server()) ::
          :ok
  def release(key, policy_gone?, server \\ @name) when is_function(policy_gone?, 1) do
    GenServer.call(server, {:release, key, policy_gone?})
  end

  # -- Callbacks ------------------------------------------------------------

  @impl true
  def init(opts) do
    {a, b, c, d} = Keyword.get(opts, :base, @default_base)
    count = Keyword.get(opts, :count, @default_count)

    free = for i <- 0..(count - 1), do: {a, b, c, d + i * 4}

    # `held` carries the addresses that are out, so a release for something
    # never issued can be told apart from a double release. `withheld` is the
    # subset a caller has tried to release while the policy stood -- kept
    # separately so exhaustion can name which of the two problems it is.
    {:ok, %{free: free, held: MapSet.new(), withheld: MapSet.new()}}
  end

  @impl true
  def handle_call(:acquire, _from, %{free: []} = state) do
    # ⚠️ Distinguishes "nothing left at all" from "everything left is still
    # registered". Both refuse, but they send an operator to different places:
    # the first is a sizing problem, the second is a destroy path that stopped
    # releasing policies.
    #
    # `withheld` is the set of addresses a caller tried to release while their
    # policy still stood. An earlier version asked `Enum.find(held, fn _ ->
    # false end)`, which finds nothing by construction -- so every exhausted
    # pool reported `:pool_exhausted` and the second diagnosis, the one this
    # branch exists for, was unreachable. It read correctly and returned the
    # plausible answer on the only path anyone tested.
    case MapSet.to_list(state.withheld) do
      [] -> {:reply, {:error, :pool_exhausted}, state}
      [key | _] -> {:reply, {:error, {:still_registered, key}}, state}
    end
  end

  def handle_call(:acquire, _from, %{free: [key | rest]} = state) do
    {:reply, {:ok, key},
     %{
       state
       | free: rest,
         held: MapSet.put(state.held, key),
         withheld: MapSet.delete(state.withheld, key)
     }}
  end

  def handle_call({:release, key, policy_gone?}, _from, state) do
    cond do
      not MapSet.member?(state.held, key) ->
        # Never issued, or already released. Either way there is nothing to put
        # back, and adding it would let two sandboxes hold one /30.
        {:reply, :ok, state}

      policy_gone?.(key) ->
        {:reply, :ok,
         %{
           state
           | free: state.free ++ [key],
             held: MapSet.delete(state.held, key),
             withheld: MapSet.delete(state.withheld, key)
         }}

      true ->
        # ⚠️ Held, deliberately. The caller released the address while its
        # policy still stands; returning it now is the reuse race. It stays out
        # until a release arrives with the policy actually gone -- and is
        # recorded as withheld so an exhausted pool can say *why*.
        {:reply, :ok, %{state | withheld: MapSet.put(state.withheld, key)}}
    end
  end
end
