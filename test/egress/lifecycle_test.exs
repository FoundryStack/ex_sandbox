defmodule ExSandbox.Egress.LifecycleTest do
  @moduledoc """
  Acquiring and reclaiming a sandbox's egress policy across its lifetime
  (005 T060a2/T060a6, `003-FR-013`).

  ## The asymmetry that makes this worth its own module

  Registration is easy to get right and easy to test: provision, look it up,
  see the allowlist. **Reclamation is neither.** A destroy that forgets to
  release leaves no visible trace — the sandbox is gone, its node is gone, its
  row is gone, and the only evidence is a `/30` that will never be issued again
  and a policy entry that will be inherited by whoever gets that address next.

  Nothing observable degrades until the pool exhausts, which on a 64-address
  pool takes 64 provisions and looks like a capacity problem rather than a leak.

  ⚠️ So the tests here assert on **what remains after teardown**, not on what
  works during operation. A suite that only checks the live path cannot
  distinguish a mechanism that reclaims from one that never does.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Binding
  alias ExSandbox.Egress.Allocator
  alias ExSandbox.Egress.Registry, as: EgressRegistry

  @allowlist [{"api.example.com", 443}]

  # A process that speaks `ExSandbox.Egress.Registry`'s call protocol but never
  # forgets -- the destroy path that dropped a policy and did not.
  #
  # ⚠️ Written as a raw `GenServer` rather than an `Agent` because `Binding`
  # names the registry *module* and passes only a server reference. That is a
  # deliberate constraint of the design, not an accident: the registry is one
  # supervised process, and letting callers substitute an arbitrary module would
  # make the enforcement point swappable from configuration. The cost is that a
  # double here must implement the protocol rather than the interface.
  defmodule ForgetfulRegistry do
    @moduledoc false
    use GenServer

    def start_link(_opts), do: GenServer.start_link(__MODULE__, nil)

    @impl true
    def init(_), do: {:ok, MapSet.new()}

    @impl true
    def handle_call({:assign, key, _allowed}, _from, keys),
      do: {:reply, :ok, MapSet.put(keys, key)}

    # The whole point: acknowledged, never acted on.
    def handle_call({:release, _key}, _from, keys), do: {:reply, :ok, keys}

    def handle_call({:registered?, key}, _from, keys),
      do: {:reply, MapSet.member?(keys, key), keys}

    def handle_call({:lookup, key}, _from, keys) do
      {:reply, if(MapSet.member?(keys, key), do: [{"api.example.com", 443}], else: []), keys}
    end
  end

  defp start_pair(id, opts) do
    allocator =
      start_supervised!(
        Supervisor.child_spec({Allocator, Keyword.put(opts, :name, nil)}, id: :"alloc_#{id}")
      )

    registry =
      start_supervised!(Supervisor.child_spec({EgressRegistry, [name: nil]}, id: :"reg_#{id}"))

    %{egress: [allocator: allocator, registry: registry]}
  end

  describe "acquire/2" do
    setup do: start_pair(:acquire, base: {10, 0, 0, 0}, count: 4)

    test "an allowlist becomes reachable under the /30 it was bound to", ctx do
      {:ok, binding} = Binding.acquire(@allowlist, ctx.egress)

      assert EgressRegistry.lookup(binding.source_key, ctx.egress[:registry]) == @allowlist
    end

    test "an empty allowlist still takes a /30 and still registers", ctx do
      # ⚠️ An empty allowlist is a real tenant configuration -- "this sandbox
      # reaches nothing" -- and it must be *registered* as such rather than
      # skipped. An unregistered source is also denied everything, so skipping
      # would behave identically today and diverge silently the moment anything
      # distinguishes "no policy" from "empty policy". `Verification.policed?/1`
      # already does.
      {:ok, binding} = Binding.acquire([], ctx.egress)

      assert EgressRegistry.registered?(binding.source_key, ctx.egress[:registry]),
             "an empty allowlist was not registered: the sandbox is indistinguishable from one with no policy at all"
    end

    test "the binding carries the namespace addresses its /30 implies", ctx do
      {:ok, binding} = Binding.acquire(@allowlist, ctx.egress)

      {a, b, c, d} = binding.source_key
      assert binding.sandbox_address == "#{a}.#{b}.#{c}.#{d + 2}"
      assert binding.gateway_address == "#{a}.#{b}.#{c}.#{d + 1}"
    end

    test "an exhausted pool refuses rather than issuing an unpoliced sandbox", ctx do
      # ⚠️ The direction that matters. Falling back to "no policy" on exhaustion
      # would give the tenant a sandbox that reaches everything, and the failure
      # would surface as a security hole rather than a capacity error.
      for _ <- 1..4, do: {:ok, _} = Binding.acquire(@allowlist, ctx.egress)

      assert {:error, :pool_exhausted} = Binding.acquire(@allowlist, ctx.egress)
    end
  end

  describe "release/2" do
    setup do: start_pair(:release, base: {10, 0, 0, 0}, count: 1)

    test "releasing frees both the policy and the /30", ctx do
      {:ok, binding} = Binding.acquire(@allowlist, ctx.egress)
      :ok = Binding.release(binding, ctx.egress)

      refute EgressRegistry.registered?(binding.source_key, ctx.egress[:registry]),
             "the policy survived destroy: the next tenant on this /30 inherits it"

      # A one-address pool, so this only succeeds if the address came back.
      assert {:ok, _} = Binding.acquire(@allowlist, ctx.egress),
             "the /30 was never returned: the pool leaks one address per sandbox and exhausts silently"
    end

    test "release is idempotent (003-FR-013)", ctx do
      {:ok, binding} = Binding.acquire(@allowlist, ctx.egress)

      assert :ok = Binding.release(binding, ctx.egress)
      assert :ok = Binding.release(binding, ctx.egress)
    end

    test "a double release does not hand the same /30 to two tenants", ctx do
      # ⚠️ The specific hazard behind idempotency here. `release` returning `:ok`
      # twice is easy; `release` putting the address back on the free list twice
      # is a pool that issues one /30 to two sandboxes, which is the reuse race
      # arrived at from the opposite direction.
      {:ok, binding} = Binding.acquire(@allowlist, ctx.egress)
      :ok = Binding.release(binding, ctx.egress)
      :ok = Binding.release(binding, ctx.egress)

      {:ok, first} = Binding.acquire(@allowlist, ctx.egress)

      assert {:error, :pool_exhausted} = Binding.acquire(@allowlist, ctx.egress),
             "the double release duplicated #{inspect(first.source_key)} in the pool: two sandboxes would share one /30 and one policy"
    end

    test "releasing a binding that was never acquired is safe", ctx do
      # Destroy is reached for sandboxes that failed to provision, and their
      # bindings may never have existed.
      binding = %Binding{
        source_key: {10, 9, 9, 0},
        sandbox_address: "10.9.9.2",
        gateway_address: "10.9.9.1"
      }

      assert :ok = Binding.release(binding, ctx.egress)
    end

    test "release/2 refuses to recycle a /30 whose policy it failed to drop", ctx do
      # ⚠️ Two earlier versions of this test passed against a sabotaged
      # `policy_gone?/2`. The first went through the happy path, where a
      # predicate that never checks gives the same answer as one that does. The
      # second called `Allocator.release/3` with its own inline predicate --
      # testing the allocator, and never executing `Binding`'s predicate at all.
      #
      # To reach it the call must be `Binding.release/2`, and the registry must
      # still hold the policy when the allocator asks. A second registry that
      # never forgets produces exactly that: `release/2` drops the policy (into
      # the void), then asks -- and a truthful predicate must answer "still
      # registered" and leave the address out.
      {:ok, binding} = Binding.acquire(@allowlist, ctx.egress)

      # A registry whose `release` is a no-op, standing in for the destroy path
      # that forgets. `Binding.release/2` cannot tell, and must not assume.
      forgetful =
        start_supervised!(Supervisor.child_spec({ForgetfulRegistry, []}, id: :forgetful))

      :ok = GenServer.call(forgetful, {:assign, binding.source_key, @allowlist})

      :ok = Binding.release(binding, allocator: ctx.egress[:allocator], registry: forgetful)

      assert {:error, {:still_registered, _}} = Allocator.acquire(ctx.egress[:allocator]),
             "the /30 was recycled although its policy was still registered: `policy_gone?` did not ask, and the next tenant inherits the previous one's allowlist"
    end

    test "a failed registration gives the /30 back, and the pool can say so", ctx do
      # ⚠️ Two earlier versions of this test passed against a sabotaged rollback,
      # and finding out why is the point of the test that replaced them.
      #
      # `Allocator.release/3` re-adds a held address whether or not the rollback
      # already did, so **any** later release repairs the leak and erases the
      # difference. The two implementations are genuinely indistinguishable on
      # every path where the caller releases again -- measured, not assumed.
      #
      # The one path where they differ is the one that matters: the caller got
      # an error and moved on, and no later release ever arrives. Then the
      # rollback is the only thing that returned the address, and the pool can
      # still name *which* problem it has:
      #
      #   * rollback present -> `{:still_registered, key}` -- a destroy path
      #     stopped releasing policies, which is a bug an operator can act on
      #   * rollback absent  -> `:pool_exhausted` -- reads as a sizing problem,
      #     and sends whoever hits it to the wrong place entirely
      #
      # Both refuse, so a test asserting "refuses" cannot tell them apart. This
      # asserts on the diagnosis.
      {:ok, first} = Binding.acquire(@allowlist, ctx.egress)

      # Address freed, policy deliberately left standing, so `assign/3` refuses.
      :ok = Allocator.release(first.source_key, fn _ -> true end, ctx.egress[:allocator])
      assert {:error, {:still_registered, _}} = Binding.acquire(@allowlist, ctx.egress)

      # The blocking policy goes. Nothing else releases -- that caller is gone.
      :ok = EgressRegistry.release(first.source_key, ctx.egress[:registry])

      assert {:error, {:still_registered, _}} = Allocator.acquire(ctx.egress[:allocator]),
             "the pool reports plain exhaustion: `acquire/2` abandoned the /30 instead of rolling it back, and the leak now reads as a sizing problem rather than a destroy path that stopped releasing policies"
    end

    test "the recycled /30 carries no trace of the previous tenant", ctx do
      {:ok, first} = Binding.acquire(@allowlist, ctx.egress)
      :ok = Binding.release(first, ctx.egress)

      {:ok, second} = Binding.acquire([{"other.example.com", 80}], ctx.egress)

      assert second.source_key == first.source_key

      assert EgressRegistry.lookup(second.source_key, ctx.egress[:registry]) == [
               {"other.example.com", 80}
             ]
    end
  end
end
