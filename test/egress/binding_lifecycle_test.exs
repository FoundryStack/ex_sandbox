defmodule ExSandbox.Egress.BindingLifecycleTest do
  @moduledoc """
  That an acquired binding is *reachable from destroy* (005 T060a3b/T060a6).

  ## The gap this suite exists to close

  `Egress.Binding.acquire/2` and `release/2` are both implemented and both
  tested. Neither test answers the question that decides whether they work in
  the running system: **once `launch/2` acquires a binding, what still holds a
  reference to it when `destroy/1` runs?**

  Today, nothing. `launch/2`'s `launched()` map is `%{node, os_pid, peer,
  cookie}` -- there is no field for a binding -- and `destroy/1` is handed a
  `%Sandbox{}`, not a `%Binding{}`. So a binding acquired at launch would be
  reachable only from the stack frame that created it.

  ⚠️ **Why that leaks silently rather than failing.** `Allocator.acquire/1`
  hands out a `/30` and `Registry.assign/3` files a policy under it. If nothing
  releases them, the policy stays registered for a sandbox that no longer
  exists and the `/30` is never reissued. Neither shows up as an error: the
  sandbox destroys cleanly, the suite passes, and the only symptom is that the
  65th provision on a long-lived host fails with `:pool_exhausted` -- reported
  against whichever tenant happened to be next, with nothing connecting it to
  the destroys that never gave their addresses back.

  Worse, a stale policy is a *live* policy. `Pool.decide/3` keys on the /30, so
  a reissued address would inherit the previous tenant's allowlist -- the exact
  crossing `T060a6`'s reuse adversary was written to prevent, arriving through
  the one path that adversary cannot see, because it tests `release/2` being
  *called* rather than the system calling it.

  These tests run anywhere: they pin the plumbing, not the namespace.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Allocator
  alias ExSandbox.Egress.Binding
  alias ExSandbox.Egress.Registry, as: EgressRegistry

  setup do
    registry =
      start_supervised!({EgressRegistry, name: :"reg_#{System.unique_integer([:positive])}"})

    allocator =
      start_supervised!(
        {Allocator, name: :"alloc_#{System.unique_integer([:positive])}", count: 2}
      )

    %{registry: registry, allocator: allocator, opts: [registry: registry, allocator: allocator]}
  end

  describe "a binding survives the frame that created it" do
    test "the binding carries everything release/2 needs", %{opts: opts} do
      {:ok, binding} = Binding.acquire([{"example.com", 443}], opts)

      # ⚠️ The point of this assertion is not that the struct has fields -- it is
      # that the fields are *sufficient*. `release/2` pattern-matches on
      # `source_key` alone, so a binding is releasable by anything holding the
      # struct, with no reference to the process that acquired it and no lookup
      # against the sandbox it belongs to.
      #
      # That is what makes storing it in the mechanism's row a complete fix
      # rather than a partial one: the row outlives `launch/2`'s stack frame,
      # and the struct is self-sufficient once retrieved.
      assert %Binding{source_key: source_key} = binding
      assert is_tuple(source_key)

      assert :ok = Binding.release(binding, opts)
    end

    test "a binding reconstructed from stored fields releases the real one", %{opts: opts} do
      {:ok, binding} = Binding.acquire([{"example.com", 443}], opts)

      # Simulates the round trip through storage: the struct is taken apart,
      # kept as data, and rebuilt somewhere else entirely. If release/2 depended
      # on anything not in these three fields -- a pid, a monitor, a timestamp --
      # this would not free the address, and the next assertion would fail.
      rebuilt = %Binding{
        source_key: binding.source_key,
        sandbox_address: binding.sandbox_address,
        gateway_address: binding.gateway_address
      }

      assert :ok = Binding.release(rebuilt, opts)
      refute EgressRegistry.registered?(binding.source_key, opts[:registry])
    end
  end

  describe "what a leaked binding costs" do
    test "an unreleased binding exhausts the pool", %{opts: opts} do
      # `count: 2` makes the exhaustion observable in three calls rather than
      # sixty-five. ⚠️ It must be `count:` -- `Allocator.init/1` reads that key,
      # and an option it does not read is accepted silently by `Keyword.get/3`,
      # leaving the assertion running against the default pool of 64 and passing
      # for the wrong reason. That exact mistake (`pool_size:`) was made earlier
      # in this feature and found only by deliberately shrinking the pool.
      {:ok, _first} = Binding.acquire([{"a.example.com", 443}], opts)
      {:ok, _second} = Binding.acquire([{"b.example.com", 443}], opts)

      assert {:error, :pool_exhausted} = Binding.acquire([{"c.example.com", 443}], opts)
    end

    test "releasing gives the address back to the next tenant", %{opts: opts} do
      {:ok, first} = Binding.acquire([{"a.example.com", 443}], opts)
      {:ok, _second} = Binding.acquire([{"b.example.com", 443}], opts)

      assert {:error, :pool_exhausted} = Binding.acquire([{"c.example.com", 443}], opts)

      :ok = Binding.release(first, opts)

      # The counterpart to the test above: the pool recovers only because
      # something released. This is what `destroy/1` has to do, and what it
      # currently has no way to do.
      assert {:ok, _third} = Binding.acquire([{"c.example.com", 443}], opts)
    end

    test "a reissued address does not inherit the previous tenant's allowlist", %{opts: opts} do
      {:ok, first} = Binding.acquire([{"previous.example.com", 443}], opts)
      key = first.source_key

      :ok = Binding.release(first, opts)

      # ⚠️ The crossing this whole ordering exists to prevent (`003-FR-002`).
      # If `release/2` freed the address without dropping the policy, the next
      # tenant handed this /30 would silently inherit `previous.example.com` --
      # and would be *permitted* to reach it, which no denial check anywhere
      # would report, because nothing was denied.
      refute EgressRegistry.registered?(key, opts[:registry])
    end
  end
end
