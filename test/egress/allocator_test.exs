defmodule ExSandbox.Egress.AllocatorTest do
  @moduledoc """
  Written against a specific wrong allocator: one that hands out the next /30
  from a counter and recycles a released /30 immediately.

  That version passes every "each sandbox gets a distinct address" test. What it
  cannot survive is the reuse race `Egress.Registry`'s moduledoc already names —
  a /30 returning to the pool while its policy entry is still registered, so the
  next tenant inherits the previous tenant's allowlist and *every outward check
  still passes*.

  The Registry enforces its half (`assign/2` refuses a still-registered /30).
  Nothing enforced the other half, because the pool `release/1` was documented
  to return the /30 to did not exist.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Allocator
  alias ExSandbox.Egress.Policy

  # ⚠️ `start_supervised!` derives the child id from the module, so two
  # `{Allocator, ...}` specs collide in one test's supervisor even when both
  # processes are anonymous. An explicit distinct id is what keeps the
  # describe-level pool separate from the default one.
  defp start_allocator(id, opts) do
    start_supervised!(Supervisor.child_spec({Allocator, Keyword.put(opts, :name, nil)}, id: id))
  end

  setup do
    %{allocator: start_allocator(:default_pool, base: {10, 0, 0, 0}, count: 4)}
  end

  describe "the reuse race (005 T060a6, Registry invariant)" do
    # ⚠️ A **one-address** pool, deliberately. With spare addresses the next
    # `acquire` returns a fresh one and the recycling path is never reached --
    # the test would pass against an allocator that recycles unconditionally,
    # which is the exact implementation it exists to catch. Draining the pool
    # to a single address is what forces the question to be asked.
    setup do
      %{single: start_allocator(:single_pool, base: {10, 0, 0, 0}, count: 1)}
    end

    test "a released /30 is not handed out again while its policy is still registered", %{
      single: allocator
    } do
      # ⚠️ **The load-bearing test.** A counter-based allocator recycles on
      # release and passes everything else. Here the caller releases the
      # address but has not yet dropped the policy -- exactly the window a
      # reordered `destroy` opens -- and handing this /30 out would give the
      # next tenant the previous tenant's allowlist with nothing going red.
      {:ok, key} = Allocator.acquire(allocator)
      :ok = Allocator.release(key, fn _ -> false end, allocator)

      assert {:error, {:still_registered, ^key}} = Allocator.acquire(allocator)
    end

    test "a released /30 becomes available once its policy is gone", %{single: allocator} do
      # The other direction: refusing forever would be safe and useless. The
      # /30 must actually come back, or the pool drains to exhaustion under
      # normal operation and every launch eventually fails.
      {:ok, key} = Allocator.acquire(allocator)
      :ok = Allocator.release(key, fn _ -> true end, allocator)

      assert {:ok, ^key} = Allocator.acquire(allocator)
    end
  end

  describe "allocation" do
    test "distinct sandboxes get non-overlapping /30s", %{allocator: allocator} do
      keys =
        for _ <- 1..4 do
          {:ok, key} = Allocator.acquire(allocator)
          key
        end

      assert length(Enum.uniq(keys)) == 4

      # ⚠️ Asserted through `source_key/1` rather than on the tuples. Two /30s
      # that differ as addresses but mask to the same key are the same sandbox
      # identity as far as the pool is concerned -- which is the property that
      # actually has to hold.
      assert keys |> Enum.map(&Policy.source_key/1) |> Enum.uniq() |> length() == 4
    end

    test "every allocated /30 is aligned to a /30 boundary", %{allocator: allocator} do
      # An unaligned base makes `source_key/1` mask to a *different* /30 than
      # the one that was handed out, so the sandbox registers one identity and
      # connects as another -- default-deny for a sandbox that was configured
      # correctly, and no test of either module alone would show it.
      for _ <- 1..4 do
        {:ok, {_, _, _, d} = key} = Allocator.acquire(allocator)
        assert rem(d, 4) == 0
        assert Policy.source_key(key) == key
      end
    end

    test "exhaustion is refused, not wrapped around", %{allocator: allocator} do
      # ⚠️ `:pool_exhausted` was declared in `Registry`'s refusal type from the
      # start and never produced by anything. Wrapping around would reissue a
      # live tenant's /30 -- the reuse race, reached by a different road.
      for _ <- 1..4, do: {:ok, _} = Allocator.acquire(allocator)

      assert {:error, :pool_exhausted} = Allocator.acquire(allocator)
    end
  end

  describe "release" do
    test "releasing a /30 that was never acquired is a no-op", %{allocator: allocator} do
      # `003-FR-013`: destroy is idempotent, so release is reached twice for the
      # same sandbox and must not fault the second time.
      assert :ok = Allocator.release({10, 0, 0, 252}, fn _ -> true end, allocator)
    end

    test "releasing twice does not put the same /30 in the pool twice", %{allocator: allocator} do
      # A double-add would let two live sandboxes hold one /30 -- the reuse race
      # without any release ordering error at all.
      {:ok, key} = Allocator.acquire(allocator)
      :ok = Allocator.release(key, fn _ -> true end, allocator)
      :ok = Allocator.release(key, fn _ -> true end, allocator)

      acquired =
        Stream.repeatedly(fn -> Allocator.acquire(allocator) end)
        |> Enum.take_while(&match?({:ok, _}, &1))
        |> Enum.map(fn {:ok, k} -> k end)

      assert Enum.count(acquired, &(&1 == key)) == 1
    end
  end
end
