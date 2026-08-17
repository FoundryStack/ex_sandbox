defmodule ExSandbox.Egress.BindingTest do
  @moduledoc """
  Binding a sandbox's resolved allowlist to the `/30` its traffic will arrive
  from (005 T060a2, `005-FR-011a`–`FR-011e`).

  ## What is being joined, and why it is the dangerous seam

  Three things have to agree for a sandbox's policy to be *its own*:

    * the `/30` the `Allocator` handed out,
    * the netns address the sandbox actually sends from, and
    * the key the `Registry` filed the allowlist under.

  The pool identifies a connection's owner by masking the source address it
  reads from the kernel (`Policy.source_key/1`). If the registration key and the
  namespace address disagree, every sandbox looks unregistered, every connection
  is denied — and **the suite stays green**, because denial is what the network
  checks assert. That is the failure mode this whole feature exists to close,
  and binding is where it would be reintroduced.

  ⚠️ These tests are about the **binding**, not the transport. They exercise the
  `Allocator`/`Registry` pair directly rather than launching sandboxes: the
  launch path is Linux-only and refuses on macOS long before any of this runs,
  so a launch-dependent test would be excluded on the host where it is being
  written. The transport is measured in the container.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Allocator
  alias ExSandbox.Egress.Netns
  alias ExSandbox.Egress.Policy
  alias ExSandbox.Egress.Registry, as: EgressRegistry

  @allowlist_a [{"a.example.com", 443}]
  @allowlist_b [{"b.example.com", 443}]

  defp start_pair(id, allocator_opts) do
    allocator =
      start_supervised!(
        Supervisor.child_spec({Allocator, Keyword.put(allocator_opts, :name, nil)},
          id: :"alloc_#{id}"
        )
      )

    registry =
      start_supervised!(Supervisor.child_spec({EgressRegistry, [name: nil]}, id: :"reg_#{id}"))

    %{allocator: allocator, registry: registry}
  end

  describe "the address a sandbox sends from is the key its policy is filed under" do
    setup do: start_pair(:join, base: {10, 0, 0, 0}, count: 4)

    test "a registered /30 is found under the address its namespace will use", ctx do
      # ⚠️ The single assertion the whole design rests on. `Allocator.acquire/1`
      # returns a network address; `Netns.addresses/1` derives the host address
      # inside the namespace from it; the pool masks whatever the kernel reports
      # back to a key. If those three disagree by even one octet the sandbox is
      # unregistered, is denied everything, and nothing outward-facing says so.
      {:ok, key} = Allocator.acquire(ctx.allocator)
      :ok = EgressRegistry.assign(key, @allowlist_a, ctx.registry)

      %{sandbox: sandbox_address} = Netns.addresses(key)
      {:ok, parsed} = :inet.parse_address(String.to_charlist(sandbox_address))

      assert Policy.source_key(parsed) == key,
             "the namespace address does not mask to its registration key: every connection would look unregistered and be denied, and every denial check would still pass"

      assert EgressRegistry.lookup(Policy.source_key(parsed), ctx.registry) == @allowlist_a
    end

    test "the namespace address is the /30's usable host, not merely inside it", ctx do
      # ⚠️ This test exists because the round trip above passed against a
      # sabotaged `addresses/1` that returned `d + 3`. Masking is *designed* to
      # be forgiving -- every one of the four addresses in a /30 masks back to
      # the same key -- so `source_key(addresses(key)) == key` holds for any
      # offset and proves only that masking works, which was never in doubt.
      #
      # `d + 3` is the broadcast address. A namespace configured with it cannot
      # carry unicast traffic at all, so the sandbox reaches nothing -- and
      # since the registration key still resolves, the policy looks correctly
      # installed while nothing can use it. Denial-only checks stay green.
      {:ok, {a, b, c, d} = key} = Allocator.acquire(ctx.allocator)
      %{gateway: gateway, sandbox: sandbox} = Netns.addresses(key)

      assert sandbox == "#{a}.#{b}.#{c}.#{d + 2}",
             "the namespace address is not the /30's second host: #{sandbox}"

      assert gateway == "#{a}.#{b}.#{c}.#{d + 1}",
             "the gateway is not the /30's first host: #{gateway}"

      # Stated as the property rather than the arithmetic: neither end may be
      # the network address (d) or the broadcast address (d + 3).
      for {name, address} <- [{"gateway", gateway}, {"sandbox", sandbox}] do
        {:ok, {_, _, _, last}} = :inet.parse_address(String.to_charlist(address))

        assert rem(last, 4) in [1, 2],
               "#{name} #{address} is the /30's network or broadcast address, which carries no unicast traffic"
      end
    end

    test "the gateway address does not resolve to the sandbox's policy", ctx do
      # The gateway is `pasta`'s end of the link, not the sandbox's. It masks to
      # the same /30, which is correct -- but it is worth pinning that the
      # sandbox address is the one the design uses, so a later edit that reads
      # `gateway` instead fails here rather than in a container.
      {:ok, key} = Allocator.acquire(ctx.allocator)
      :ok = EgressRegistry.assign(key, @allowlist_a, ctx.registry)

      %{gateway: gateway, sandbox: sandbox} = Netns.addresses(key)
      refute gateway == sandbox
    end

    test "two sandboxes get distinct /30s and distinct policies", ctx do
      {:ok, key_a} = Allocator.acquire(ctx.allocator)
      {:ok, key_b} = Allocator.acquire(ctx.allocator)

      :ok = EgressRegistry.assign(key_a, @allowlist_a, ctx.registry)
      :ok = EgressRegistry.assign(key_b, @allowlist_b, ctx.registry)

      # ⚠️ Compared **after masking**, not as issued. Comparing the keys alone
      # passed against an allocator striding by 2, which issues {10,0,0,0} and
      # {10,0,0,2} -- distinct keys that mask to the same /30. Two tenants would
      # share one policy entry, the second `assign` would be refused as
      # `still_registered`, and the sandbox that lost the race would be denied
      # everything while looking correctly provisioned.
      refute Policy.source_key(key_a) == Policy.source_key(key_b),
             "two issued /30s mask to the same key: the tenants would share one policy entry"

      # And the addresses their namespaces use must not collide either.
      assert Netns.addresses(key_a).sandbox != Netns.addresses(key_b).sandbox
      assert Netns.addresses(key_a).sandbox != Netns.addresses(key_b).gateway

      assert EgressRegistry.lookup(key_a, ctx.registry) == @allowlist_a
      assert EgressRegistry.lookup(key_b, ctx.registry) == @allowlist_b
    end

    test "an unregistered /30 resolves to the empty allowlist, which denies", ctx do
      {:ok, key} = Allocator.acquire(ctx.allocator)

      # Acquired but never assigned -- the window between the two. It must deny,
      # not permit, and `Policy.permits?/2` on `[]` is what makes the miss path
      # and the deny path the same path.
      assert EgressRegistry.lookup(key, ctx.registry) == []
      refute Policy.permits?(EgressRegistry.lookup(key, ctx.registry), {"a.example.com", 443})
    end
  end

  describe "the reuse race, end to end (005 T060a6)" do
    # ⚠️ A **one-address** pool. With spare addresses the second acquire returns
    # a fresh /30 and the race is unreachable -- the test would pass against an
    # allocator that recycles the instant it is asked, which is the exact
    # implementation it exists to catch.
    setup do: start_pair(:race, base: {10, 0, 0, 0}, count: 1)

    test "tenant B cannot inherit tenant A's allowlist by reusing its /30", ctx do
      {:ok, key} = Allocator.acquire(ctx.allocator)
      :ok = EgressRegistry.assign(key, @allowlist_a, ctx.registry)

      # A destroy path that releases the address but forgets the policy. This is
      # the reordering the `Registry` moduledoc refuses to guard by convention.
      :ok =
        Allocator.release(key, &(not EgressRegistry.registered?(&1, ctx.registry)), ctx.allocator)

      assert {:error, {:still_registered, ^key}} = Allocator.acquire(ctx.allocator),
             "the /30 was handed out while A's policy still stood: B would connect and be enforced against A's allowlist, and every outward check would pass"
    end

    test "a correct destroy returns the /30 and the next tenant gets a clean one", ctx do
      {:ok, key} = Allocator.acquire(ctx.allocator)
      :ok = EgressRegistry.assign(key, @allowlist_a, ctx.registry)

      # Release the policy first, then the address -- the order the invariant
      # asks for, enforced by the predicate rather than trusted.
      :ok = EgressRegistry.release(key, ctx.registry)

      :ok =
        Allocator.release(key, &(not EgressRegistry.registered?(&1, ctx.registry)), ctx.allocator)

      assert {:ok, ^key} = Allocator.acquire(ctx.allocator)

      # ⚠️ And it must come back *empty*. A recycled address carrying a stale
      # allowlist is the leak itself; that the address is reusable is only safe
      # because the policy went with it.
      assert EgressRegistry.lookup(key, ctx.registry) == [],
             "the recycled /30 still carries the previous tenant's allowlist"
    end

    test "re-registering a released /30 is permitted, and holds the new policy", ctx do
      {:ok, key} = Allocator.acquire(ctx.allocator)
      :ok = EgressRegistry.assign(key, @allowlist_a, ctx.registry)
      :ok = EgressRegistry.release(key, ctx.registry)

      :ok =
        Allocator.release(key, &(not EgressRegistry.registered?(&1, ctx.registry)), ctx.allocator)

      {:ok, ^key} = Allocator.acquire(ctx.allocator)
      :ok = EgressRegistry.assign(key, @allowlist_b, ctx.registry)

      assert EgressRegistry.lookup(key, ctx.registry) == @allowlist_b
    end
  end
end
