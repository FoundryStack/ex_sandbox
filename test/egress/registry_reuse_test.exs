defmodule ExSandbox.Egress.RegistryReuseTest do
  @moduledoc """
  The /30-reuse race (005 T060a6): can a new sandbox inherit the previous
  tenant's allowlist?

  ⚠️ Written **before** the reclamation path that it constrains, because this
  failure is invisible from outside. A sandbox holding a stale allowlist passes
  every outward-facing check -- it reaches destinations, denied destinations are
  refused, the policy is not editable from inside. The only thing wrong is
  *whose* policy it is, and no outward check can see that.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Policy
  alias ExSandbox.Egress.Registry

  setup do
    server = start_supervised!({Registry, name: :"reuse_#{System.unique_integer([:positive])}"})
    %{server: server}
  end

  @tenant_a [{"a.example.com", 443}]
  @tenant_b [{"b.example.com", 443}]

  test "a /30 cannot be reassigned while the previous tenant's policy remains", %{server: s} do
    key = Policy.source_key({10, 0, 0, 1})

    assert :ok = Registry.assign(key, @tenant_a, s)

    # Sandbox A is "destroyed" -- but suppose the release is missed, reordered,
    # or fails silently. This is the exact state the invariant exists to catch.
    assert {:error, {:still_registered, ^key}} = Registry.assign(key, @tenant_b, s)

    # ⚠️ And critically: the refusal must not have half-applied. If the assign
    # partially wrote, B would hold a mixture and the leak would still be real.
    assert Registry.lookup(key, s) == @tenant_a
  end

  test "after release, the /30 is assignable and carries only the new policy", %{server: s} do
    key = Policy.source_key({10, 0, 0, 1})

    assert :ok = Registry.assign(key, @tenant_a, s)
    assert :ok = Registry.release(key, s)
    refute Registry.registered?(key, s)

    assert :ok = Registry.assign(key, @tenant_b, s)
    assert Registry.lookup(key, s) == @tenant_b

    # The previous tenant's destinations are gone, not merged.
    refute Policy.permits?(Registry.lookup(key, s), {"a.example.com", 443})
    assert Policy.permits?(Registry.lookup(key, s), {"b.example.com", 443})
  end

  test "release is idempotent (003-FR-013)", %{server: s} do
    key = Policy.source_key({10, 0, 0, 1})
    assert :ok = Registry.assign(key, @tenant_a, s)
    assert :ok = Registry.release(key, s)
    assert :ok = Registry.release(key, s)
    refute Registry.registered?(key, s)
  end

  test "an unregistered /30 denies by default rather than erroring", %{server: s} do
    # The miss path and the deny path must be the same path -- an error return
    # invites a caller to handle it, and the tempting handling is to let the
    # connection through while logging.
    key = Policy.source_key({10, 0, 0, 8})
    assert Registry.lookup(key, s) == []
    refute Policy.permits?(Registry.lookup(key, s), {"anywhere.example.com", 443})
  end

  test "every address within a released /30 is denied, not just the network address", %{
    server: s
  } do
    # ⚠️ A release that cleared only the exact key it was given would leave
    # sibling addresses resolving to a stale entry. Masking makes them one key,
    # so this asserts the masking and the release agree.
    key = Policy.source_key({10, 0, 0, 1})
    assert :ok = Registry.assign(key, @tenant_a, s)
    assert :ok = Registry.release(key, s)

    for last <- 0..3 do
      sibling = Policy.source_key({10, 0, 0, last})
      assert Registry.lookup(sibling, s) == [], "#{last} still resolves to a policy"
    end
  end

  test "a neighbouring /30 is unaffected by a release", %{server: s} do
    # The mirror of the test above: masking must not be so coarse that
    # releasing one sandbox silently disarms another.
    a = Policy.source_key({10, 0, 0, 1})
    b = Policy.source_key({10, 0, 0, 5})

    assert :ok = Registry.assign(a, @tenant_a, s)
    assert :ok = Registry.assign(b, @tenant_b, s)
    assert :ok = Registry.release(a, s)

    assert Registry.lookup(b, s) == @tenant_b
  end
end
