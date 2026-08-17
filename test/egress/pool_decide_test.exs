defmodule ExSandbox.Egress.PoolDecideTest do
  @moduledoc """
  The pool's decision rule (005 T060a1), tested without a network.

  The conformance suite establishes the boundary by *attempting* connections,
  which is the only way to prove a boundary holds. This file is the complement:
  it states what the rule is, so a change to the rule is visible here rather
  than only as a distant conformance failure.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Policy
  alias ExSandbox.Egress.Pool
  alias ExSandbox.Egress.Registry

  setup do
    server = start_supervised!({Registry, name: :"pool_#{System.unique_integer([:positive])}"})
    %{registry: server}
  end

  @source {10, 0, 0, 1}
  @allowed {"api.example.com", 443}

  test "a permitted destination from a registered source is permitted", %{registry: r} do
    :ok = Registry.assign(Policy.source_key(@source), [@allowed], r)
    assert Pool.decide(@source, @allowed, r) == :permitted
  end

  test "a destination outside the allowlist is refused", %{registry: r} do
    :ok = Registry.assign(Policy.source_key(@source), [@allowed], r)
    assert Pool.decide(@source, {"evil.example.com", 443}, r) == {:refused, :not_permitted}
  end

  test "an unregistered source is refused, distinguishably", %{registry: r} do
    # ⚠️ Distinguished for diagnosis, but it must still REFUSE. An unknown
    # source is a sandbox whose policy was never registered or was already
    # released; treating it as "no restrictions" is the exact inversion this
    # design exists to prevent.
    assert Pool.decide(@source, @allowed, r) == {:refused, :unknown_source}
  end

  test "a released source stops being permitted immediately", %{registry: r} do
    key = Policy.source_key(@source)
    :ok = Registry.assign(key, [@allowed], r)
    assert Pool.decide(@source, @allowed, r) == :permitted

    :ok = Registry.release(key, r)
    assert Pool.decide(@source, @allowed, r) == {:refused, :unknown_source}
  end

  test "every host address in a sandbox's /30 gets that sandbox's policy", %{registry: r} do
    # The masking is what makes identity stable: a sandbox's connections come
    # from a host address inside its /30, not from the network address.
    :ok = Registry.assign(Policy.source_key({10, 0, 0, 0}), [@allowed], r)

    for last <- 0..3 do
      assert Pool.decide({10, 0, 0, last}, @allowed, r) == :permitted,
             "10.0.0.#{last} did not resolve to its own sandbox's policy"
    end
  end

  test "a neighbouring sandbox does not inherit this one's allowlist", %{registry: r} do
    # 003-FR-002 in its smallest form: B must not reach what only A may reach.
    :ok = Registry.assign(Policy.source_key({10, 0, 0, 0}), [@allowed], r)
    :ok = Registry.assign(Policy.source_key({10, 0, 0, 4}), [{"b.example.com", 443}], r)

    assert Pool.decide({10, 0, 0, 5}, @allowed, r) == {:refused, :not_permitted}
    assert Pool.decide({10, 0, 0, 1}, {"b.example.com", 443}, r) == {:refused, :not_permitted}
  end
end
