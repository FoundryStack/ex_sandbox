defmodule ExSandbox.Mechanism.BeamContextTest do
  @moduledoc """
  What a mechanism does with the `context` its caller handed it (012 T012, 005
  T060a2).

  ## The claim under test

  `ExSandbox.Sandbox`'s moduledoc says `context` is "stored, compared, and
  **propagated** -- never parsed". A mechanism is free to *add* to it: that is
  how `:address`, `:exec`, and `:connect` reach the conformance suite. It is not
  free to *replace* it, because replacement silently destroys whatever the host
  put there.

  ⚠️ **Why this went unnoticed.** The discarded value is consumed by nobody yet.
  `005` T060a2 resolves a tenant's `network_allowlist` at provision time,
  refuses malformed entries, aborts the provision on an unreadable one -- and
  hands the result to `provision/1` in `context`, where it is dropped. Every
  test of that path passes, because they all assert on the *parse*, and the
  parse is correct. The allowlist is validated and then thrown away, and the
  sandbox that results enforces no policy at all while the provision reports
  success.

  That is the same shape as the `--unshare-net` trap this feature exists to
  close: a boundary that denies everything is indistinguishable from a correct
  one under checks that only test denial. Here it is a boundary that was
  *configured* and never installed.

  These tests do not launch anything. They pin the propagation contract, which
  holds on every host -- the launch path is Linux-only and refuses on macOS
  before `build_context/1` is ever reached, which is precisely why a
  launch-dependent test would not have caught this.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Sandbox

  # The keys a caller of `provision/1` legitimately puts in `context` today.
  # Both come from `Axonn.Sandbox.Provision`'s `:provision_compute` step.
  @host_context %{
    network_allowlist: [{"example.com", 443}],
    data_store_ref: "ds-abc123"
  }

  defp sandbox(context) do
    %Sandbox{
      id: "ctx-#{System.unique_integer([:positive])}",
      owner_ref: "tenant-a",
      template_ref: nil,
      context: context
    }
  end

  describe "the context propagation contract" do
    test "a mechanism's context additions do not destroy the host's entries" do
      # ⚠️ This is the whole finding. `build_context/1` builds a fresh map of
      # three keys and `do_provision/1` assigns it with `context:`, which
      # replaces rather than merges. A host that resolved an allowlist gets a
      # sandbox whose context no longer mentions one.
      #
      # Expressed against the *contract* rather than against `build_context/1`,
      # which is private: whatever a mechanism returns from provision must still
      # carry what its caller put in.
      original = sandbox(@host_context)

      provisioned = simulate_mechanism_context_build(original)

      assert Map.get(provisioned.context, :network_allowlist) == [{"example.com", 443}],
             "the resolved allowlist was discarded: the sandbox enforces no policy while provision reports success"

      assert Map.get(provisioned.context, :data_store_ref) == "ds-abc123",
             "the data store handle was discarded"
    end

    test "a mechanism still publishes its own keys" do
      # The additions must survive too -- a fix that merged the wrong way round
      # would let the host clobber `:address`, breaking the conformance suite
      # instead of the policy. Both directions matter.
      provisioned = simulate_mechanism_context_build(sandbox(@host_context))

      assert Map.has_key?(provisioned.context, :address)
      assert is_function(Map.get(provisioned.context, :exec), 1)
      assert is_function(Map.get(provisioned.context, :connect), 2)
    end

    test "the mechanism's keys win over a host that supplies the same names" do
      # ⚠️ This test exists because the one above passed against a merge in the
      # wrong direction. Asserting the keys are *present* does not distinguish
      # "the mechanism published them" from "the host did" -- with the host
      # winning, `:address` and `:connect` are still present and still the right
      # types, so presence-checking goes green either way.
      #
      # It matters because `:connect` is what the network conformance group
      # probes through. A host able to override it could hand the suite a
      # function that reports success without touching this sandbox, and every
      # network check would pass while measuring nothing.
      hostile =
        sandbox(
          Map.merge(@host_context, %{address: "host-supplied", connect: fn _, _ -> :connected end})
        )

      provisioned = simulate_mechanism_context_build(hostile)

      assert Map.get(provisioned.context, :address) == "peer:" <> hostile.id,
             "the host's :address survived: the suite would report on a handle the mechanism never issued"

      refute Map.get(provisioned.context, :connect) == hostile.context.connect,
             "the host's :connect survived: every network check would probe the host's function, not this sandbox"
    end

    test ":address is not the {host, port} tuple the network group dials" do
      # ⚠️ This is a **deliberate withholding**, and the reason measurement
      # gives is stronger than the one originally recorded.
      #
      # `Conformance.Network.sandbox_address/2` matches only `{host, port}`, so
      # publishing a tuple is what moves the peer-reachability check off the
      # third outcome. It would also make that check meaningless, for a reason
      # that is a property of pasta rather than of anything this project can
      # fix:
      #
      #   **every pasta netns is assigned the host's own address.** Measured
      #   twice (`egress-path-measurements.md`): two sandboxes both come up as
      #   `172.17.0.2`, and A's connect to that address lands on **A's own
      #   listener** while B never accepts.
      #
      # So a tuple of a sandbox's address is not an address that names *that*
      # sandbox from anywhere else. Whatever the check then reported --
      # `:refused` scored as the boundary holding, or `:connected` scored as a
      # breach -- would be a fact about A talking to itself.
      #
      # The originally recorded reason (`{"peer", id}` fails to resolve, and
      # `:refused` is scored as the boundary holding) is true and was never the
      # whole story: it suggests the tuple becomes correct once a real listener
      # exists. It does not. `FR-011c` is satisfied *structurally* -- B's
      # address is not an address A can name -- which is a stronger guarantee
      # than a rule, and precisely why the check cannot be made to demonstrate
      # it by dialling.
      provisioned = simulate_mechanism_context_build(sandbox(@host_context))

      refute match?({_host, _port}, Map.get(provisioned.context, :address)),
             "publishing {host, port} makes the peer check dial an address that " <>
               "resolves to the DIALLING sandbox's own listener, so its verdict " <>
               "describes a sandbox talking to itself rather than a boundary"

      assert is_binary(Map.get(provisioned.context, :address)),
             "`003-FR-022` still asks that a started sandbox carry an address"
    end

    test "a nil host context still yields the mechanism's own keys" do
      # `context` defaults to `nil`, not `%{}` -- a merge that assumes a map
      # would crash every mechanism-only provision, which is most of the suite.
      provisioned = simulate_mechanism_context_build(sandbox(nil))

      assert Map.has_key?(provisioned.context, :address)
      refute Map.has_key?(provisioned.context, :network_allowlist)
    end

    test "an unrecognised host key survives untouched" do
      # `context` is opaque (`FR-007`). A mechanism must not decide which of the
      # host's keys are worth keeping -- it does not know what they mean, and
      # the next host will put something else there.
      provisioned = simulate_mechanism_context_build(sandbox(%{something_future: :opaque}))

      assert Map.get(provisioned.context, :something_future) == :opaque
    end
  end

  describe "policy_handle (005 T060a4, FR-011b, FR-011e)" do
    test "is absent for a sandbox that was never launched, so no policy exists to name" do
      provisioned = simulate_mechanism_context_build(sandbox(@host_context))

      refute Map.has_key?(provisioned.context, :policy_handle)
    end

    @tag :policy_handle
    test "is absent rather than inherited when the host supplies one" do
      # ⚠️ The same provenance rule `:permitted` and `:address` already carry.
      # `attempt_widen_allowlist/2` scores an absent handle as the boundary
      # HOLDING, so a host that could name any unreachable path would have
      # `FR-011b` reported as demonstrated against a mechanism enforcing
      # nothing -- the check's verdict supplied by the party it constrains.
      provisioned =
        simulate_mechanism_context_build(
          sandbox(%{policy_handle: "/tmp/definitely-not-the-policy.sock"})
        )

      refute Map.has_key?(provisioned.context, :policy_handle)
    end

    test "an unlaunched sandbox makes the suite report the third outcome, not a pass" do
      # ⚠️ The end-to-end consequence, asserted through the real check rather
      # than by inspecting the key. `attempt_widen_allowlist/2` raises
      # `CapabilityUnavailable` when the handle is undeclared -- honest, and
      # counted in the census as a gap. The failure this pins is the opposite
      # one: publish a handle for an `--unshare-net` sandbox and the check
      # instead returns `{:refused, {:policy_not_visible, _}}`, scoring
      # `FR-011b` as demonstrated for a sandbox that has no egress policy to
      # widen in the first place.
      provisioned = simulate_mechanism_context_build(sandbox(@host_context))

      assert_raise ExSandbox.Conformance.CapabilityUnavailable, fn ->
        ExSandbox.Conformance.Network.attempt_widen_allowlist(
          ExSandbox.Mechanism.Beam,
          provisioned
        )
      end
    end
  end

  # Mirrors `do_provision/1`'s context construction without launching a node.
  # `build_context/1` is private and the launch path refuses off Linux, so this
  # reproduces the one expression under test:
  #
  #     %{sandbox | mechanism_ref: sandbox.id, context: build_context(sandbox)}
  #
  # ⚠️ A mirror is weaker evidence than the real call, and is used here only
  # because the real call is unreachable on this host. It is kept to a single
  # expression so the drift it can hide is small, and the launch-path test in
  # the isolation container exercises the genuine article.
  defp simulate_mechanism_context_build(%Sandbox{} = sandbox) do
    %{sandbox | mechanism_ref: sandbox.id, context: ExSandbox.Mechanism.Beam.context_for(sandbox)}
  end
end
