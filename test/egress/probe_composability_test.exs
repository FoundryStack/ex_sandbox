defmodule ExSandbox.Egress.ProbeComposabilityTest do
  @moduledoc """
  The network capability probe must not claim a boundary it cannot enforce
  (005 T060a5, `012-FR-016a`).

  ## The wrong implementation this is written against

  One that reports `network_restriction: true` because `bwrap`, `pasta`, and
  `/dev/net/tun` are all present. Each part exists; the *composition* does not
  work — `pasta` starts its child with `CapEff=0` in a user namespace whose
  mappings it could not write, and `bwrap` then cannot create the mount
  namespace that is its entire purpose.

  ⚠️ **The danger is one-directional and worth naming.** An over-claiming probe
  does not produce a red suite. `require_permitted_reachable/2` scores a refusal
  as a `guarantee_failure`, but every *denial* check still passes — a tenant
  that cannot launch, or one confined to an empty namespace, reaches nothing.
  A boundary permitting nothing is indistinguishable from a correct one under a
  suite that only tests denial. So the probe saying "yes" when the answer is
  "no" converts *we cannot do this* into *we demonstrated this*.

  Under-claiming is safe by comparison: the census reports
  `capability_unavailable`, which is the third outcome `012-FR-016a` exists for.
  """
  use ExUnit.Case, async: true

  describe "the probe's shape" do
    test "network policy is not claimed from the presence of its parts" do
      # ⚠️ Pins the *reasoning*, not the answer, so this test is meaningful on
      # a host where the answer is legitimately `false` for want of `bwrap`.
      #
      # A probe built only from `executable_present?` calls would pass every
      # check that inspects tools and still be wrong, because what fails here
      # is what happens when the tools are combined. The source must show an
      # attempt, not an inventory.
      # ⚠️ Checks the probe *calls* it, not merely that it is defined. The first
      # version of this test asserted the latter and passed under sabotage:
      # deleting the call from `probe_network_policy/0` left the function in
      # place, so a probe that had stopped checking composability entirely still
      # looked correct. Verified by sabotage -- that is how this comment exists.
      source = File.read!("lib/ex_sandbox/hardening/linux.ex")

      [_, probe] = String.split(source, "defp probe_network_policy do", parts: 2)
      probe_body = probe |> String.split("\n  end", parts: 2) |> hd()

      assert probe_body =~ "policed_launch_composable?",
             """
             `probe_network_policy/0` no longer checks whether a policed launch
             can actually be composed.

             Presence of `bwrap`, `pasta`, and `/dev/net/tun` is not sufficient
             and was measured not to be: the two tools do not compose, so a
             probe built from presence alone reports a boundary this mechanism
             cannot enforce. Every denial check would still pass.
             """
    end

    test "composability is decided by running it, not by reading capabilities" do
      # ⚠️ `CapEff` has produced two wrong answers already: rootless Podman
      # grants a full set inside its own user namespace, `--cap-drop=ALL`
      # grants none, and default Docker grants a subset without
      # `CAP_SYS_ADMIN` -- and `bwrap` fails in the last two for reasons no
      # single bit explains. Attempting the composition is the only check that
      # cannot be fooled by a capability set that merely looks sufficient.
      source = File.read!("lib/ex_sandbox/hardening/linux.ex")

      [_, composable] = String.split(source, "defp policed_launch_composable? do", parts: 2)
      body = composable |> String.split("\n  end", parts: 2) |> hd()

      assert body =~ "System.cmd",
             "composability must be attempted, not inferred from a capability bitmask"

      assert body =~ "bwrap",
             "the attempt must include the confinement half; pasta alone always succeeds"
    end
  end
end
