defmodule ExSandbox.Egress.ProbeComposabilityTest do
  @moduledoc """
  The network capability probe must not claim a boundary it cannot enforce
  (005 T060a5, `012-FR-016a`).

  ## The wrong implementation this is written against

  One that reports `network_restriction: true` because `bwrap`, `pasta`, and
  `/dev/net/tun` are all present. Each part exists; the *composition* may not
  work.

  ⚠️ **There are two such wrong implementations, and the second was written
  here before it was caught.** The first builds the answer from an inventory of
  tools. The second attempts a composition — but the *wrong* one:

      unshare --user --map-root-user --net -- bwrap --dev-bind / / -- /bin/true

  That succeeds under default `docker run`, where the egress path is
  nonetheless unpoliceable: the host cannot `setns()` into a namespace owned by
  a user namespace it does not control, so `pasta` and the `nft` redirect are
  both refused. Measured — see `egress-path-measurements.md`.

  ⚠️ **Confining the tenant is the easy half and proves nothing.** The half that
  decides the capability is whether the platform can *enter* a namespace it did
  not create, because that is what installing the policy requires.

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

    test "the probe attempts entry into a namespace it did not create" do
      # ⚠️ This is the half that decides the capability, and it is the half a
      # plausible-looking probe omits. Measured under default `docker run`:
      # `unshare -Urn -- bwrap ...` returns 0 while `nsenter` into that same
      # namespace returns "reassociate to namespaces failed: Operation not
      # permitted". A probe checking only the first reports a policed egress
      # path on a host that has none.
      #
      # ⚠️ And it must be a **foreign** namespace. Entering one this process
      # created itself always succeeds, so a probe that did that would pass on
      # exactly the hosts it exists to reject -- vacuous in the one direction
      # that matters.
      source = File.read!("lib/ex_sandbox/hardening/linux.ex")

      [_, composable] = String.split(source, "defp policed_launch_composable? do", parts: 2)
      body = composable |> String.split("\n  end", parts: 2) |> hd()

      assert body =~ "can_enter_foreign_netns?",
             """
             `policed_launch_composable?/0` no longer checks whether this host
             can enter a network namespace it did not create.

             Creating a confined namespace is not the capability. Installing the
             `nft` redirect and attaching `pasta` both require `setns()` into
             the tenant's namespace, which needs CAP_SYS_ADMIN in the user
             namespace owning it. Without that check the probe reports `true`
             for a sandbox that is isolated and unpoliced -- and every denial
             check passes against it.
             """

      # ⚠️ Read from `await_foreign_netns/2`, which is where the foreignness
      # check lives now that the entry probe polls. The polling is not
      # cosmetic: `Port.open` returns before `unshare` has entered its new
      # namespaces, and reading `/proc/<pid>/ns/net` once saw the **host**
      # namespace in 16 of 20 measured trials -- so a single-read probe reports
      # the capability absent on a capable host, most of the time.
      [_, enter] = String.split(source, "defp await_foreign_netns(pid, attempts) do", parts: 2)
      enter_body = enter |> String.split("\n  end", parts: 2) |> hd()

      assert enter_body =~ "foreign_netns?",
             """
             The entry probe no longer confirms the namespace is foreign.

             Entering a namespace this process created itself always succeeds,
             so dropping that check makes the probe pass on precisely the hosts
             it exists to reject.
             """
    end

    test "both copies of the probe answer the same question" do
      # ⚠️ `:network_restriction` is answered by two independent implementations,
      # and them disagreeing is a defect this codebase has already carried
      # (005 T060a5c). `ExSandbox.provision/2` consults `Capability`;
      # `require_hardening/0` consults `Hardening.Linux`. When they disagreed,
      # "this host cannot police egress" was reported as thirty phantom
      # conformance failures with no cause attached -- checks like "halting the
      # host from inside the sandbox is refused", which had not stopped being
      # true.
      #
      # ⚠️ Pinned by a test rather than by a comment asking future edits to keep
      # them in sync, because the last time it drifted the comment was already
      # there. Compares the executable bodies with comments and blank lines
      # stripped: the prose may differ, the operations attempted may not.
      bodies =
        for file <- ["lib/ex_sandbox/hardening/linux.ex", "lib/ex_sandbox/capability.ex"] do
          source = File.read!(file)

          for fun <- [
                "defp unshare_and_bwrap_compose? do",
                "defp attempt_foreign_netns_entry(unshare) do",
                "defp await_foreign_netns(pid, attempts) do",
                "defp nsenter_succeeds?(pid) do"
              ] do
            [_, tail] = String.split(source, fun, parts: 2)

            tail
            |> String.split("\n  end", parts: 2)
            |> hd()
            |> String.split("\n")
            |> Enum.map(&String.trim/1)
            |> Enum.reject(&(&1 == "" or String.starts_with?(&1, "#")))
          end
        end

      assert hd(bodies) == List.last(bodies),
             """
             The two `:network_restriction` probes have drifted.

             `ExSandbox.provision/2` consults `Capability` and
             `require_hardening/0` consults `Hardening.Linux`. If they answer
             differently about the same host, a missing capability is reported
             as a pile of conformance failures naming guarantees that never
             stopped holding, with nothing pointing at the real cause.
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

      # ⚠️ Read from the two helpers rather than from
      # `policed_launch_composable?/0` itself, which now delegates to them. An
      # earlier version of this assertion read only the delegating function and
      # failed the moment the probe grew its second half -- correctly, since the
      # `System.cmd` really had moved, but for a change that strengthened the
      # probe rather than weakening it. What must be pinned is that *both* halves
      # run a command; where the calls live is not the property.
      [_, compose] = String.split(source, "defp unshare_and_bwrap_compose? do", parts: 2)
      compose_body = compose |> String.split("\n  end", parts: 2) |> hd()

      [_, nsenter] = String.split(source, "defp nsenter_succeeds?(pid) do", parts: 2)
      nsenter_body = nsenter |> String.split("\n  end", parts: 2) |> hd()

      assert compose_body =~ "System.cmd",
             "composability must be attempted, not inferred from a capability bitmask"

      assert compose_body =~ "bwrap",
             "the attempt must include the confinement half; pasta alone always succeeds"

      assert nsenter_body =~ "System.cmd",
             "namespace entry must be attempted, not inferred -- it is the half " <>
               "that decides whether the tenant can be policed at all"
    end
  end

  describe "the probe measures the sequence the mechanism actually performs" do
    # ⚠️ Both assertions here pin a flag whose ABSENCE produced a false `false`:
    # the probe reported `network_restriction: false` on a host that runs the
    # design perfectly well. That direction is the dangerous one to leave
    # untested, because an under-claiming probe is invisible in the census --
    # it reads as the honest third outcome rather than as a broken check.
    setup do
      %{
        sources:
          Enum.map(
            [
              "lib/ex_sandbox/hardening/linux.ex",
              "lib/ex_sandbox/capability.ex"
            ],
            &File.read!/1
          )
      }
    end

    test "the sandbox netns is created INSIDE one platform userns, not beside it",
         %{sources: sources} do
      for source <- sources do
        [_, entry] = String.split(source, "defp attempt_foreign_netns_entry(unshare) do", parts: 2)
        body = entry |> String.split("\n  end", parts: 2) |> hd()

        # The outer namespace is created once, with a uid map, and the inner
        # `unshare` takes `--net` ALONE. An inner `--user` would put the netns
        # in a sibling user namespace, where `setns()` is correctly refused --
        # which is precisely the measurement that made this path look
        # "unobtainable by construction" for two sessions.
        assert body =~ "--map-root-user",
               "the platform must own a user namespace; without one it holds no " <>
                 "CAP_SYS_ADMIN over the netns it creates"

        assert body =~ "unshare --net",
               "the sandbox netns must be created as a DESCENDANT of that userns"

        refute body =~ "unshare --net --user",
               "an inner --user recreates the sibling-userns shape this probe " <>
                 "exists to distinguish from a genuine host limitation"
      end
    end

    # ⚠️ This test exists because the equivalent SABOTAGE SURVIVED the whole
    # suite. Removing `--unshare-user` from the bwrap probe left all 331 tests
    # green: on macOS `bwrap` is absent, so the branch never runs, and in the
    # container the flag's absence only *under*-claims. It is the fourth
    # instance of the same species as the unsupervised pool, the unreferenced
    # `Binding`, and the unwired relay -- a defect no host-side test can reach,
    # so it is pinned at the source instead.
    test "bwrap is probed with the flags the mechanism actually launches with",
         %{sources: sources} do
      for source <- sources do
        # Both copies express this differently -- `can_unshare?/1` in the
        # hardening module, `unshares?/1` in `Capability` -- so match on the
        # command construction rather than on a function name.
        probes =
          Regex.scan(~r/defp (?:can_unshare\?|unshares\?)\(flag\)(?:,\s*do:)?(.{0,400})/s, source)

        assert probes != [], "neither copy defines a bwrap unshare probe"

        for [_, body] <- probes do
          assert body =~ "--unshare-user",
                 "without --unshare-user, bwrap builds its mount namespace in the " <>
                   "HOST userns and needs CAP_SYS_ADMIN -- so this probes a command " <>
                   "the mechanism never runs and reports false on every " <>
                   "unprivileged host"
        end
      end
    end

    test "entering the netns also joins the userns that owns it", %{sources: sources} do
      for source <- sources do
        [_, nsenter] = String.split(source, "defp nsenter_succeeds?(pid) do", parts: 2)
        body = nsenter |> String.split("\n  end", parts: 2) |> hd()

        # Measured, same host, same pid:
        #   nsenter -t <pid> -n ip link                          -> EPERM
        #   nsenter -t <pid> -n -U --preserve-credentials ...    -> OK
        #
        # The BEAM runs OUTSIDE the sandbox userns, so it holds nothing there
        # until it joins. Dropping `-U` does not weaken the probe subtly -- it
        # makes it answer `false` everywhere.
        assert body =~ "\"-U\"",
               "the BEAM is outside the sandbox userns; entering the netns " <>
                 "without joining its owning userns is refused"

        assert body =~ "--preserve-credentials",
               "util-linux requires it when joining a userns the caller is not " <>
                 "already privileged in"
      end
    end
  end
end
