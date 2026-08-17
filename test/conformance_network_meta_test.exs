defmodule ExSandbox.ConformanceNetworkMetaTest do
  @moduledoc """
  The network group fails a mechanism that confines no network (005 T060b,
  T060d).

  ## The same argument as `ExSandbox.ConformanceMetaTest`, one guarantee over

  A network check written as "assert the sandbox did not reach anything" passes
  against a mechanism with no confinement whenever the destination happens to
  be down, the DNS lookup happens to fail, or the address happens to be
  unroutable. It is not a weak check; it is not a check.

  So `ExSandbox.PorousMechanism` — which runs every command in the host's own
  unconfined shell — is pointed at the group here, and the denial checks must
  **fail** against it. If one passes, it is measuring its own inability to
  connect rather than a boundary, and it would report a mechanism with no
  network isolation as conformant.

  ## Why the permitted half is asserted separately

  The porous mechanism declares no allowlist, so the permitted-direction check
  must report the **third outcome** rather than passing or failing. That is the
  distinction `FR-011d` turns on: a mechanism that denies everything has not
  implemented the permitted half, and it must not be able to collect a green
  tick for the half it never wrote.

  A group where the permitted check quietly passed against a mechanism with no
  allowlist would rank deny-everything above a real allowlist implementation,
  which is the exact incentive `005-FR-011a` was written to remove.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.SuiteRunner

  # Named individually rather than matched by prefix: a prefix match would
  # absorb the permitted-direction check, whose expected outcome is different,
  # and silently weaken this into asserting nothing about it.
  @denial_checks [
    "reaching another sandbox over the network is refused",
    "reaching the platform's own listening port is refused",
    "a destination outside the environment's allowlist is refused"
  ]

  # ⚠️ Excluded from the "must fail / must not be unavailable" assertions
  # below, and the exclusion is a real weakening that has to be named.
  #
  # This check is gated on a host control probe against the same denied address
  # (`005-FR-011c`, T060j). On a host that cannot itself route to TEST-NET-1 --
  # which is every host in practice, because no operator routes it -- the check
  # reports the third outcome for a correct reason: from inside and outside the
  # sandbox alike the address is silent, so silence attributes to nothing.
  #
  # Before that gate existed, this check PASSED against `PorousMechanism`. The
  # third outcome is strictly better than that, but it means the check is
  # demonstrated only where a real allowlist makes a reachable destination
  # denied -- which is what 005 T060a builds, and what T060a8 measures.
  @host_gated_check "a destination outside the environment's allowlist is refused"

  @unconditional_denial_checks @denial_checks -- [@host_gated_check]

  @permitted_check "a destination inside the environment's allowlist is reachable"

  @widening_check "the allowlist cannot be widened from inside the sandbox"
  @peer_check "reaching another sandbox over the network is refused"

  defp names(results) do
    Enum.map(results.passed, &Atom.to_string/1) ++
      Enum.map(results.failures ++ results.unavailable, fn {n, _} -> Atom.to_string(n) end)
  end

  defp matching(list, check) do
    Enum.filter(list, fn
      {name, _} -> Atom.to_string(name) =~ check
      name -> Atom.to_string(name) =~ check
    end)
  end

  defp network_results(mechanism), do: SuiteRunner.run(mechanism, describe: "network")

  test "every check named here still exists in the group" do
    # Guards the lists above. A renamed check would make every assertion below
    # vacuous by matching nothing, and they would all stay green -- the failure
    # mode this whole file exists to catch, arriving through its own guard.
    present = names(network_results(ExSandbox.PorousMechanism))

    for check <- [@permitted_check, @widening_check, @peer_check | @denial_checks] do
      assert Enum.any?(present, &String.contains?(&1, check)),
             "no network check named #{inspect(check)} -- this file's lists are stale"
    end
  end

  describe "against a mechanism that confines no network" do
    test "the group runs at all" do
      results = network_results(ExSandbox.PorousMechanism)

      assert names(results) != [],
             "the network group produced no results, so it is not running"
    end

    test "every denial check fails" do
      results = network_results(ExSandbox.PorousMechanism)

      wrongly_passed =
        Enum.flat_map(@unconditional_denial_checks, &matching(results.passed, &1))

      assert wrongly_passed == [],
             """
             These network checks PASSED against a mechanism that runs every command
             in the host's own unconfined shell:

               #{Enum.map_join(wrongly_passed, "\n  ", &inspect/1)}

             A check that passes here is measuring its own inability to connect --
             a destination that is down, a name that does not resolve, an address
             that is unroutable -- rather than a boundary that stopped it. It
             would report a mechanism with no network isolation as conformant,
             which is 003-FR-002 asserted by a contract that does not test it.
             """
    end

    test "no denial check that could run reports the third outcome" do
      # ⚠️ Scoped to the checks `PorousMechanism` gives the suite enough to
      # attempt, and the scoping is the point.
      #
      # That mechanism declares no `:address` and no `:policy_handle`, so those
      # two checks report the third outcome -- correctly. A mechanism that never
      # claimed to confine the network has not violated a guarantee it never
      # made (`FR-011e`), and reporting an undeclared handle as a breach sends a
      # reader looking for a defect that is not there.
      #
      # The checks it *can* attempt must still fail. And the case this scoping
      # would otherwise let through -- a mechanism that declares the handles and
      # confines nothing anyway -- is covered by `OpenNetworkMechanism` below,
      # which is the reason that fixture exists.
      results = network_results(ExSandbox.PorousMechanism)

      attemptable = ["reaching the platform's own listening port is refused"]

      wrongly_unavailable = Enum.flat_map(attemptable, &matching(results.unavailable, &1))

      assert wrongly_unavailable == [],
             """
             These network checks reported "host capability unavailable" against a
             mechanism that confines nothing, and had everything they needed to
             attempt the act:

               #{Enum.map_join(wrongly_unavailable, "\n  ", &inspect/1)}

             The third outcome is for a boundary that could not be *probed*. A
             mechanism that let the connection through has demonstrated the
             opposite, and reporting it as undemonstrated hides a real violation
             behind an honest-sounding label.
             """
    end

    test "the permitted-direction check reports the third outcome, not a pass" do
      results = network_results(ExSandbox.PorousMechanism)

      passed = matching(results.passed, @permitted_check)
      unavailable = matching(results.unavailable, @permitted_check)

      assert passed == [],
             """
             The permitted-direction check PASSED against a mechanism that declares
             no allowlist at all.

             `FR-011d` requires both directions, and this is the half a
             deny-everything mechanism cannot implement. A pass here means the
             suite scores "no allowlist" the same as a working one -- which ranks
             a sandbox that cannot serve a webhook or call an API above one that
             can, and removes every incentive to build the allowlist 005-FR-011a
             requires.
             """

      assert unavailable != [],
             """
             The permitted-direction check neither passed nor reported the third
             outcome against a mechanism with no allowlist.

             It must report `capability_unavailable`: declaring no permitted
             destinations is an unfinished mechanism, not a violated guarantee,
             and the difference has to stay visible in the census.
             """
    end
  end

  describe "against a mechanism that declares a boundary and enforces none" do
    # ⚠️ The shape the scoping above would otherwise let through, and the reason
    # `OpenNetworkMechanism` exists. It publishes `:address`, `:permitted`,
    # `:policy_handle`, and a `:connect` that reports success unconditionally --
    # so every "the mechanism did not declare it" excuse is gone and the group
    # has to produce a verdict on the guarantee itself.
    test "every denial check fails, and none reports the third outcome" do
      results = network_results(ExSandbox.OpenNetworkMechanism)

      wrongly_passed = Enum.flat_map(@denial_checks, &matching(results.passed, &1))

      # ⚠️ Third-outcome assertion scoped to the checks that do not depend on
      # the host being able to route to the denied address. This mechanism's
      # `connect` reports success unconditionally, so it must still FAIL every
      # denial check (asserted above, unscoped) -- but the host-gated one can
      # legitimately report unavailable before it ever reaches `connect`.
      wrongly_unavailable =
        Enum.flat_map(@unconditional_denial_checks, &matching(results.unavailable, &1))

      assert wrongly_passed == [],
             """
             These network checks PASSED against a mechanism whose `connect`
             reports success for every destination:

               #{Enum.map_join(wrongly_passed, "\n  ", &inspect/1)}
             """

      assert wrongly_unavailable == [],
             """
             These network checks reported "host capability unavailable" against a
             mechanism that DECLARED its handles and then let every connection
             through:

               #{Enum.map_join(wrongly_unavailable, "\n  ", &inspect/1)}

             Once a mechanism declares a boundary, failing to enforce it is a
             violation and nothing else. The third outcome here would file a
             real breach under the same label as an unfinished mechanism.
             """
    end

    test "the permitted-direction check passes" do
      # The one check this mechanism should clear: it declares a permitted
      # destination and reaches it. A group that failed here would be unable to
      # distinguish "reaches what it should" from "reaches everything", and
      # `FR-011d` needs both halves to be separately observable.
      results = network_results(ExSandbox.OpenNetworkMechanism)

      assert matching(results.passed, @permitted_check) != [],
             """
             The permitted-direction check did not pass against a mechanism that
             declares a permitted destination and connects to it.

             Failures: #{inspect(matching(results.failures, @permitted_check))}
             Unavailable: #{inspect(matching(results.unavailable, @permitted_check))}
             """
    end
  end

  describe "against a mechanism with no runner" do
    test "no denial check passes by declining to attempt anything" do
      # `EchoMechanism` carries no `context.exec`, so no network act can be
      # attempted. Every check must be inconclusive -- which `require_refused/2`
      # treats as a failure -- and none may pass.
      #
      # This is the shape the `{:no_runner, _}` and `{:no_probe, _}` returns in
      # the group exist for: had they been `{:refused, _}`, a mechanism that
      # cannot run a single command would pass every denial check in this group
      # by never trying.
      results = network_results(ExSandbox.EchoMechanism)

      wrongly_passed =
        Enum.flat_map(@denial_checks, &matching(results.passed, &1))

      assert wrongly_passed == [],
             """
             These network checks PASSED against a mechanism that cannot run any
             command inside a sandbox:

               #{Enum.map_join(wrongly_passed, "\n  ", &inspect/1)}

             Declining to attempt a connection is not evidence of a boundary.
             """
    end
  end

  describe "against a mechanism whose allowlist is enforced but editable" do
    # ⚠️ The shape a first implementation actually produces, and the reason
    # `EditablePolicyMechanism` exists. Its allowlist is real: denied
    # destinations are refused, the permitted one is reachable, peers are
    # separated. Four of five checks pass honestly. Its only defect is that the
    # policy lives where tenant code can append to it.
    #
    # `OpenNetworkMechanism` cannot establish this. Everything fails there, so a
    # green assertion says "something failed" rather than "FR-011b caught it" --
    # consistent with a widening check that had rotted into always-failing.
    test "the allowlist-widening check fails" do
      results = network_results(ExSandbox.EditablePolicyMechanism)

      assert matching(results.failures, @widening_check) != [],
             """
             The allowlist-widening check did not FAIL against a mechanism whose
             policy file tenant code can append to.

             Passed:      #{inspect(matching(results.passed, @widening_check))}
             Unavailable: #{inspect(matching(results.unavailable, @widening_check))}

             This mechanism enforces its allowlist for real -- every connection
             the suite attempts is decided correctly -- and stores it inside the
             confined space. `FR-011b` is the only check in the group that can
             tell an enforced boundary from one its own subject can rewrite, so
             a pass or a third outcome here means the group cannot make that
             distinction at all.
             """
    end

    test "the other four checks still pass" do
      # ⚠️ Guards the opposite failure, and it is the half that keeps the
      # fixture honest. A widening check that failed everything would satisfy
      # the assertion above while telling a conformant mechanism it had leaked.
      # Requiring the other four to pass pins this fixture to failing exactly
      # one guarantee -- so the test above is attributable to `FR-011b` and not
      # to a mechanism that is broken in some unrelated way.
      results = network_results(ExSandbox.EditablePolicyMechanism)

      # ⚠️ Excludes @host_gated_check for the same reason as above: it reports
      # the third outcome on any host that cannot route to TEST-NET-1, which is
      # a property of the internet rather than of this fixture. Including it
      # would make this guard fail for a reason having nothing to do with the
      # editable policy it exists to attribute.
      expected = [@permitted_check | @unconditional_denial_checks]
      passed = Enum.flat_map(expected, &matching(results.passed, &1))

      not_passed =
        Enum.flat_map(expected, fn check ->
          matching(results.failures, check) ++ matching(results.unavailable, check)
        end)

      assert not_passed == [],
             """
             These checks did not pass against a mechanism that enforces a real
             allowlist and separates its sandboxes:

               #{Enum.map_join(not_passed, "\n  ", &inspect/1)}

             Only `FR-011b` should fail here. If others do, the widening result
             above is not attributable to the editable policy, and this fixture
             establishes nothing about that check.
             """

      assert length(passed) == length(expected),
             "expected all #{length(expected)} non-widening checks to pass, got #{length(passed)}"

      # The host-gated check must not PASS here either -- unavailable is the
      # only acceptable non-failing outcome for it.
      assert matching(results.passed, @host_gated_check) == [],
             """
             The host-gated denied-destination check PASSED against a mechanism
             whose allowlist tenant code can widen.

             It is gated on a host control probe precisely so it cannot report a
             pass it did not earn (T060j).
             """
    end
  end

  describe "against a mechanism that puts every sandbox on one shared route" do
    # ⚠️ The topological defect, and the only fixture that can prove the
    # peer-crossing check does any work. Against `PorousMechanism` that check
    # reports the third outcome (no `:address`); against `OpenNetworkMechanism`
    # it fails alongside everything else. Both are consistent with a check that
    # never attempts a real crossing and merely trusts the declared topology.
    test "the peer-crossing check fails" do
      results = network_results(ExSandbox.SharedRouteMechanism)

      assert matching(results.failures, @peer_check) != [],
             """
             The peer-crossing check did not FAIL against a mechanism that puts
             every sandbox on one shared route.

             Passed:      #{inspect(matching(results.passed, @peer_check))}
             Unavailable: #{inspect(matching(results.unavailable, @peer_check))}

             This mechanism enforces a real, host-side, unwritable allowlist --
             every outward-facing check passes honestly -- and shares one link
             between sandboxes, so A can open a socket to B's published address.
             That is precisely what `005-FR-011c`'s "no shared bridge" forbids
             and what `003-FR-002` guarantees.

             A pass here means the check is reading the declared topology rather
             than attempting the crossing, which T060a8 requires it not to do.
             """
    end

    test "the outward-facing checks still pass" do
      # The same attribution guard as above: this fixture must fail exactly
      # `003-FR-002`, so the result above cannot be explained by anything else.
      results = network_results(ExSandbox.SharedRouteMechanism)

      # ⚠️ @host_gated_check deliberately absent -- see the note on that
      # attribute. Its third outcome here is a fact about routing, not about
      # this fixture's shared route.
      expected = [@permitted_check, @widening_check]

      not_passed =
        Enum.flat_map(expected, fn check ->
          matching(results.failures, check) ++ matching(results.unavailable, check)
        end)

      assert not_passed == [],
             """
             These outward-facing checks did not pass against a mechanism whose
             only defect is a route shared between sandboxes:

               #{Enum.map_join(not_passed, "\n  ", &inspect/1)}

             If they fail, the peer-crossing failure above is not attributable
             to the shared route.
             """
    end
  end
end
