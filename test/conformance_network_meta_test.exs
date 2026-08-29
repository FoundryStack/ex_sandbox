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

  # ⚠️ Named in the existence guard below and in NO outcome assertion, and the
  # omission is deliberate rather than an oversight (029 T004, T005).
  #
  # Both checks were added to make requirements the group could not see
  # measurable at all: `029-FR-012`'s name matching (every permitted destination
  # the suite named was an IP literal) and `029-FR-013`'s UDP (every probe was
  # `:gen_tcp` against a policy that is `meta l4proto tcp`). Their outcome
  # against these fixtures is not yet a fact this file can pin -- neither
  # `PorousMechanism` nor `EditablePolicyMechanism` declares a `:udp_probe`, so
  # the UDP check reports the third outcome against every one of them, which
  # says nothing about the fixture.
  #
  # Guarding their *existence* is what this file can honestly do today: it stops
  # a rename from making them vanish, which is the failure the guard below
  # exists to catch.
  @permitted_name_check "a permitted destination named by HOSTNAME is reachable"
  @udp_check "UDP egress is confined the same as TCP"

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

    for check <- [
          @permitted_check,
          @permitted_name_check,
          @udp_check,
          @widening_check,
          @peer_check | @denial_checks
        ] do
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

      # ⚠️ `@denial_checks`, not `@unconditional_denial_checks`: the host-gated
      # denied-destination check is included here for the first time (005
      # T060a4/T060j).
      #
      # It was excluded while the denied address was TEST-NET-1, which no
      # operator routes -- the control probe said `:no`, so it reported the
      # third outcome on every host and could not be asserted either way. With a
      # genuinely reachable denied address the control succeeds and the check
      # runs. Measured against this fixture: it FAILS, with the evidence "the
      # sandbox opened a connection to a denied destination (8.8.8.8:53)".
      #
      # That is the whole of T060j. The check went from passing vacuously
      # (`nc`'s bound ignored, exit 124 scored as a drop) to honestly
      # unavailable to actually discriminating, and only the last of those three
      # detects a mechanism with no policy.
      wrongly_passed = Enum.flat_map(@denial_checks, &matching(results.passed, &1))

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

    test "the other checks still pass" do
      # ⚠️ Guards the opposite failure, and it is the half that keeps the
      # fixture honest. A widening check that failed everything would satisfy
      # the assertion above while telling a conformant mechanism it had leaked.
      # Requiring the others to pass pins this fixture to failing exactly
      # one guarantee -- so the test above is attributable to `FR-011b` and not
      # to a mechanism that is broken in some unrelated way.
      results = network_results(ExSandbox.EditablePolicyMechanism)

      # ⚠️ Excludes @host_gated_check for the same reason as above: it reports
      # the third outcome on any host that cannot route to TEST-NET-1, which is
      # a property of the internet rather than of this fixture. Including it
      # would make this guard fail for a reason having nothing to do with the
      # editable policy it exists to attribute.
      #
      # ⚠️ Excludes @peer_check because this test REQUIRED A FALSE PASS until
      # 2026-08-29 (029 T034d). This fixture publishes a distinct port per
      # sandbox and `editable_policy_mechanism.ex` says in its own comment that
      # nothing listens on it, so the refusal it produced was the refusal any
      # dead port produces -- from a mechanism with a boundary or without one
      # alike. `attempt_reach_sandbox/3` now asks whether the platform can
      # reach that address before crediting the refusal, and the honest verdict
      # here is the third outcome. The test below pins that, so this fixture is
      # still held to a definite verdict rather than to "anything but a
      # failure".
      expected = [@permitted_check | @unconditional_denial_checks -- [@peer_check]]
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

      # ⚠️ The third outcome, asserted positively rather than left as "not a
      # failure". Excluding the peer check from the list above would otherwise
      # let it drift back to passing, which is the exact state 029 T034d was
      # opened to end.
      assert matching(results.unavailable, @peer_check) != [],
             """
             The peer-crossing check did not report the third outcome against a
             mechanism that publishes an address with nothing listening on it.

             Passed:   #{inspect(matching(results.passed, @peer_check))}
             Failures: #{inspect(matching(results.failures, @peer_check))}

             A refusal at a dead port is what a mechanism with no boundary
             produces. Crediting it as a pass is `029-FR-015`'s control that
             reads as the guarantee it is not, and this fixture is the one that
             makes it visible.
             """

      # ⚠️ The host-gated check must not FAIL here. It may pass or report the
      # third outcome, and which one is a fact about this host's egress.
      #
      # This assertion used to read "must not PASS", and that was wrong for a
      # reason worth keeping. It was written when the denied destination was
      # TEST-NET-1, which nobody routes, so the control probe said `:no`
      # everywhere and `unavailable` was the only outcome reachable -- the
      # assertion described the internet, not the fixture. With a genuinely
      # reachable denied address (005 T060a4) the control succeeds, the check
      # runs for real, and `EditablePolicyMechanism` **refuses** it because its
      # allowlist is genuinely enforced. A pass here is now earned rather than
      # unearned, which is exactly what T060j asked for.
      #
      # What must still never happen is a *failure*: this fixture's only defect
      # is a writable policy, so a denial check failing against it would not be
      # attributable to the thing the fixture exists to isolate.
      assert matching(results.failures, @host_gated_check) == [],
             """
             The host-gated denied-destination check FAILED against a mechanism
             that genuinely refuses denied destinations.

             Its only intended defect is a policy tenant code can widen, so a
             denial failure here is not attributable to it.
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

  describe "the permitted/denied destination pair (005 T060a4, FR-011c, FR-011d)" do
    setup do
      original = Application.get_env(:ex_sandbox, :conformance)
      on_exit(fn -> restore_conformance_env(original) end)
      :ok
    end

    test "the two destinations differ, or FR-011c asks a mechanism to refuse what it permits" do
      # ⚠️ The failure this guards is silent and inverted. With the pair equal,
      # the sandbox's own allowlist permits the address the denial check probes,
      # so a CORRECT mechanism lets the connection through and fails
      # `FR-011c`, while a mechanism ignoring its allowlist entirely refuses it
      # and PASSES. The suite would rank a broken mechanism above a working one.
      Application.put_env(:ex_sandbox, :conformance,
        permitted_destination: {"1.1.1.1", 443},
        denied_destination: {"1.1.1.1", 443}
      )

      assert_raise ArgumentError, ~r/permitted and denied destinations are the same/, fn ->
        ExSandbox.Conformance.Network.denied_address()
      end
    end

    test "a deployment can name its own pair rather than recording a permanent gap" do
      Application.put_env(:ex_sandbox, :conformance,
        permitted_destination: {"permitted.internal", 8443},
        denied_destination: {"denied.internal", 9443}
      )

      assert ExSandbox.Conformance.Network.permitted_address() == {"permitted.internal", 8443}
      assert ExSandbox.Conformance.Network.denied_address() == {"denied.internal", 9443}
    end

    test "the defaults are a reachable pair, not a black hole" do
      # ⚠️ Pins the property that made the old default useless rather than the
      # literal addresses. `attempt_reach_denied_host/2` gates on a host control
      # probe against the denied address, so a documentation-reserved or
      # otherwise unrouted default makes the check report the third outcome on
      # every host forever -- which is what `203.0.113.1` did. This asserts the
      # defaults are not drawn from the reserved ranges that guarantee that.
      restore_conformance_env(nil)

      {denied_host, _} = ExSandbox.Conformance.Network.denied_address()
      {permitted_host, _} = ExSandbox.Conformance.Network.permitted_address()

      for host <- [denied_host, permitted_host] do
        refute host =~ ~r/^(203\.0\.113\.|198\.51\.100\.|192\.0\.2\.)/,
               """
               #{host} is in an RFC 5737 documentation range, which no operator
               routes. A check gated on the host reaching it can never run.
               """
      end
    end

    test "the permitted destination is dialable, so a mechanism can publish it" do
      # `Mechanism.Beam.put_permitted/1` publishes only entries matching
      # `{binary, integer}`; an `:any_port` entry is dropped. A default the
      # mechanism cannot publish leaves `:permitted` absent and the census
      # reporting `:no_allowlist` -- the exact gap this pair exists to close.
      restore_conformance_env(nil)

      assert {host, port} = ExSandbox.Conformance.Network.permitted_address()
      assert is_binary(host)
      assert is_integer(port)
    end
  end

  describe "the allowlist flag (005 T060a4)" do
    setup do
      original = Application.get_env(:ex_sandbox, :conformance)
      on_exit(fn -> restore_conformance_env(original) end)
      :ok
    end

    test "is ON by default, so the checks measure a boundary rather than skipping" do
      # ⚠️ The default INVERTED once T060a4e landed, and the direction matters.
      # It was off while the policed launch could not boot: on, all five network
      # checks failed honestly with `:mechanism_error`, but they aborted the
      # credentials phase before the isolation phase ran, costing every other
      # measurement in the census for nothing gained.
      #
      # With the launch bootable (`systemd-run -- setpriv -- pasta -- bwrap`,
      # measured) the trade reverses: off is now the setting that costs
      # measurement, because the checks report the third outcome forever and the
      # permit direction -- the only half that can tell an allowlist from
      # blanket denial -- is never exercised.
      restore_conformance_env(nil)

      assert %{network_allowlist: [_ | _]} = ExSandbox.Conformance.Network.suite_context()
    end

    test "can still be turned off explicitly, and off is honoured" do
      Application.put_env(:ex_sandbox, :conformance, allowlist_enabled: false)

      assert ExSandbox.Conformance.Network.suite_context() == %{}
    end

    test "carries the allowlist when enabled, which is what makes the checks real" do
      Application.put_env(:ex_sandbox, :conformance,
        allowlist_enabled: true,
        permitted_destination: {"permitted.internal", 8443}
      )

      # ⚠️ TWO entries since 029 T004, and the second is load-bearing. The IP
      # literal is what the existing permit check derives from; the hostname is
      # the only reason `029-FR-012`'s name matching is reachable from this
      # suite at all -- with an all-literal allowlist no check ever asks a
      # sandbox to reach a destination it knows by name.
      assert ExSandbox.Conformance.Network.suite_context() == %{
               network_allowlist: [
                 {"permitted.internal", 8443},
                 ExSandbox.Conformance.Network.permitted_name_address()
               ]
             }
    end

    test "off is not an exclusion: the checks still report, they do not vanish" do
      # ⚠️ `012-FR-011` forbids a consumer switching a check off. This flag does
      # not do that -- with it off the group still RUNS and reports
      # `capability_unavailable`, which the census counts against the baseline.
      # A mechanism gets no credit for a check it did not run. The assertion is
      # on the census-visible outcome rather than on the flag, because that is
      # the property that matters.
      # ⚠️ Set explicitly rather than relying on the default, which now carries
      # an allowlist. This test is about what OFF does, so it must actually be
      # off -- reading the default here would silently stop testing the flag.
      Application.put_env(:ex_sandbox, :conformance, allowlist_enabled: false)

      results = network_results(ExSandbox.PorousMechanism)

      assert names(results) != [],
             "the group vanished with the flag off, which would be an exclusion"

      assert matching(results.unavailable, @permitted_check) != [],
             """
             With no allowlist the permitted-direction check must report the
             third outcome. Silence here would be an exclusion wearing another
             name.
             """
    end
  end

  defp restore_conformance_env(nil), do: Application.delete_env(:ex_sandbox, :conformance)
  defp restore_conformance_env(value), do: Application.put_env(:ex_sandbox, :conformance, value)
end
