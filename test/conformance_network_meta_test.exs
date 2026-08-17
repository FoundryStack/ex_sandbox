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

  @permitted_check "a destination inside the environment's allowlist is reachable"

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

    for check <- [@permitted_check | @denial_checks] do
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
        Enum.flat_map(@denial_checks, &matching(results.passed, &1))

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

    test "no denial check reports the third outcome" do
      # `capability_unavailable` is for a host that cannot enforce, not for a
      # mechanism that does not confine. A porous mechanism reaching that
      # outcome has found a way to be neither passed nor failed.
      results = network_results(ExSandbox.PorousMechanism)

      wrongly_unavailable =
        Enum.flat_map(@denial_checks, &matching(results.unavailable, &1))

      assert wrongly_unavailable == [],
             """
             These network checks reported "host capability unavailable" against a
             mechanism that confines nothing:

               #{Enum.map_join(wrongly_unavailable, "\n  ", &inspect/1)}

             The third outcome means the *host* could not demonstrate the
             guarantee. A mechanism that lets every connection through has
             demonstrated the opposite, and reporting it as undemonstrated hides
             a real violation behind an honest-sounding label.
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
end
