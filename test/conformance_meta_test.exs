defmodule ExSandbox.ConformanceMetaTest do
  @moduledoc """
  The isolation group fails a mechanism that isolates nothing (003 T045).

  ## What this catches that the group itself cannot

  `ExSandbox.Conformance.Isolation` asserts things about a mechanism. Nothing
  in it asserts anything about *itself* — and the failure mode T044 exists to
  prevent is invisible from the inside. An isolation check written as

      {:ok, out} = exec(sandbox, "printenv SECRET")
      refute out =~ @secret

  passes against a mechanism with no isolation whatsoever whenever the secret
  simply is not in that particular output. It looks like a test, it goes green,
  and it establishes nothing.

  The only way to know the group is written the right way round is to point it
  at a mechanism that is definitively porous and require that every check
  **which performs a hostile act** fails. That is what this test does.

  ## Not every isolation check is a hostile act

  The group also carries one opacity assertion — that a structured `owner_ref`
  survives the round trip unparsed (`012-FR-007`). A porous mechanism passes it
  correctly, because refusing to parse a value is unrelated to confinement.
  Requiring *that* to fail would be requiring the mechanism to corrupt its
  input. The hostile acts are enumerated below rather than inferred from the
  describe name, so this distinction stays explicit instead of silently
  weakening the assertion later.

  ## Why `PorousMechanism` rather than `EchoMechanism`

  A mechanism with no runner fails by being inconclusive, which proves much
  less: the group could be rejecting it for having no `context.exec` rather
  than for leaking. `ExSandbox.PorousMechanism` runs each command in the host's
  own shell, so every hostile act genuinely succeeds and the group has to
  reject it on the evidence.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.SuiteRunner

  # The checks that perform a hostile act, named individually. Matching on the
  # describe prefix instead would silently absorb any future non-hostile check
  # into the assertion and weaken it.
  @hostile_acts [
    "reading the platform's own credentials from inside is refused",
    "reading another sandbox's filesystem is refused",
    "halting the host from inside the sandbox is refused",
    "enumerating host processes from inside is refused"
  ]

  defp hostile?(name) do
    text = Atom.to_string(name)
    Enum.any?(@hostile_acts, &String.contains?(text, &1))
  end

  defp isolation_results(mechanism) do
    results = SuiteRunner.run(mechanism, describe: "isolation")

    %{
      passed: Enum.filter(results.passed, &hostile?/1),
      failed: results.failures |> Enum.map(&elem(&1, 0)) |> Enum.filter(&hostile?/1),
      unavailable: results.unavailable |> Enum.map(&elem(&1, 0)) |> Enum.filter(&hostile?/1)
    }
  end

  test "every hostile act named here still exists in the group" do
    # Guards the list above: a renamed or deleted check would otherwise make
    # this whole test vacuous by matching nothing, and it would stay green.
    names =
      ExSandbox.PorousMechanism
      |> SuiteRunner.run(describe: "isolation")
      |> then(fn r ->
        Enum.map(r.passed, &Atom.to_string/1) ++
          Enum.map(r.failures ++ r.unavailable, fn {n, _} -> Atom.to_string(n) end)
      end)

    for act <- @hostile_acts do
      assert Enum.any?(names, &String.contains?(&1, act)),
             "no isolation check named #{inspect(act)} -- @hostile_acts is stale"
    end
  end

  describe "against a mechanism that isolates nothing" do
    test "every hostile act fails" do
      results = isolation_results(ExSandbox.PorousMechanism)

      assert results.failed != [],
             "the isolation group produced no failures at all against a porous mechanism, " <>
               "which means it is not running"

      assert results.passed == [],
             """
             These isolation checks PASSED against a mechanism that runs every command
             in the host's own shell:

               #{Enum.map_join(results.passed, "\n  ", &inspect/1)}

             A check that passes here is asserting that no leak was observed rather
             than that a hostile act was refused (003 T044, Constitution Isolation
             Review). Rewrite it to perform the act and require refusal.
             """
    end

    test "no hostile act reports the third outcome" do
      # `capability_unavailable` is for a host that cannot support a *cap*, not
      # for a mechanism that fails to isolate. If a porous mechanism can reach
      # that outcome, it has found a way to be neither passed nor failed --
      # which is the exclusion `012-FR-011` forbids, arrived at sideways.
      results = isolation_results(ExSandbox.PorousMechanism)

      assert results.unavailable == [],
             """
             These isolation checks reported "host capability unavailable" against a
             porous mechanism:

               #{Enum.map_join(results.unavailable, "\n  ", &inspect/1)}

             Isolation has no host capability that could legitimately be absent.
             """
    end
  end

  describe "against a mechanism with no runner" do
    test "hostile acts fail rather than passing silently" do
      # The other half of the trap: a mechanism that never attempts the act
      # must not pass by default. `EchoMechanism` carries no `context.exec`.
      results = isolation_results(ExSandbox.EchoMechanism)

      assert results.passed == [],
             """
             These isolation checks PASSED against a mechanism that cannot run
             anything at all:

               #{Enum.map_join(results.passed, "\n  ", &inspect/1)}

             Declining to attempt a breach is not evidence of isolation.
             """
    end
  end
end
