defmodule ExSandbox.ConformanceCredentialsMetaTest do
  @moduledoc """
  The credentials group fails a credential that reaches everything (005 T060g).

  ## Why this exists

  The isolation and network groups each have an adversarial meta-test; the
  credentials group had none. That mattered more here than anywhere else,
  because this group's own moduledoc names the false-pass shape it is exposed
  to:

  > A check that merely confirms the role exists, or that the sandbox can reach
  > its own database, passes against a credential with **superuser** privileges.

  Nothing was forcing that to stay true. Three defects of exactly this species
  have already been found in this suite (`SuiteRunner`'s missing setup,
  `attempt_self_halt`, `attempt_host_process_list`), and every one of them read
  as correct code — each was caught by *executing* a guard against the failure
  it claims to detect, never by review. Six credentials checks had never been
  pointed at a credential that ought to fail them.

  ## The distinction this test has to make

  Unlike the isolation group, **not every check here is a refusal**. Three are
  positive controls that a leaky credential passes correctly:

    * reading your own credential (concealment is not the guarantee)
    * the credential reaching its own store (keeps the refusals honest)
    * rotation issuing a new secret in place

  Requiring those to fail would be requiring the credential model to break. So
  the refusals are enumerated by name below rather than inferred, and the
  positives are asserted to still pass — a group that failed *everything*
  against this probe would be broken in the opposite direction and is worth
  catching too.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.SuiteRunner

  # The checks that assert a credential is refused somewhere. Named individually
  # for the same reason `@hostile_acts` is: matching on the describe prefix
  # would silently absorb any future positive control into the assertion and
  # weaken it to nothing.
  @refusals [
    "the credential is refused against another sandbox's store",
    "the credential is refused against the platform database",
    "the secret appears in no log line, record, or inspect output"
  ]

  # The positive controls. A leaky credential passes these *correctly*.
  @positives [
    "a sandbox can read its own credential",
    "the credential reaches its own store",
    "rotation issues a new secret without rebuilding the sandbox"
  ]

  defp named?(name, list) do
    text = Atom.to_string(name)
    Enum.any?(list, &String.contains?(text, &1))
  end

  defp credentials_results do
    results =
      SuiteRunner.run(ExSandbox.PorousMechanism,
        describe: "credentials",
        credential_probe: ExSandbox.LeakyCredentialProbe
      )

    %{
      passed: results.passed,
      failed: Enum.map(results.failures, &elem(&1, 0)),
      unavailable: Enum.map(results.unavailable, &elem(&1, 0))
    }
  end

  test "every check named here still exists in the group" do
    # Guards both lists above. A renamed or deleted check would otherwise make
    # this whole file vacuous by matching nothing, and it would stay green --
    # the same way the missing-setup bug kept the isolation meta-test green
    # while it measured a harness crash.
    results = credentials_results()
    names = Enum.map(results.passed ++ results.failed ++ results.unavailable, &Atom.to_string/1)

    for check <- @refusals ++ @positives do
      assert Enum.any?(names, &String.contains?(&1, check)),
             "no credentials check named #{inspect(check)} -- the lists in this file are stale"
    end
  end

  describe "against a credential that reaches everything" do
    test "every refusal check fails" do
      results = credentials_results()

      assert results.failed != [],
             "the credentials group produced no failures at all against a credential that " <>
               "connects to every store, which means it is not running"

      still_passing = Enum.filter(results.passed, &named?(&1, @refusals))

      assert still_passing == [],
             """
             These credentials checks PASSED against a credential that opens every
             store it is pointed at, including the platform's own database:

               #{Enum.map_join(still_passing, "\n  ", &inspect/1)}

             A refusal check that passes here is asserting that the credential
             *exists* rather than that it is *refused* (003 credentials group
             moduledoc, 013-FR-008/FR-009). Rewrite it to attempt the connection
             and require it be turned away.
             """
    end

    test "no refusal check reports the third outcome" do
      # `capability_unavailable` is for a host with no data store, not for a
      # credential that fails to restrict. A probe is supplied here, so reaching
      # that outcome would mean the group found a way to be neither passed nor
      # failed against a credential it should reject -- the exclusion
      # `012-FR-011` forbids, arrived at sideways.
      results = credentials_results()
      unavailable = Enum.filter(results.unavailable, &named?(&1, @refusals))

      assert unavailable == [],
             """
             These credentials checks reported "host capability unavailable" while a
             probe was supplied:

               #{Enum.map_join(unavailable, "\n  ", &inspect/1)}

             The third outcome means the host has no data store to probe. With a
             probe present it is a way of neither passing nor failing, which is
             what `012-FR-011` forbids.
             """
    end

    test "the positive controls still pass" do
      # The opposite failure, and it is not hypothetical: a group rewritten to
      # assert the credential is refused *everywhere* would fail this probe on
      # all six checks and look maximally strict while being wrong. Reading your
      # own credential and reaching your own store must succeed -- containment
      # comes from the credential granting nothing elsewhere.
      results = credentials_results()
      not_passing = Enum.filter(results.failed ++ results.unavailable, &named?(&1, @positives))

      assert not_passing == [],
             """
             These credentials positive controls did NOT pass against a working
             credential:

               #{Enum.map_join(not_passing, "\n  ", &inspect/1)}

             This probe reads its own credential, reaches its own store, and
             rotates in place -- all three are supposed to succeed. A group that
             fails them is testing concealment rather than containment (003-FR-018).
             """
    end
  end
end
