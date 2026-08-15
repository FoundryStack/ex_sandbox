defmodule ExSandbox.ConformanceFailOpenTest do
  @moduledoc """
  The suite fails a mechanism that configures a cap without the cap taking
  effect (012 T029a, FR-012a, SC-008, research R7a).

  ## This is a meta-test of the suite, not of a mechanism

  It is the only test that catches a conformance suite which checks
  **invocation** instead of **effect**, and it is the one most likely to be
  written in a way that fails open.

  `ExSandbox.FailOpenMechanism` is the `005` R9b composition in fixture form. It
  accepts a 64 MB cap, records that it applied that exact cap, and then lets a
  192 MB allocation run to completion and exit 0. Measured on macOS:

      taskpolicy -m 100 sandbox-exec -f profile.sb ./hog 300

  allocates 300 MB and exits 0, because the cap is silently lost across the
  intervening `exec`. Everything observable except the allocation says the cap
  is in place.

  ## The wrong way to write this test

      assert ExSandbox.FailOpenMechanism.applied_caps() == [{id, 64}]

  That passes. The fixture's record is *honest* — it really did configure the
  cap — which is exactly why asserting on the record measures nothing. Any of
  these has the same defect:

    * asserting the limiter was called with the right arguments
    * asserting the wrapper appears in the process tree
    * asserting configuration names the cap
    * asserting the sandbox exited without error

  The assertion below is instead about **what the suite concluded**: it must
  have failed this mechanism. That is the only formulation that distinguishes a
  suite measuring enforcement from one measuring configuration.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.SuiteRunner

  setup do
    %{result: SuiteRunner.run(ExSandbox.FailOpenMechanism)}
  end

  describe "a silently-dropped cap is failed, not passed (FR-012a, SC-008)" do
    test "the fixture really does configure the cap it drops" do
      # Establishes that the fixture is the hard case and not a strawman: if it
      # never configured a cap, failing it would prove nothing about a suite's
      # ability to tell configuration from enforcement.
      sandbox = ExSandbox.Conformance.Helpers.build_sandbox(memory_limit_mb: 64)
      {:ok, _} = ExSandbox.provision(ExSandbox.FailOpenMechanism, sandbox)

      assert {_id, 64} = hd(ExSandbox.FailOpenMechanism.applied_caps()),
             "the fixture must genuinely record applying the cap -- that honesty " <>
               "is what makes it the R9b composition rather than a strawman"
    end

    test "the suite fails it", %{result: result} do
      assert result.failures != [],
             """
             The suite PASSED a mechanism that configures a 64 MB cap and then
             allows a 192 MB allocation to complete.

             This is the R7a defect: the suite is measuring that the limiter was
             invoked, not that the cap held. Every mechanism it certifies from
             here is unverified, and 005 R9b showed the two are indistinguishable
             from outside.

             Passed checks were: #{inspect(result.passed)}
             """
    end

    test "the memory check specifically is the one that fails", %{result: result} do
      failing = Enum.map(result.failures, fn {name, _} -> to_string(name) end)

      assert Enum.any?(failing, &String.contains?(&1, "memory cap")),
             "the memory-cap check did not fail. Failing checks were: " <>
               inspect(failing) <>
               ". A suite failing this mechanism for some unrelated reason has " <>
               "not demonstrated it can detect a dropped cap."
    end

    test "the failure says the breach ran to completion", %{result: result} do
      text = Enum.map_join(result.failures, "\n", fn {_name, message} -> message end)

      assert text =~ "NOT stopped",
             "the failure must state the breach was attempted and not stopped:\n\n" <> text
    end

    test "the failure warns that correct invocation is not enforcement", %{result: result} do
      text = Enum.map_join(result.failures, "\n", fn {_name, message} -> message end)

      # A mechanism author looking at this failure will check their limiter
      # invocation, find it correct, and conclude the suite is wrong -- unless
      # the message tells them invocation was never the question.
      assert text =~ "Invocation is not enforcement",
             "the failure does not warn that a correctly-invoked limiter can still " <>
               "drop the cap (005 R9b), which is the first thing the author will " <>
               "check and find fine:\n\n" <> text
    end

    test "no resource-limit check reports as passing", %{result: result} do
      passing = Enum.map(result.passed, &to_string/1)

      resource_passes =
        Enum.filter(passing, fn name ->
          String.contains?(name, "cap") or String.contains?(name, "budget")
        end)

      # T034b: a cap this mechanism does not enforce must never report as
      # satisfied, whether by passing or by being quietly skipped.
      assert resource_passes == [] or
               Enum.all?(resource_passes, &String.contains?(&1, "never breached")),
             "these resource-limit checks passed against a mechanism enforcing " <>
               "nothing: #{inspect(resource_passes)}"
    end
  end

  describe "the third outcome is not used to hide a failure (FR-012b)" do
    test "a dropped cap is reported as a failure, not as unavailable", %{result: result} do
      unavailable = Enum.map(result.unavailable, fn {name, _} -> to_string(name) end)

      memory_unavailable =
        Enum.filter(unavailable, &String.contains?(&1, "memory cap"))

      # The third outcome exists for a host that cannot attempt the breach. This
      # host can: the fixture runs the allocation and reports it completed.
      # Routing that to "unavailable" would be a failure in disguise.
      assert memory_unavailable == [],
             "the memory-cap breach was attempted and completed, so it is a " <>
               "mechanism failure. Reporting it as capability-unavailable hides a " <>
               "real defect behind a legitimate-looking outcome."
    end
  end
end
