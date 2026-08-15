defmodule ExSandbox.ConformanceFailureNamingTest do
  @moduledoc """
  A conformance failure names the guarantee that was violated (012 T029, T033,
  SC-004, Story 2 AS 2).

  `SC-004` asks that a third-party mechanism author can act on a failure without
  reading this repository. An ExUnit assertion message tells them a comparison
  failed:

      Assertion with == failed
      code:  ExSandbox.destroy(@mechanism, provisioned) == :ok
      left:  {:error, :not_found}
      right: :ok

  which reads like the suite being pedantic about a return shape. The fix is
  expressed in different terms — *cleanup sweeps run against sandboxes that may
  already be gone, so destroy must be idempotent* — and those terms are the
  `003` requirement.

  So this runs the suite against a mechanism with a real, specific defect and
  requires the message to carry the requirement id.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.SuiteRunner

  describe "failure messages name the violated guarantee (SC-004)" do
    setup do
      %{result: SuiteRunner.run(ExSandbox.BrokenMechanism)}
    end

    test "the broken mechanism does fail the suite", %{result: result} do
      # Without this the rest of the module could pass vacuously.
      assert result.failures != [],
             "BrokenMechanism violates 003-FR-013 by erroring on a second destroy, " <>
               "but the suite reported no failures. A suite that passes a broken " <>
               "mechanism measures nothing."
    end

    test "the idempotent-destroy failure cites 003-FR-013", %{result: result} do
      text = Enum.map_join(result.failures, "\n", fn {_name, message} -> message end)

      assert text =~ "003-FR-013",
             "no failure named 003-FR-013. Messages were:\n\n" <> text
    end

    test "the message explains the guarantee, not just the assertion", %{result: result} do
      text = Enum.map_join(result.failures, "\n", fn {_name, message} -> message end)

      # The distinguishing content: *why* the requirement exists. An author who
      # reads only that `:ok` was expected has no reason to think their error
      # return is wrong.
      assert text =~ "idempotent",
             "the failure does not explain what the mechanism must do differently"

      assert text =~ ~r/sweep/i,
             "the failure does not explain why idempotence is required -- without " <>
               "the reason, the requirement reads as arbitrary"
    end

    test "every failure message names some 003 requirement", %{result: result} do
      Enum.each(result.failures, fn {name, message} ->
        assert message =~ ~r/00[0-9]-(FR|SC)-\d+/,
               "the failure for #{inspect(name)} names no requirement:\n\n#{message}"
      end)
    end

    test "failures identify themselves as contract violations, not suite defects",
         %{result: result} do
      text = Enum.map_join(result.failures, "\n", fn {_name, message} -> message end)

      # A mechanism author's first instinct on a failing conformance suite is
      # that the suite is wrong. The message says otherwise, and says where the
      # legitimate appeal is.
      assert text =~ "not a suite defect"
    end
  end

  describe "a conforming mechanism is not failed for the wrong reason" do
    test "EchoMechanism's failures, if any, are all about behaviour it lacks" do
      result = SuiteRunner.run(ExSandbox.EchoMechanism)

      # EchoMechanism genuinely isolates nothing, so it should fail. What it
      # must not do is fail with an unnamed error -- that would mean the suite
      # crashed rather than judged.
      Enum.each(result.failures, fn {name, message} ->
        refute message =~ "** (KeyError",
               "the suite crashed rather than judging #{inspect(name)}:\n\n#{message}"

        refute message =~ "** (FunctionClauseError",
               "the suite crashed rather than judging #{inspect(name)}:\n\n#{message}"

        refute message =~ "** (UndefinedFunctionError",
               "the suite crashed rather than judging #{inspect(name)}:\n\n#{message}"
      end)
    end
  end
end
