defmodule ExSandbox.ConformanceReconciliationMetaTest do
  @moduledoc """
  The reconciliation group cannot currently detect its own subject (005 T060i).

  ## The finding

  Pointing `ExSandbox.BookkeepingMechanism` at the reconciliation group makes
  **all four checks pass** -- including the one named "list_running enumerates
  reality, not the mechanism's bookkeeping".

  That mechanism's `list_running/0` returns what it was *asked to start*: a set
  added to on `start/1` and removed from on `stop/1`. It is the natural
  implementation, it is trivially consistent with itself, and it cannot detect
  the only case `003-FR-015` exists for -- a sandbox that **died without telling
  anyone**, after a host restart or an OOM kill, where nothing called `stop/1`.

  ## Why the group misses it

  Structural, not a wrong assertion. Every check ends its sandbox through
  `stop/1` or `destroy/1` -- the paths on which a bookkeeping mechanism updates
  both its views. Bookkeeping and reality therefore never diverge during the
  run, so a check comparing them has nothing to find. The group tests that
  `list_running/0` tracks the mechanism's *own* calls, which is not the
  guarantee.

  This differs from the six defects found before it: those were guards that read
  correctly and returned green on the path they were written to catch. This one
  is a **gap in coverage** -- the hostile condition is never created, so the
  check is sound and simply never exercised.

  ## Why this test asserts the gap rather than a fix

  Closing it needs a way for the suite to end a sandbox *without* a mechanism
  call, and `ExSandbox.Mechanism` deliberately has no such callback -- adding
  one means every third-party mechanism must implement "kill yourself the way a
  crash would", which is a real contract change and not one to make silently
  (`012-FR-010`: the suite must be runnable by any mechanism).

  So this file pins the finding: it asserts the group passes this mechanism
  **today**, and it will fail the moment that stops being true. Whoever closes
  the gap gets a red test pointing at this moduledoc rather than a silent change
  in what the suite guarantees.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.SuiteRunner

  setup do
    ExSandbox.BookkeepingMechanism.start_link()
    :ok
  end

  test "the fixture genuinely diverges, so a passing group is the group's doing" do
    # ⚠️ Without this, "all four checks passed" is ambiguous: a fixture that
    # never actually diverged would produce the same green, and the finding
    # below would be about the fixture rather than the suite. Measured here so
    # the claim rests on the mechanism misreporting, not on an assumption.
    m = ExSandbox.BookkeepingMechanism

    sandbox = %ExSandbox.Sandbox{
      id: "meta-#{System.unique_integer([:positive])}",
      owner_ref: "o",
      template_ref: "t"
    }

    {:ok, provisioned} = ExSandbox.provision(m, sandbox)
    {:ok, started} = ExSandbox.start(m, provisioned)

    # Reality ends. No mechanism callback is involved, because none would be.
    ExSandbox.BookkeepingMechanism.kill(started)

    {:ok, listed} = ExSandbox.list_running(m)

    assert started.mechanism_ref in listed,
           "the fixture is not diverging -- list_running dropped the ref it should still claim"

    assert ExSandbox.status(m, started) == {:ok, :absent},
           "the fixture is not diverging -- status agrees with the bookkeeping"
  end

  test "the group passes a mechanism that reports bookkeeping instead of reality" do
    results = SuiteRunner.run(ExSandbox.BookkeepingMechanism, describe: "reconciliation")

    assert results.total == 4,
           "expected the reconciliation group's 4 checks, got #{results.total}"

    assert results.failures == [],
           """
           A reconciliation check now FAILS the bookkeeping mechanism:

             #{Enum.map_join(results.failures, "\n  ", fn {n, _} -> inspect(n) end)}

           If that is deliberate -- someone closed the gap this file documents --
           delete this test and record what changed. The group can now detect a
           sandbox that died without a mechanism call, which is what `003-FR-015`
           is about, and that is worth saying out loud rather than letting a
           meta-test quietly go red.
           """

    assert length(results.passed) == 4,
           "expected all 4 checks to pass this mechanism; passed #{length(results.passed)}"
  end
end
