defmodule ExSandbox.Egress.ComposedCommandPlanTest do
  @moduledoc """
  The plan is built from the command the hardening layer **actually emits**
  (005 T060a4e).

  ## Why this file exists

  Every other test in `test/egress/` builds its plan from a hand-written
  `@confined` fixture. That is a reasonable way to pin the plan's *shape* and a
  useless way to establish that the plan works, because a fixture cannot drift
  the way real output can — and when it does drift, every test built on it stays
  green while the launch path is broken.

  ⚠️ **This is not hypothetical; it is how T060a4e survived.** The fixtures read
  `["systemd-run", "--scope", "bwrap", "--unshare-net", "erlexec"]` — no
  `setpriv` group at all. `Hardening.Linux.compose/3` has emitted one since
  `005` T007. A plan built from a command with no privilege drop **cannot
  exhibit** the defect that only appears when a drop lands inside a helper's
  namespace, so the unbootable ordering passed the entire egress suite and was
  found only by turning the conformance allowlist on and watching every network
  check fail with `:mechanism_error`.

  So this file asks the one question the fixtures structurally cannot: given
  what the composer really produces, does the plan come out bootable?
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.LaunchPlan
  alias ExSandbox.Hardening.Linux

  @port 9999
  @key {10, 0, 0, 4}

  defp composed do
    sandbox =
      struct!(ExSandbox.Sandbox,
        id: "compose-guard-#{System.unique_integer([:positive])}",
        owner_ref: "o",
        template_ref: "t",
        cpu_limit: 500,
        memory_limit_mb: 128,
        disk_quota_mb: 256
      )

    # ⚠️ `compose_for_inspection/2` rather than a launch. It runs on any host —
    # the point is the *command*, and composing one requires none of the
    # facilities running one does. A guard that only worked on Linux would not
    # have caught this defect on the machine where it was written.
    {:ok, {prog, args}} = Linux.compose_for_inspection(sandbox, [])
    [prog | args]
  end

  describe "a plan built from the real composed command" do
    test "is built at all, rather than refused" do
      # The regression in its plainest form. Under the wrapping ordering this
      # produced a plan that built fine and could not boot; the split refuses a
      # command with no privilege drop, so "builds" now means something.
      assert {:ok, _plan} = LaunchPlan.build(@key, @port, composed())
    end

    test "runs the composed command unchanged, network confinement kept" do
      # D6 of `let-sandboxes-outlive-a-deploy`: the namespace `--unshare-net`
      # makes holds only loopback, and `police/2` gives it its one way out.
      command = composed()
      {:ok, plan} = LaunchPlan.build(@key, @port, command)

      assert plan.tenant_command == command
      assert "--unshare-net" in plan.tenant_command
    end

    test "the resource caps survive into the policed command" do
      # ⚠️ The half of the ordering that had to be measured rather than argued.
      # Moving `setpriv` also risked moving it ahead of `systemd-run`, which
      # needs privilege to apply the caps — trading the
      # network boundary for the resource caps, the `005` R9b shape exactly.
      #
      # This asserts only that the flags are still THERE and still outermost.
      # That they still ENFORCE across two intervening execs is not something a
      # command inspection can establish, and it is not claimed here:
      # `docker/launch-ordering-probe.sh` measures it by attempting a breach
      # (192MB under a 64M cap → SIGKILL), which is the only evidence that counts.
      {:ok, plan} = LaunchPlan.build(@key, @port, composed())

      assert Enum.any?(plan.tenant_command, &String.starts_with?(&1, "MemoryMax=")),
             "the memory cap must survive the rewrite"

      assert Enum.any?(plan.tenant_command, &String.starts_with?(&1, "CPUQuota=")),
             "the cpu cap must survive the rewrite"
    end
  end
end
