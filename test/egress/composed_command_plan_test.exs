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
  exhibit** the defect that only appears when a drop lands inside pasta's
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
      # command it cannot place pasta into, so "builds" now means something.
      assert {:ok, _plan} = LaunchPlan.build(@key, @port, composed())
    end

    test "places pasta after the privilege drop and inside the scope" do
      {:ok, plan} = LaunchPlan.build(@key, @port, composed())
      basenames = Enum.map(plan.pasta_command, &Path.basename/1)
      at = fn name -> Enum.find_index(basenames, &(&1 == name)) end

      assert at.("systemd-run") < at.("setpriv"),
             "the scope must stay outermost or MemoryMax/CPUQuota never apply"

      assert at.("setpriv") < at.("pasta"),
             """
             `setpriv` must run BEFORE pasta. Measured (T060a4e): pasta in spawn
             mode always creates its own userns and cannot write its `uid_map`,
             so the map is empty, every process inside is uid 65534, and
             `setpriv --reuid` fails with EINVAL for any uid:

               Couldn't write to /proc/self/uid_map: Operation not permitted
               setpriv: setresuid failed: Invalid argument
               {:boot_failed, {:exit_status, 127}}
             """

      assert at.("pasta") < at.("bwrap"),
             "the tenant must end up inside pasta's namespace"
    end

    test "pasta's --runas matches the uid setpriv actually drops to" do
      {:ok, plan} = LaunchPlan.build(@key, @port, composed())

      reuid =
        Enum.find_value(plan.pasta_command, fn
          "--reuid=" <> uid -> uid
          _ -> nil
        end)

      runas = plan.pasta_command |> Enum.drop_while(&(&1 != "--runas")) |> Enum.at(1)

      # ⚠️ A mismatch here fails silently rather than loudly: pasta maps a uid
      # the tenant never becomes, and the namespace comes up owned by nobody in
      # particular. Reading both out of the same emitted command is the only way
      # to check the two agree.
      assert runas == "#{reuid}:#{reuid}",
             "pasta would map uid #{runas} while setpriv drops to #{reuid}"

      refute runas == "0",
             "`--runas 0` after a drop fails outright, and `--runas 0:0` HANGS"
    end

    test "the resource caps survive into the policed command" do
      # ⚠️ The half of the ordering that had to be measured rather than argued.
      # Moving `setpriv` ahead of pasta also risked moving it ahead of
      # `systemd-run`, which needs privilege to apply the caps — trading the
      # network boundary for the resource caps, the `005` R9b shape exactly.
      #
      # This asserts only that the flags are still THERE and still outermost.
      # That they still ENFORCE across two intervening execs is not something a
      # command inspection can establish, and it is not claimed here:
      # `docker/launch-ordering-probe.sh` measures it by attempting a breach
      # (192MB under a 64M cap → SIGKILL), which is the only evidence that counts.
      {:ok, plan} = LaunchPlan.build(@key, @port, composed())

      assert Enum.any?(plan.pasta_command, &String.starts_with?(&1, "MemoryMax=")),
             "the memory cap must survive the rewrite"

      assert Enum.any?(plan.pasta_command, &String.starts_with?(&1, "CPUQuota=")),
             "the cpu cap must survive the rewrite"
    end

    test "the pidfile is somewhere the DROPPED uid can write" do
      # ⚠️ Found by running the launch, not by reading the command. While pasta
      # wrapped the whole command it ran as root and `/var/run` worked; inserted
      # after `setpriv` it runs as the sandbox uid, and the first container run
      # after the reorder died with:
      #
      #     Couldn't open PID file /var/run/axonn-pasta-10-0-0-0.pid: Permission denied
      #     {:boot_failed, {:exit_status, 1}}
      #
      # Every ordering assertion in this suite passed against that command,
      # because the command was right -- what changed was which uid ran part of
      # it. This test cannot check the filesystem of a host it is not on, so it
      # pins the property that made the old path wrong: a directory only root
      # can write.
      {:ok, plan} = LaunchPlan.build(@key, @port, composed())

      refute String.starts_with?(plan.pidfile, "/var/run/"),
             """
             /var/run is root-owned, and pasta no longer runs as root. The
             tenant never boots and the failure surfaces as :mechanism_error,
             which reads as a host problem rather than a path problem.
             """

      assert plan.pidfile in plan.pasta_command,
             "pasta must be told the same path the launcher later reads"
    end

    test "the pidfile name is keyed by the /30, which the allocator RECYCLES" do
      # ⚠️ The property that makes a stale-file sweep necessary. The pidfile is
      # named from the source key, which is recycled; `sandbox_uid/1` hashes the
      # sandbox **id**, which is not. So the second sandbox on a given /30
      # usually runs as a different uid, and `/tmp` is sticky -- it cannot
      # replace another uid's file. Measured in the isolation phase after the
      # credentials phase had used the same /30:
      #
      #     Couldn't open PID file /tmp/axonn-pasta-10-0-0-0.pid: Permission denied
      #     {:boot_failed, {:exit_status, 1}}
      {:ok, a} = LaunchPlan.build({10, 0, 0, 4}, @port, composed())
      {:ok, b} = LaunchPlan.build({10, 0, 0, 4}, @port, composed())

      assert a.pidfile == b.pidfile,
             "two sandboxes on the same /30 share a pidfile, so a stale one blocks the next"

      {:ok, c} = LaunchPlan.build({10, 0, 0, 8}, @port, composed())

      refute a.pidfile == c.pidfile,
             "different /30s must not collide, or the host searches the wrong process"
    end

    test "the network confinement is replaced rather than kept" do
      {:ok, plan} = LaunchPlan.build(@key, @port, composed())

      refute "--unshare-net" in plan.pasta_command,
             "an empty namespace would deny everything and pass every denial check"
    end
  end
end
