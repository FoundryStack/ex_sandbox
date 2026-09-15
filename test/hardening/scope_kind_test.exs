defmodule ExSandbox.Hardening.ScopeKindTest do
  @moduledoc """
  The launcher emits the kind of `systemd-run` scope this host can actually
  create, and the tier probe reads the same answer.

  ## The defect this covers

  `probe_cgroups/0` asked `writable_cgroup?/0`, which probed a **`--user`**
  scope. `systemd_run_args/2` emitted a **system** scope. Both had been true
  since the module was written, and on a root supervisor -- the posture the
  library was designed for -- the disagreement is invisible, because root gets
  both.

  It is not invisible on a host that runs the platform unprivileged. MEASURED
  2026-09-15, Ubuntu 24.04, uid 110, linger enabled:

      systemd-run --scope -p MemoryMax=64M true
        -> Failed to start transient scope unit:
           Interactive authentication required.
      systemd-run --user --scope -p MemoryMax=64M -- \\
        sh -c 'cat /sys/fs/cgroup$(cut -d: -f3 </proc/self/cgroup)/memory.max'
        -> 67108864

  So the tier probe reported cgroups usable, `ExSandbox.Capability` reported
  `:resource_limits` available, and every launch was refused by systemd with a
  message about polkit -- which names neither the mismatch nor the fix.

  ## Why these assertions run on a host with no systemd at all

  `scope_mode/0` is memoised in `:persistent_term`, so a test can state the
  host's answer and assert what the launcher does with it. That is the whole
  point of the seam: the composition is testable everywhere, and the
  measurement is the part that needs Linux.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Hardening.Linux

  setup do
    on_exit(&Linux.forget_scope_mode/0)
    :ok
  end

  defp sandbox do
    %ExSandbox.Sandbox{
      id: "sb-#{System.unique_integer([:positive])}",
      owner_ref: "owner-1",
      template_ref: "tpl",
      memory_limit_mb: 256,
      cpu_limit: 500,
      disk_quota_mb: 1024
    }
  end

  defp seed(mode), do: :persistent_term.put({Linux, :scope_mode}, mode)

  defp args do
    {_path, args} = Linux.compose_for_inspection(sandbox()) |> elem(1)
    args
  end

  test "a host that can create a system scope is asked for one" do
    seed(:system)
    assert ["--scope", "--quiet" | _] = args()
    refute "--user" in args()
  end

  test "a host that can only create a user scope is asked for that, first" do
    seed(:user)

    # ⚠️ FIRST, before `--scope`. `systemd-run` reads `--user` as the manager to
    # talk to, and a flag after the unit's own properties is not the same
    # command.
    assert ["--user", "--scope", "--quiet" | _] = args()
  end

  test "the limits survive the user scope, which is the point of creating one" do
    seed(:user)
    a = args()

    assert "MemoryMax=256M" in a
    assert "CPUQuota=50%" in a
    assert "MemorySwapMax=0" in a
  end

  test "a host that can create neither is asked for a plain scope and refused by the gate" do
    # ⚠️ NOT a degraded command. `build_command/2` never reaches composition on
    # such a host -- `ExSandbox.Capability`'s `:resource_limits` clause reads
    # the same `scope_mode/0` and reports unavailable, so the launch is refused
    # before the mechanism is called. The shape below is what the launcher
    # *would* emit, asserted so that a future edit cannot quietly turn the
    # no-scope case into a launch with no limits at all.
    seed(nil)
    assert ["--scope", "--quiet" | _] = args()
  end
end
