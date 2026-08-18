defmodule ExSandbox.Hardening.CapabilityBuildParityTest do
  @moduledoc """
  Every capability the probe reports is actually constructed by the command
  (005 T012).

  ## The seam this closes

  `capabilities/0` probes five things and `available?/0` requires all five.
  `contracts/hardening.md` then relegates three of them — filesystem
  confinement, disk quota, network restriction — to "deployment", outside the
  code.

  Taken literally that ships a silent failure. On a correctly configured Linux
  host every probe passes, `build_command/2` emits a command constructing only
  cgroups, the uid drop, and `env -i`, and the sandbox launches **reported
  fully hardened with three of five boundaries absent**. `verify_applied/1` as
  the contract originally scoped it inspects only uid, cgroup, and memory/CPU,
  so it cannot catch this either.

  Every other test in this suite passes in that state. This one does not.

  ## Why parity rather than a list of expected flags

  Asserting "the command contains `--unshare-net`" pins today's construction and
  would need editing whenever the mechanism changes. What must hold is the
  *relationship*: a capability that is probed is a capability that is built. A
  sixth capability added to the probe with no matching construction fails here
  automatically, which is the case a fixed list would miss.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Hardening.Linux

  # What counts as "constructed" for each probed capability: evidence that must
  # appear in the built command. Keyed by capability so a new probe key with no
  # entry fails the completeness test below rather than being silently ignored.
  @construction %{
    resource_limits: {"cgroup caps", &__MODULE__.has_resource_limits?/1},
    privilege_separation: {"uid/gid drop", &__MODULE__.has_privilege_drop?/1},
    filesystem_confinement: {"mount confinement", &__MODULE__.has_filesystem_confinement?/1},
    network_restriction: {"egress denial", &__MODULE__.has_network_restriction?/1},
    disk_quota: {"storage quota", &__MODULE__.has_disk_quota?/1}
  }

  def has_resource_limits?(args) do
    Enum.any?(args, &String.starts_with?(&1, "MemoryMax=")) and
      Enum.any?(args, &String.starts_with?(&1, "CPUQuota="))
  end

  def has_privilege_drop?(args) do
    "setpriv" in args and Enum.any?(args, &String.starts_with?(&1, "--reuid="))
  end

  def has_filesystem_confinement?(args), do: "--ro-bind" in args or "--bind" in args

  def has_network_restriction?(args), do: "--unshare-net" in args

  # ⚠️ The evidence is the **bind of the sandbox's storage**, not a `--size`
  # argument. This test previously accepted `"--size" in args`, and that was
  # wrong twice over: `bwrap`'s `--size` takes raw bytes and only modifies a
  # following `--tmpfs`, so the trailing `--size 1024M` it was matching modified
  # nothing *and* made `bwrap` reject the entire command. The parity check passed
  # against an argument that broke every launch.
  #
  # What actually enforces `FR-009` is the bind: `storage_path/1` points into a
  # filesystem `probe_disk_quota/0` has confirmed can carry a quota, and binding
  # it carries that enforcement in. So parity means "the storage is bound",
  # which is checkable here, rather than "a quota is in force", which is not --
  # establishing that is the resource-cap suite's job.
  def has_disk_quota?(args) do
    # Scans **every** `--bind`, not just the first. An earlier version took only
    # `Enum.find_index/2`'s first hit, which passed until `HOME=` was added to
    # the environment layer and shifted what that index pointed at -- a check
    # that depended on argument order rather than on the bind being present.
    args
    |> Enum.with_index()
    |> Enum.filter(fn {arg, _i} -> arg == "--bind" end)
    |> Enum.any?(fn {_arg, i} ->
      args |> Enum.at(i + 1) |> to_string() |> String.contains?("sandboxes/")
    end)
  end

  defp built_args do
    sandbox = %ExSandbox.Sandbox{
      id: "parity-#{System.unique_integer([:positive])}",
      owner_ref: "owner",
      template_ref: "tpl",
      memory_limit_mb: 256,
      cpu_limit: 500,
      disk_quota_mb: 1024
    }

    {:ok, {_cmd, args}} = Linux.compose_for_inspection(sandbox, [])
    args
  end

  test "the mount-confinement probe attempts the flags the launch actually uses" do
    # ⚠️ Parity of *presence* is not enough, and this is the hole the rest of
    # this file did not cover.
    #
    # `has_filesystem_confinement?/1` above checks that the built command
    # contains a bind. It passed the whole time `probe_mount_namespace/0` was
    # testing `bwrap --unshare-net` while `confinement_args/2` launched with
    # `--unshare-pid --proc /proc` -- a strictly harder operation. On a
    # privileged host both succeed, so nothing showed. On an UNPRIVILEGED host
    # (the `013-FR-006b` shape) the probe's form succeeds and the launch's form
    # fails:
    #
    #     bwrap --unshare-user --unshare-net --ro-bind / / true      -> rc=0
    #     bwrap --unshare-user --unshare-pid --proc /proc ...        -> rc=1
    #       "Can't mount proc on /newroot/proc: Operation not permitted"
    #
    # The census then reported `filesystem_confinement: ok`, `available?: true`,
    # and **every launch died** with `{:boot_failed, {:exit_status, 1}}` -- six
    # failures and `unavailable` 7 -> 14, measured. An over-claiming probe turns
    # "this host cannot do it" into a launch that crashes, instead of into the
    # third outcome the census can report honestly.
    #
    # This asserts on the probe's SOURCE rather than by running it, deliberately:
    # running it can only report what this host happens to allow, and on a
    # privileged host (or on macOS) that is `true` either way -- which is
    # precisely the blindness that let the drift survive.
    source = File.read!("lib/ex_sandbox/hardening/linux.ex")

    [_, probe_body] = String.split(source, "defp can_confine_mounts? do", parts: 2)
    [probe_body, _] = String.split(probe_body, "\n  end", parts: 2)

    launch_flags = built_args()

    required =
      ["--unshare-pid", "--proc"]
      |> Enum.filter(&(&1 in launch_flags))

    assert required != [],
           "expected the launch to confine mounts with --unshare-pid/--proc; " <>
             "if that changed, this test and `can_confine_mounts?/0` must change with it"

    missing = Enum.reject(required, &String.contains?(probe_body, &1))

    assert missing == [],
           """
           `can_confine_mounts?/0` does not attempt #{inspect(missing)}, but the
           launch command built by `confinement_args/2` uses it.

           A probe that attempts an EASIER operation than the launch reports a
           capability the host may not have. Unprivileged, that is exactly what
           happened: probe green, every launch dead.

           Either probe the flags the launch uses, or stop using them.
           """
  end

  test "every probed capability has a construction entry" do
    # Guards the map above. Without this, adding a sixth probe and forgetting to
    # describe its construction would make the parity test below silently skip
    # it -- the exact hole this file exists to close, reopened one level up.
    probed = Linux.capabilities() |> Map.keys() |> MapSet.new()
    described = @construction |> Map.keys() |> MapSet.new()

    assert MapSet.equal?(probed, described),
           """
           `capabilities/0` and this test's construction map disagree.

           Probed but not described: #{inspect(MapSet.difference(probed, described) |> MapSet.to_list())}
           Described but not probed: #{inspect(MapSet.difference(described, probed) |> MapSet.to_list())}

           A probed capability with no described construction cannot be checked
           for parity, so `available?/0` could require it while nothing builds it.
           """
  end

  test "every probed capability is actually constructed" do
    args = built_args()

    missing =
      for {capability, {description, present?}} <- @construction,
          not present?.(args),
          do: "#{capability} (#{description})"

    assert missing == [],
           """
           These capabilities are probed by `capabilities/0` -- and therefore
           required by `available?/0` -- but are not constructed by the launch
           command:

             #{Enum.join(missing, "\n  ")}

           A host satisfying every probe would launch a sandbox reported fully
           hardened with these boundaries absent. Either construct them or stop
           probing them; there is no third option that is not a silent failure.
           """
  end

  test "verification covers the constructed boundaries" do
    # One level down, the same seam: a boundary that is built but never verified
    # is a boundary that can silently fail to apply. `verify_applied/1` returns
    # the mount and egress checks, so their absence would show here.
    verified = Linux.__info__(:functions) |> Keyword.keys()

    assert :verify_applied in verified

    source = File.read!("lib/ex_sandbox/hardening/linux.ex")

    for evidence <- ["mount_confined", "netns_separated", "disk_quota_mb"] do
      assert source =~ evidence,
             "verify_applied/1 does not report #{evidence}; a boundary is built but unchecked"
    end
  end
end
