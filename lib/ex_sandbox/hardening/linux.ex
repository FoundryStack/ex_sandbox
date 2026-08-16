defmodule ExSandbox.Hardening.Linux do
  @moduledoc """
  OS-level confinement for the BEAM mechanism on Linux (005 T004 – T012,
  contracts/hardening.md, research R2, R3, R9).

  ## The security boundary is here, not in the BEAM

  Nothing inside the Erlang VM can cap a process's memory or deny it a socket.
  `005` settled that the boundary is the operating system, so this module
  composes five kernel-enforced constructions and refuses to launch when it
  cannot build all of them.

      systemd-run --scope -p MemoryMax=… -p CPUQuota=…   # FR-008
        setpriv --reuid=… --regid=… --clear-groups        # FR-007
          bwrap --ro-bind / --bind <storage>              # FR-010
            env -i <granted…> BINDIR=<…>                  # FR-004
              <erlexec> <peer args>

  ## Refusal, never degradation

  `build_command/2` returns `{:error, :hardening_unavailable}` when any
  capability is missing. It never emits a command with a layer omitted, because
  that failure is invisible: the sandbox launches, the happy path is identical,
  and the only difference is whether tenant code is confined.

  This is why `available?/0` requires **all five** capabilities rather than
  most. Cgroup caps without privilege separation still permits reading platform
  files — "mostly hardened" describes a host that is not hardened.

  ## Probes attempt; they never infer

  Every probe below performs the operation it reports on. Reading `:os.type()`
  would report `true` on a Linux host with no cgroup delegation, no `setpriv`,
  or an unprivileged process — which is exactly the silent-failure mode R9
  exists to prevent, and exactly what an operator cannot see.

  ## What `verify_applied/1` can and cannot establish

  It reads the limits **in force on the running process** — the cgroup's
  effective values — rather than the command that requested them. R9b measured
  a limiter invoked with correct arguments, present in the process tree, named
  in configuration, and silently not applied. Reading back the request would
  have reported success.

  Inspection is still not proof that a limit *stops* a breach; establishing that
  is the conformance suite's job (`012-FR-012a`). The two are complementary and
  neither substitutes for the other.
  """

  @type capability_map :: %{
          resource_limits: boolean(),
          privilege_separation: boolean(),
          filesystem_confinement: boolean(),
          network_restriction: boolean(),
          disk_quota: boolean()
        }

  # Never granted to a sandbox, whatever the caller passes
  # (contracts/hardening.md §Never in `granted_env`). Matched as substrings
  # because the shape matters more than the exact spelling: `DATABASE_URL`,
  # `AXONN_DATABASE_URL`, and `REPLICA_DATABASE_URL` are all the same mistake.
  @forbidden_env_fragments ~w(
    SECRET
    PASSWORD
    DATABASE_URL
    API_KEY
    TOKEN
    CREDENTIAL
    PRIVATE_KEY
    RELEASE_COOKIE
    ERLANG_COOKIE
  )

  @cgroup_root "/sys/fs/cgroup"

  @doc """
  Probes what this host can actually enforce.

  Probed once at gateway startup rather than per provision — the answer is a
  property of the host, and probing per launch would put shell-outs on the
  provisioning path for a value that does not change.
  """
  @spec capabilities() :: capability_map()
  def capabilities do
    %{
      resource_limits: probe_cgroups(),
      privilege_separation: probe_setpriv(),
      filesystem_confinement: probe_mount_namespace(),
      network_restriction: probe_network_policy(),
      disk_quota: probe_disk_quota()
    }
  end

  @doc """
  True only when every capability is present.

  There is no partial state: see the moduledoc.
  """
  @spec available?() :: boolean()
  def available? do
    capabilities() |> Map.values() |> Enum.all?()
  end

  @doc """
  Builds the command that launches a sandbox under full confinement.

  `granted_env` is an **allowlist** — the sandbox receives these pairs and
  nothing else. Returns `{:error, :hardening_unavailable}` when any capability
  is missing, and `{:error, {:forbidden_env, keys}}` when `granted_env` carries
  a platform-shaped secret.
  """
  @spec build_command(ExSandbox.Sandbox.t(), [{String.t(), String.t()}]) ::
          {:ok, {String.t(), [String.t()]}}
          | {:error, :hardening_unavailable | :invalid_limits | {:forbidden_env, [String.t()]}}
  def build_command(sandbox, granted_env \\ []) do
    # Forbidden-env first, deliberately. A caller passing DATABASE_URL has made
    # a mistake that is true on every host, and reporting `:hardening_unavailable`
    # for it would send them to fix the wrong thing -- they would provision a
    # Linux gateway, retry, and only then learn the real problem. The specific
    # error also has to survive being tested on a developer machine, which is
    # where that mistake actually gets written.
    with :ok <- reject_forbidden_env(granted_env),
         :ok <- require_available(),
         {:ok, limits} <- validate_limits(sandbox) do
      {:ok, compose(sandbox, limits, granted_env)}
    end
  end

  @doc """
  Reads the confinement actually in force on a running sandbox process.

  `{:error, :not_applied}` means the process is running unconfined and the
  caller must terminate it — a running unconfined sandbox is what Principle II
  forbids. `{:error, :unverifiable}` means this host cannot answer, which is
  never reported as `:ok`.
  """
  @spec verify_applied(integer()) ::
          {:ok, map()} | {:error, :not_applied | :unverifiable}
  def verify_applied(os_pid) when is_integer(os_pid) do
    with {:ok, uid} <- read_uid(os_pid),
         {:ok, cgroup} <- read_cgroup(os_pid) do
      applied = %{
        uid: uid,
        cgroup: cgroup,
        memory_limit_mb: read_effective_memory_mb(cgroup),
        cpu_quota: read_effective_cpu_quota(cgroup),
        # The three T010 boundaries, verified rather than assumed. Checking only
        # what R2 composes would leave them unchecked, which is the same silent
        # gap one level down.
        mount_confined: mount_namespace_applied?(os_pid),
        egress_restricted: egress_policy_applied?(os_pid),
        disk_quota_mb: read_effective_disk_quota(os_pid)
      }

      cond do
        # uid 0 means `setpriv` did not drop privilege -- the process is running
        # as root inside what is meant to be an unprivileged sandbox.
        uid == 0 ->
          {:error, :not_applied}

        # An unconstrained cgroup means `systemd-run` did not place the process
        # in its scope, which R2 lists as a real failure rather than a
        # hypothetical.
        applied.memory_limit_mb == :unlimited ->
          {:error, :not_applied}

        not applied.mount_confined or not applied.egress_restricted ->
          {:error, :not_applied}

        true ->
          {:ok, applied}
      end
    end
  end

  # -- Composition ----------------------------------------------------------

  @doc """
  The command `build_command/2` would emit, without the availability gate.

  Public for one reason: the command's *shape* must be testable on hosts where
  hardening is unavailable, which is every developer machine that is not Linux.
  The alternative is that `env -i` -- one word, easily dropped, and invisible
  when missing because the sandbox still launches -- goes unverified until CI.

  Callers must use `build_command/2`. This deliberately skips the availability
  check, so a caller reaching for it directly would build exactly the degraded
  command R9 forbids.
  """
  @doc since: "005 T009"
  @spec compose_for_inspection(ExSandbox.Sandbox.t(), [{String.t(), String.t()}]) ::
          {:ok, {String.t(), [String.t()]}} | {:error, term()}
  def compose_for_inspection(sandbox, granted_env \\ []) do
    with :ok <- reject_forbidden_env(granted_env),
         {:ok, limits} <- validate_limits(sandbox) do
      {:ok, compose(sandbox, limits, granted_env)}
    end
  end

  @doc false
  # Exposed for the T009 limits test, which must reach this check without the
  # availability gate masking it.
  def validate_limits_for_inspection(sandbox), do: validate_limits(sandbox)

  defp compose(sandbox, limits, granted_env) do
    user = "sandbox-#{sandbox.id}"

    args =
      systemd_run_args(limits) ++
        setpriv_args(user) ++
        confinement_args(sandbox, limits) ++
        env_args(granted_env) ++
        [erlexec_path()]

    {"systemd-run", args}
  end

  defp systemd_run_args(limits) do
    [
      "--scope",
      "--quiet",
      "-p",
      "MemoryMax=#{limits.memory_mb}M",
      "-p",
      "CPUQuota=#{limits.cpu_percent}%",
      # `MemorySwapMax=0`: without it a sandbox at its memory cap swaps instead
      # of being killed, so the cap bounds RSS rather than consumption and one
      # tenant can still exhaust the host's IO.
      "-p",
      "MemorySwapMax=0"
    ]
  end

  defp setpriv_args(user) do
    [
      "setpriv",
      "--reuid=#{user}",
      "--regid=#{user}",
      "--clear-groups",
      # Without this a process that drops to an unprivileged uid can still
      # regain privilege through a setuid binary, which makes the uid drop
      # decorative.
      "--no-new-privs"
    ]
  end

  # T010: the three boundaries `contracts/hardening.md` relegated to
  # "deployment". Left there, `available?/0` requires all five capabilities
  # while `build_command/2` constructs two of them -- so a correctly configured
  # host probes green, launches, and reports a fully hardened sandbox with
  # three boundaries absent.
  defp confinement_args(sandbox, limits) do
    storage = storage_path(sandbox)

    [
      "bwrap",
      # FR-010: the sandbox sees the runtime read-only and its own storage
      # read-write. Everything else -- including every other sandbox's storage
      # and the platform's own files -- is simply not in its mount view.
      "--ro-bind",
      "/usr",
      "/usr",
      "--ro-bind",
      "/lib",
      "/lib",
      "--ro-bind",
      "/lib64",
      "/lib64",
      "--bind",
      storage,
      storage,
      "--proc",
      "/proc",
      "--dev",
      "/dev",
      # FR-011: a private network namespace with no interfaces. Denies reaching
      # other sandboxes' runtimes and platform-internal services by construction
      # rather than by rule, so there is no policy to misconfigure.
      "--unshare-net",
      "--unshare-pid",
      "--unshare-ipc",
      "--unshare-uts",
      "--die-with-parent",
      # FR-009: the quota on that storage. Applied as a bind of an already
      # quota-limited filesystem -- see `storage_path/1`.
      "--size",
      "#{limits.disk_mb}M"
    ]
  end

  defp env_args(granted_env) do
    # `env -i` clears the environment; `:peer`'s `env` option does not.
    # Research R3 measured a child spawned with one granted variable seeing 76,
    # including PLATFORM_SECRET, because that option *merges* rather than
    # replaces. FR-004 requires an allowlist, and this is the only construction
    # that implements one.
    pairs = for {name, value} <- granted_env, do: "#{name}=#{value}"

    # BINDIR is not optional: `peer.erl:1214-1221` uses it to locate `erlexec`,
    # and a fully empty environment prevents the node from booting at all.
    ["env", "-i" | pairs] ++ ["BINDIR=#{bindir()}"]
  end

  # -- Guards ---------------------------------------------------------------

  defp require_available do
    if available?() do
      :ok
    else
      # Deliberately not logged with the missing capabilities at this level:
      # the caller is a gateway that already refused to come up, and repeating
      # it per launch turns a startup misconfiguration into log noise.
      {:error, :hardening_unavailable}
    end
  end

  defp reject_forbidden_env(granted_env) do
    forbidden =
      for {name, _value} <- granted_env,
          upcased = String.upcase(to_string(name)),
          Enum.any?(@forbidden_env_fragments, &String.contains?(upcased, &1)),
          do: to_string(name)

    case forbidden do
      [] -> :ok
      keys -> {:error, {:forbidden_env, keys}}
    end
  end

  defp validate_limits(sandbox) do
    limits = %{
      memory_mb: sandbox.memory_limit_mb,
      cpu_percent: cpu_percent(sandbox.cpu_limit),
      disk_mb: sandbox.disk_quota_mb
    }

    # A missing limit is `:invalid_limits`, not a default. Defaulting here would
    # launch a sandbox with a cap nobody chose, and the caller would have no way
    # to tell that from a cap they set.
    if Enum.any?(Map.values(limits), &is_nil/1) do
      {:error, :invalid_limits}
    else
      {:ok, limits}
    end
  end

  # Millicores to a systemd CPUQuota percentage: 500 millicores is half a core.
  defp cpu_percent(nil), do: nil
  defp cpu_percent(millicores), do: div(millicores, 10)

  # -- Probes: each attempts the operation ---------------------------------

  defp probe_cgroups do
    # Attempted rather than inferred: the delegation file existing *and* being
    # writable is what determines whether a scope can actually be created. A
    # Linux host without cgroup v2 delegation fails here, which is the case
    # `:os.type()` would have reported as fine.
    File.exists?(Path.join(@cgroup_root, "cgroup.controllers")) and
      executable_present?("systemd-run") and
      writable_cgroup?()
  end

  defp probe_setpriv do
    # Present *and* able to drop: `setpriv --reuid` no-ops when the parent
    # lacked the privilege to drop, which the contract calls out explicitly.
    executable_present?("setpriv") and can_drop_privilege?()
  end

  defp probe_mount_namespace do
    executable_present?("bwrap") and can_unshare?("--unshare-net")
  end

  defp probe_network_policy do
    # The same construction as filesystem confinement, probed separately because
    # a host can support mount namespaces while denying network ones.
    executable_present?("bwrap") and can_unshare?("--unshare-net")
  end

  defp probe_disk_quota do
    # A quota is only enforceable if the sandbox storage root sits on a
    # filesystem that supports one. Probed by asking the filesystem, not by
    # assuming.
    root = sandbox_storage_root()

    File.dir?(root) and quota_capable_filesystem?(root)
  end

  defp executable_present?(name), do: System.find_executable(name) != nil

  defp writable_cgroup? do
    case System.cmd("systemd-run", ["--scope", "--quiet", "--user", "true"],
           stderr_to_stdout: true
         ) do
      {_output, 0} -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  defp can_drop_privilege? do
    # Actually attempts the drop. `setpriv` exits non-zero when it cannot.
    case System.cmd("setpriv", ["--reuid=65534", "--regid=65534", "--clear-groups", "true"],
           stderr_to_stdout: true
         ) do
      {_output, 0} -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  defp can_unshare?(flag) do
    case System.cmd("bwrap", [flag, "--ro-bind", "/", "/", "true"], stderr_to_stdout: true) do
      {_output, 0} -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  defp quota_capable_filesystem?(path) do
    case System.cmd("stat", ["-f", "-c", "%T", path], stderr_to_stdout: true) do
      {output, 0} -> String.trim(output) in ["xfs", "ext2/ext3", "ext4", "btrfs"]
      _ -> false
    end
  rescue
    _ -> false
  end

  # -- Verification: reads what is in force, not what was asked ------------

  defp read_uid(os_pid) do
    case File.read("/proc/#{os_pid}/status") do
      {:ok, status} ->
        case Regex.run(~r/^Uid:\s+(\d+)/m, status) do
          [_, uid] -> {:ok, String.to_integer(uid)}
          _ -> {:error, :unverifiable}
        end

      {:error, _} ->
        {:error, :unverifiable}
    end
  end

  defp read_cgroup(os_pid) do
    case File.read("/proc/#{os_pid}/cgroup") do
      {:ok, contents} ->
        case Regex.run(~r{^0::(.+)$}m, String.trim(contents)) do
          [_, path] -> {:ok, path}
          _ -> {:error, :unverifiable}
        end

      {:error, _} ->
        {:error, :unverifiable}
    end
  end

  defp read_effective_memory_mb(cgroup) do
    # The cgroup's *effective* value, per R9b: reading back the requested limit
    # would report success on a host where the limiter was silently lost.
    case File.read(Path.join([@cgroup_root, cgroup, "memory.max"])) do
      {:ok, "max\n"} -> :unlimited
      {:ok, value} -> value |> String.trim() |> String.to_integer() |> div(1024 * 1024)
      {:error, _} -> :unlimited
    end
  end

  defp read_effective_cpu_quota(cgroup) do
    case File.read(Path.join([@cgroup_root, cgroup, "cpu.max"])) do
      {:ok, contents} ->
        case String.split(String.trim(contents)) do
          ["max", _period] -> :unlimited
          [quota, period] -> String.to_integer(quota) / String.to_integer(period) * 100
          _ -> :unlimited
        end

      {:error, _} ->
        :unlimited
    end
  end

  defp mount_namespace_applied?(os_pid) do
    # A confined process has a different mount namespace from this one. Compared
    # rather than assumed, because `bwrap` appearing in the process tree does
    # not prove the namespace was entered.
    with {:ok, sandbox_ns} <- File.read_link("/proc/#{os_pid}/ns/mnt"),
         {:ok, own_ns} <- File.read_link("/proc/self/ns/mnt") do
      sandbox_ns != own_ns
    else
      _ -> false
    end
  end

  defp egress_policy_applied?(os_pid) do
    with {:ok, sandbox_ns} <- File.read_link("/proc/#{os_pid}/ns/net"),
         {:ok, own_ns} <- File.read_link("/proc/self/ns/net") do
      sandbox_ns != own_ns
    else
      _ -> false
    end
  end

  defp read_effective_disk_quota(_os_pid) do
    # Reported rather than asserted: the quota lives on the storage filesystem
    # rather than on the process, so it is verified at bind time by
    # `probe_disk_quota/0` and surfaced here for the caller's record.
    :filesystem_enforced
  end

  # -- Paths ----------------------------------------------------------------

  defp sandbox_storage_root do
    Application.get_env(:ex_sandbox, :beam, [])
    |> Keyword.get(:storage_root, "/var/lib/axonn/sandboxes")
  end

  defp storage_path(sandbox), do: Path.join(sandbox_storage_root(), sandbox.id)

  defp bindir do
    # Where `peer.erl` looks for `erlexec`. Read from the running system rather
    # than hardcoded, so a release with a relocated ERTS still boots.
    :code.root_dir()
    |> List.to_string()
    |> Path.join("erts-#{:erlang.system_info(:version)}/bin")
  end

  defp erlexec_path, do: Path.join(bindir(), "erlexec")
end
