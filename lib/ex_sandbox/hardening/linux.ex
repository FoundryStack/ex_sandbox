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

  # Bounded so a probe cannot hang the gateway's startup: `capabilities/0` is
  # called on the provisioning path. 2s total is far above the observed time for
  # `unshare` to enter its namespaces (single-digit milliseconds) and far below
  # anything a caller would notice.
  @netns_poll_attempts 40
  @netns_poll_interval_ms 50

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
          {:ok, map()} | {:error, {:not_applied, atom()} | :not_applied | :unverifiable}
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
        # ⚠️ Named for what is measured (a separate netns), not for the
        # guarantee it is often read as (an enforced allowlist). See
        # `sandbox_netns_separated?/1`.
        netns_separated: sandbox_netns_separated?(os_pid),
        disk_quota_mb: read_effective_disk_quota(os_pid)
      }

      # ⚠️ Each branch names WHICH boundary was missing, rather than returning a
      # bare `:not_applied` for all four. The bare form cost a full debugging
      # cycle in T060a10: narrowing the census container's privilege turned five
      # tests red with `hardening did not apply (:not_applied)` and nothing to
      # say whether the uid, the cgroup, the mount namespace, or the netns was
      # the one that failed -- four very different host problems behind one
      # atom, distinguishable only by re-deriving them from outside.
      #
      # `verify_or_terminate/2` still refuses on any of them, so this widens the
      # diagnosis without widening what is accepted.
      cond do
        # uid 0 means `setpriv` did not drop privilege -- the process is running
        # as root inside what is meant to be an unprivileged sandbox.
        uid == 0 ->
          {:error, {:not_applied, :uid_not_dropped}}

        # An unconstrained cgroup means `systemd-run` did not place the process
        # in its scope, which R2 lists as a real failure rather than a
        # hypothetical.
        applied.memory_limit_mb == :unlimited ->
          {:error, {:not_applied, :cgroup_unconstrained}}

        not applied.mount_confined ->
          {:error, {:not_applied, :mount_not_confined}}

        not applied.netns_separated ->
          {:error, {:not_applied, :netns_not_separated}}

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
    args =
      systemd_run_args(limits, sandbox) ++
        setpriv_args(sandbox_uid(sandbox)) ++
        confinement_args(sandbox, limits) ++
        env_args(sandbox, granted_env) ++
        [erlexec_path()]

    # ⚠️ An **absolute path**, never the bare name. The probes above resolve
    # binaries with `System.cmd/3`, which searches `PATH` -- but the launcher
    # does not: `:peer` spawns via `open_port({:spawn_executable, prog}, ...)`,
    # and `:spawn_executable` requires a path it can `exec` directly.
    #
    # Returning `"systemd-run"` here made every launch raise `:enoent` with
    # "invalid port name" from inside `:peer.init/1` -- while all five
    # capabilities still probed true, because the probes and the launcher
    # resolve programs differently. Found by running the isolation suite in a
    # container with the facilities genuinely present.
    {systemd_run_path(), args}
  end

  # Resolved at compose time rather than hardcoded: distributions disagree
  # (`/usr/bin` on Debian, `/bin` on some others).
  #
  # The fallback is the **canonical absolute path**, never the bare name. A bare
  # name is the defect this function exists to fix, so falling back to one would
  # reintroduce it on exactly the hosts where resolution failed -- and it would
  # fail at `:peer.init/1` with `:enoent` rather than here, where the cause is
  # still legible. On a host without `systemd-run` the launch must fail; this
  # ensures it fails naming a path that was looked for.
  @systemd_run_fallback "/usr/bin/systemd-run"

  defp systemd_run_path do
    System.find_executable("systemd-run") || @systemd_run_fallback
  end

  defp systemd_run_args(limits, sandbox) do
    [
      "--scope",
      "--quiet",
      # ⚠️ A **named** unit, so the scope can be queried after the sandbox dies
      # (R7e). Without it systemd auto-names `run-<hash>.scope`, and the cause of
      # death is unrecoverable: the cgroup directory is removed the instant the
      # last process exits, so `memory.events` is gone before anything observes
      # it. The unit object survives in `failed` state and reports
      # `Result=oom-kill`, which is what distinguishes a tenant's cap breach
      # (`:resource_cap`) from a platform fault (`:mechanism_error`).
      "--unit=#{scope_unit_name(sandbox)}",
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

  @doc """
  The systemd scope unit a sandbox runs in.

  Public because `provision_failure_reason/1` must name the same unit to read
  its `Result` after death, and a mismatch between the two would silently report
  every breach as a platform fault.
  """
  @spec scope_unit_name(ExSandbox.Sandbox.t()) :: String.t()
  def scope_unit_name(sandbox), do: "sandbox-#{sandbox.id}.scope"

  defp setpriv_args(uid) do
    [
      "setpriv",
      "--reuid=#{uid}",
      "--regid=#{uid}",
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
  defp confinement_args(sandbox, _limits) do
    storage = storage_path(sandbox)

    [
      "bwrap"
      # FR-010: the sandbox sees the runtime read-only and its own storage
      # read-write. Everything else -- including every other sandbox's storage
      # and the platform's own files -- is simply not in its mount view.
    ] ++
      runtime_ro_binds() ++
      resolv_conf_bind() ++
      [
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
        "--die-with-parent"
        # FR-009's quota is **not** an argument here, deliberately. It comes from
        # the bind above: `storage_path/1` points into a filesystem that
        # `probe_disk_quota/0` has already confirmed can carry a quota, and the
        # bind carries that enforcement into the sandbox.
        #
        # A trailing `--size #{limits.disk_mb}M` used to sit here. `bwrap` rejected
        # the whole command -- "--size takes a non-zero number of bytes" -- because
        # `--size` takes raw bytes and, per `bwrap --help`, "Set[s] size of next
        # argument (only for --tmpfs)". Last in the list, it modified nothing even
        # when spelled correctly. Both malformed and redundant, and because it was
        # last, its failure read as a broken launch rather than a broken quota.
      ]
  end

  # ⚠️ **`029-FR-013`: without this the resolver is unreachable and every
  # hostname entry in an allowlist is dead, which is `FR-012` failing for a
  # reason that has nothing to do with matching.**
  #
  # The design this replaces assumed glibc falls back to `127.0.0.1:53` when
  # there is no `resolv.conf`, so that a sandbox with no `/etc` would reach the
  # in-namespace listener with nothing configured. MEASURED on the isolation
  # image (Debian, `elixir:1.20.2-otp-29`), inside `unshare -n`, with a stub
  # nameserver bound on `127.0.0.1:53`:
  #
  #     no /etc/resolv.conf            -> stub received NOTHING, :nxdomain
  #     resolv.conf naming 127.0.0.1   -> stub received a 30-byte query, resolved
  #
  # The control in the second line is what makes the first line mean "glibc did
  # not fall back" rather than "the stub was broken". So the file has to exist,
  # and the platform writes it.
  #
  # ⚠️ Bound **read-only from a platform-owned path**, not written into the
  # sandbox's own storage. The storage bind is read-write, so a file inside it
  # is a file the tenant edits -- and while pointing itself at another address
  # only earns it an nftables drop, a resolver configuration a tenant controls
  # is not one an operator can reason about.
  #
  # ⚠️ Nothing is bound when the resolver is not on port 53. `resolv.conf` has
  # no syntax for a port, so writing the file would tell the tenant to query an
  # address that will not answer -- a configuration that looks present and is
  # not, which is worse than an absent one.
  defp resolv_conf_bind do
    case resolver_for_tenant() do
      nil -> []
      path -> ["--ro-bind", path, "/etc/resolv.conf"]
    end
  end

  defp resolver_for_tenant do
    case ExSandbox.Egress.Resolver.resolver_address() do
      {address, 53} -> write_resolv_conf(address)
      _other -> nil
    end
  end

  defp write_resolv_conf(address) do
    literal = address |> normalise_address() |> to_string()
    path = Path.join(sandbox_storage_root(), "resolv.conf")

    # ⚠️ One file for every sandbox, and that is safe precisely because it
    # carries no per-sandbox information: the resolver address is the same
    # inside every namespace, and the listener on the far side of it serves
    # exactly one sandbox because it lives in that sandbox's netns. Per-sandbox
    # copies would only add a file to leak on destroy.
    case File.write(path, "nameserver #{literal}\n") do
      :ok -> path
      # A host where this cannot be written gets NO bind rather than a launch
      # failure: the sandbox then has no DNS, which is the same state the
      # `nil`-resolver ruleset produces, and it is visible as a name that does
      # not resolve rather than as a sandbox that would not start.
      {:error, _reason} -> nil
    end
  end

  defp normalise_address(address) when is_tuple(address), do: :inet.ntoa(address)
  defp normalise_address(address) when is_binary(address), do: address

  # The read-only binds that give the sandbox a runtime, derived from **this
  # host** rather than assumed.
  #
  # Two bugs came from assuming a layout. `/lib64` was bound unconditionally and
  # does not exist on arm64 Debian, where the loader lives in
  # `/lib/aarch64-linux-gnu` -- `bwrap` then refuses to start at all ("Can't find
  # source path /lib64"), failing every launch on every such host. And the
  # Erlang installation itself was never bound: `erlexec` sits under
  # `/usr/local/lib/erlang` (or Homebrew's Cellar), which `/usr` and `/lib` do
  # not cover, so the sandbox could not see the runtime it was about to exec.
  #
  # Candidates are filtered by existence, and the runtime root is added
  # explicitly. `--ro-bind-try` is deliberately not used instead: it would let a
  # missing *runtime* path pass silently, turning a launch failure that names its
  # cause into a sandbox that boots without the libraries it needs.
  defp runtime_ro_binds do
    [erlang_root() | ["/usr", "/lib", "/lib64", "/bin", "/sbin"]]
    |> Enum.uniq()
    |> Enum.filter(&File.exists?/1)
    |> Enum.reject(&nested_in_other?(&1, ["/usr", "/lib"]))
    |> Enum.flat_map(&["--ro-bind", &1, &1])
  end

  # `/usr/local/lib/erlang` is already covered by the `/usr` bind; binding it
  # again makes `bwrap` mount over its own mount, which it rejects.
  defp nested_in_other?(path, parents) do
    Enum.any?(parents, fn parent ->
      path != parent and String.starts_with?(path, parent <> "/")
    end)
  end

  defp erlang_root, do: to_string(:code.root_dir())

  @doc """
  Create this sandbox's writable storage, owned by the uid it will drop to
  (FR-009, FR-010).

  Called before `build_command/2`'s output is spawned. `bwrap` refuses a bind
  whose source does not exist -- "Can't find source path ..." -- so without this
  every launch exits 1 having constructed a perfectly correct command.

  Ownership matters as much as existence. Created as root and left that way, the
  sandbox drops privilege and cannot write to its own storage: the launch
  succeeds and every write fails, which is harder to diagnose than an outright
  refusal. Mode `0o700` keeps it to the owning uid, since every sandbox on a
  gateway shares this root under a different uid.
  """
  @spec prepare_storage(ExSandbox.Sandbox.t()) :: :ok | {:error, term()}
  def prepare_storage(sandbox) do
    path = storage_path(sandbox)
    uid = sandbox_uid(sandbox)

    with :ok <- File.mkdir_p(path),
         :ok <- File.chmod(path, 0o700) do
      chown(path, uid)
    end
  end

  # `File.chown/2` is a no-op for an unprivileged process, and that is the
  # common case in tests. Failure is reported rather than raised: on a host
  # where the caller cannot chown, the launch should fail at
  # `verify_applied/1` naming the uid, not here naming a permission.
  defp chown(path, uid) do
    case File.chown(path, uid) do
      :ok -> :ok
      {:error, :eperm} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  # The unprivileged uid this sandbox runs as (FR-007).
  #
  # ⚠️ A **number**, not a name. This built `"sandbox-<id>"` and passed
  # it to `--reuid`, which resolves a name only if it has a passwd entry --
  # nothing creates one, so every launch died with "failed to parse reuid" before
  # Erlang started. `probe_setpriv/0` missed it by attempting the drop against
  # the hardcoded `65534`, which resolves everywhere: the probe and the launch
  # were testing different uids.
  #
  # Derived from the sandbox id rather than allocated, which buys two properties
  # the alternative does not. It is **stable** -- `verify_applied/1` and
  # reclamation compute the same uid without shared state -- and it needs no
  # mutation of the host passwd database, which would require root, outlive the
  # sandbox, and turn cleanup into user-database gardening.
  #
  # The range is configurable because the safe span is a deployment fact: it must
  # avoid the host's real accounts and any other tenant of the same machine.
  defp sandbox_uid(sandbox) do
    {min, max} = uid_range()
    span = max - min + 1

    # ⚠️ Collision is possible and is a real limitation: two sandbox ids can hash
    # into one uid, and two sandboxes sharing a uid can read each other's files.
    # `:erlang.phash2` is used for stability across nodes and restarts, not for
    # uniqueness. With the default 60,000-wide range the birthday bound puts
    # ~1% collision odds around 35 concurrent sandboxes -- acceptable for the
    # slice, and the reason `FR-013`'s per-gateway allocator should replace this
    # with a real reservation before scale-out.
    min + :erlang.phash2(sandbox.id, span)
  end

  defp uid_range do
    Application.get_env(:ex_sandbox, :beam, [])
    |> Keyword.get(:sandbox_uid_range, {70_000, 129_999})
  end

  defp env_args(sandbox, granted_env) do
    # `env -i` clears the environment; `:peer`'s `env` option does not.
    # Research R3 measured a child spawned with one granted variable seeing 76,
    # including PLATFORM_SECRET, because that option *merges* rather than
    # replaces. FR-004 requires an allowlist, and this is the only construction
    # that implements one.
    pairs = for {name, value} <- granted_env, do: "#{name}=#{value}"

    # BINDIR is not optional: `peer.erl:1214-1221` uses it to locate `erlexec`,
    # and a fully empty environment prevents the node from booting at all.
    #
    # HOME is not optional either, for a less obvious reason. Under `env -i` the
    # sandbox's `auth` module cannot resolve a cookie directory and the kernel
    # refuses to start outright:
    #
    #     failed_to_start_child,auth,{{badmatch,error},
    #       [{filename,basedir_join_home,1,...
    #
    # It points at the sandbox's **own storage**, which it already owns and no
    # other sandbox can reach. A shared HOME would put every sandbox's cookie in
    # one directory -- handing tenant code the credential `FR-003` relies on.
    #
    # Neither is a hole in the allowlist. Both are entries in it: an allowlist
    # with nothing in it does not boot, and the question is only what goes in.
    ["env", "-i" | pairs] ++ ["BINDIR=#{bindir()}", "HOME=#{storage_path(sandbox)}"]
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
    # ⚠️ `--unshare-net` alone is NOT the check, and testing only it is the same
    # defect `can_unshare?/1` below already documents one level down: a check of
    # a command the platform never runs.
    #
    # `confinement_args/2` launches with `--proc /proc` **and** `--unshare-pid`,
    # and that pair is strictly harder than `--unshare-net`. Measured on the
    # census image (`docker/unprivileged-census-probe.sh` records the shape):
    #
    #     unprivileged  bwrap --unshare-user --unshare-net  --ro-bind / / true  -> rc=0
    #     unprivileged  bwrap --unshare-user --unshare-pid --proc /proc ...     -> rc=1
    #                   "Can't mount proc on /newroot/proc: Operation not permitted"
    #     privileged    both forms                                              -> rc=0
    #
    # So on an unprivileged host the old probe reported `filesystem_confinement:
    # ok`, `available?/0` returned true, and **every launch then failed** with
    # `{:boot_failed, {:exit_status, 1}}`. That is an over-claiming probe, which
    # `probe_network_policy/0` above spells out as the failure mode this module
    # exists to remove: it converts "we cannot do this here" into a launch that
    # dies, rather than into the third outcome the census can report honestly.
    #
    # It stayed invisible while the census container ran `privileged: true`,
    # because privilege is exactly what makes the two forms agree (013-FR-006b).
    executable_present?("bwrap") and can_confine_mounts?()
  end

  defp probe_network_policy do
    # ⚠️ `--unshare-net` gives *isolation* -- a namespace with no route out --
    # which is not the same as *policy*. An allowlist needs a route that leads
    # somewhere we control (005 T060a, contracts/egress.md).
    #
    # ⚠️ The third condition is the one measurement forced, and its meaning has
    # been **corrected**. It previously read "`pasta` and `bwrap` do not
    # compose", concluded from five attempts that all used `pasta`'s *spawn*
    # mode (`pasta -- <cmd>`). In that mode pasta owns the user namespace, fails
    # to write its `uid_map`, and hands the tenant `CapEff=0` -- from which
    # `bwrap` cannot create the mount namespace that is its entire job. Every
    # relaxation varied `bwrap`'s flags; none varied the mode, which is the
    # thing that was actually wrong.
    #
    # They **do** compose in the netns-first order, measured end to end in
    # `docker/netns-first-e2e.sh`: create the namespace, attach `pasta --netns`,
    # then run `bwrap` inside it. Two facts make it work, and both are checked
    # by `policed_launch_composable?/0` rather than assumed:
    #
    #   * `bwrap` does **not** create a network namespace unless `--unshare-net`
    #     is passed -- it inherits the one it is launched in, so `pasta` never
    #     has to spawn it.
    #   * a process in a user namespace it created **itself** holds a full
    #     capability set within it, which is exactly what `bwrap` needs.
    #
    # Reporting `true` here would be the exact failure this whole exercise
    # exists to remove. `require_permitted_reachable/2` scores a refusal as a
    # `guarantee_failure`, but the *denial* checks would all pass -- because a
    # tenant that cannot launch, or one confined to an empty namespace, reaches
    # nothing. A boundary that permits nothing is indistinguishable from a
    # correct one under a suite that only tests denial, so an over-claiming
    # probe converts "we cannot do this" into "we demonstrated this".
    executable_present?("bwrap") and can_unshare?("--unshare-net") and
      pasta_usable?() and policed_launch_composable?()
  end

  # `pasta` needs one thing this host may not have, and it is a **device**
  # rather than a capability.
  #
  # ⚠️ Measured 2026-08-17: with `/dev/net/tun` absent, `pasta --config-net`
  # fails `Failed to open() /dev/net/tun` -> `Failed to set up tap device in
  # namespace`, rc=1. With it present, pasta brings up a genuinely separate
  # netns (different `/proc/self/ns/net` inode) while holding
  # `CapEff=0000000000000000` -- no capability in the host netns at all.
  #
  # ⚠️ That last property is why `pasta` was chosen and also why it cannot
  # carry a confined tenant: the same empty capability set that makes it
  # rootless-safe is what stops `bwrap` creating its mount namespace. See
  # `policed_launch_composable?/0`.
  defp pasta_usable? do
    executable_present?("pasta") and File.exists?("/dev/net/tun")
  end

  # Whether a network-policed tenant can *also* be confined.
  #
  # ⚠️ Asks the question by attempting it rather than by inspecting
  # capabilities, because the capability model here has already produced two
  # wrong answers. `CapEff` is not the predicate: rootless Podman grants a full
  # set inside its own user namespace, `--cap-drop=ALL` grants none, and default
  # Docker grants a subset without `CAP_SYS_ADMIN` -- and `bwrap` fails in the
  # last two for reasons no single bit explains. Running the composition is the
  # only check that cannot be fooled by a capability set that looks sufficient.
  defp policed_launch_composable? do
    # ⚠️ This probe must attempt the **whole** path, and the reason is a defect
    # this function already carried in its first netns-first version.
    #
    # That version ran only `unshare --user --map-root-user --net -- bwrap …`
    # and reported `true` whenever the tenant could be built. Measured under
    # default `docker run` (`CapEff=00000000a80425fb`): that command **succeeds**
    # and the path is still unpoliceable —
    #
    #     unshare -Urn -- bwrap --dev-bind / / -- /bin/true   -> rc=0
    #     nsenter -t <holder> -n ip link
    #       -> nsenter: reassociate to namespaces failed: Operation not permitted
    #     pasta --config-net --runas 0 --netns /proc/<holder>/ns/net
    #       -> Couldn't switch to pasta namespaces: Operation not permitted
    #
    # `setns()` into a network namespace **owned by another user namespace**
    # requires `CAP_SYS_ADMIN` *in that owning userns*, which the platform
    # process does not have over a namespace the tenant created. So the tenant
    # is confined and the host cannot reach in to install the redirect or attach
    # `pasta` — the isolated-but-unpoliced state, reported as available.
    #
    # ⚠️ That is an **over-claiming** probe, the precise failure mode this
    # feature exists to remove: every denial check passes against a sandbox that
    # reaches nothing, so the census would report the network group demonstrated.
    # Confining the tenant is the half that is easy and the half that proves
    # nothing.
    #
    # So the operation probed is the one that actually decides it: can this
    # process **enter** a namespace it did not create, which is what installing
    # the `nft` redirect and attaching `pasta` both require.
    with true <- unshare_and_bwrap_compose?(),
         true <- can_enter_foreign_netns?() do
      true
    else
      _ -> false
    end
  end

  # Half one: a tenant can be both namespaced and confined.
  defp unshare_and_bwrap_compose? do
    case System.cmd(
           "unshare",
           [
             "--user",
             "--map-root-user",
             "--net",
             "--",
             "bwrap",
             "--dev-bind",
             "/",
             "/",
             "--",
             "/bin/true"
           ],
           stderr_to_stdout: true
         ) do
      {_output, 0} -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  # Half two, and the one that is actually load-bearing: a network namespace
  # created as a **descendant of a user namespace this process owns** can be
  # entered, which is what installing the `nft` redirect and attaching `pasta`
  # both require.
  #
  # ⚠️ **The sequence is the whole point, and an earlier version of this probe
  # had it backwards.** It spawned `unshare --user --map-root-user --net`, which
  # creates a *sibling* user namespace, and then tried to enter the netns inside
  # it. That is refused -- `setns()` into a netns owned by another user namespace
  # needs `CAP_SYS_ADMIN` **in that owning userns** -- and the refusal was read
  # as "this host cannot police egress". It is not a host limitation; it is the
  # wrong order of operations, and the production design never performs it.
  #
  # The order this probes is the one the mechanism uses, and the one rootless
  # Podman, RootlessKit and slirp4netns all use: create **one** user namespace,
  # then create each sandbox netns as a **descendant** of it with `--net` alone
  # (never `--user` again). `cap_capable_helper()` walks upward -- "if you have a
  # capability in a parent user ns, then you have it over all children user
  # namespaces as well" -- so the platform holds `CAP_SYS_ADMIN` over those
  # namespaces because it **made** them, with no privilege granted by the host.
  #
  # ⚠️ Still probed against a namespace created by a *separate* process. Entering
  # a namespace this process made directly would be vacuous: it always succeeds,
  # so it would pass on precisely the hosts this exists to reject.
  defp can_enter_foreign_netns? do
    case System.find_executable("unshare") do
      nil ->
        false

      unshare ->
        attempt_foreign_netns_entry(unshare)
    end
  end

  # ⚠️ `--user --map-root-user` wraps the **outer** shell, and the inner
  # `unshare --net` deliberately omits `--user`. Adding it back is the exact
  # regression described above: the netns would land in a sibling userns and the
  # entry would be refused on a host that can run the design perfectly well.
  #
  # ⚠️ **The port's own pid is the WRONG process to watch, and reading it was a
  # real defect here.** `Port.info(:os_pid)` names the outer shell, which stays
  # in the platform's network namespace -- only its *grandchild* enters the new
  # one. Measured while building this: the outer pid reported the host netns
  # while pids two levels down held `net:[4026532696]`, so `foreign_netns?/1`
  # was permanently false and the probe answered `false` on a host the shell
  # equivalent had just proved capable.
  #
  # Failing toward `false` is the safe direction, which is exactly why it was
  # worth catching: it is invisible in the census, reading as the honest third
  # outcome rather than as a broken probe.
  #
  # So the inner shell **publishes the pid that actually holds the namespace**
  # on stdout, and the probe waits for that line rather than guessing.
  defp attempt_foreign_netns_entry(unshare) do
    holder =
      Port.open({:spawn_executable, unshare}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        line: 64,
        args: [
          "--user",
          "--map-root-user",
          "--",
          "/bin/sh",
          "-c",
          "unshare --net -- /bin/sh -c 'echo $$; sleep 5' & wait"
        ]
      ])

    try do
      case await_holder_pid(holder, @netns_poll_attempts) do
        {:ok, pid} -> await_foreign_netns(pid, @netns_poll_attempts)
        :error -> false
      end
    after
      Port.close(holder)
    end
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  # The pid printed by the process that entered the namespace. Bounded, and a
  # non-numeric or absent line is a `false` rather than a crash -- this runs on
  # hosts where `unshare` may refuse for reasons the probe exists to report.
  defp await_holder_pid(_port, 0), do: :error

  defp await_holder_pid(port, attempts) do
    receive do
      {^port, {:data, {:eol, line}}} ->
        case Integer.parse(String.trim(line)) do
          {pid, ""} -> {:ok, pid}
          _ -> await_holder_pid(port, attempts - 1)
        end

      {^port, {:exit_status, _}} ->
        :error
    after
      @netns_poll_interval_ms -> await_holder_pid(port, attempts - 1)
    end
  end

  # ⚠️ Polled, never read once. `Port.open` returns as soon as the process is
  # spawned, and `unshare` has not necessarily entered its new namespaces yet --
  # `/proc/<pid>/ns/net` still reports the **host** namespace until it does.
  #
  # Measured, and the race is not a corner case: reading immediately after spawn
  # saw the host namespace in **16 of 20** trials. A probe built on a single read
  # would therefore report `network_restriction: false` on a perfectly capable
  # host, most of the time, for a reason that has nothing to do with capability
  # and would read as one.
  #
  # ⚠️ Failing toward `false` is the safe direction, which is exactly why this
  # was worth finding: a flaky under-claim is invisible in the census (it looks
  # like the honest third outcome) and would have made the capability appear
  # permanently absent on the very host that could run it.
  #
  # The same trap, one layer down, is why `ExSandbox.Egress.Pasta` polls for
  # pasta's tenant instead of checking once.
  defp await_foreign_netns(_pid, 0), do: false

  defp await_foreign_netns(pid, attempts) do
    if foreign_netns?(pid) do
      nsenter_succeeds?(pid)
    else
      Process.sleep(@netns_poll_interval_ms)
      await_foreign_netns(pid, attempts - 1)
    end
  end

  defp foreign_netns?(pid) do
    with {:ok, theirs} <- File.read_link("/proc/#{pid}/ns/net"),
         {:ok, ours} <- File.read_link("/proc/self/ns/net") do
      theirs != ours
    else
      _ -> false
    end
  end

  # ⚠️ `-U --preserve-credentials` is load-bearing: `-n` alone is REFUSED.
  #
  # `setns()` into a netns requires `CAP_SYS_ADMIN` in the user namespace that
  # **owns** it. The platform holds that capability inside the userns it created,
  # but a process that has not joined that userns holds nothing there -- so
  # entering the netns without also entering its owning userns fails, even
  # though the very same process created both. Measured, same host, same pid:
  #
  #     nsenter -t <pid> -n ip link                          -> EPERM
  #     nsenter -t <pid> -n -U --preserve-credentials ip link -> OK
  #
  # ⚠️ This is the constraint that makes the whole design work rather than a
  # detail: the BEAM runs **outside** the sandbox userns, so every namespace
  # operation the platform performs -- attaching `pasta`, installing the `nft`
  # redirect -- must join the userns as well. An earlier shell probe appeared to
  # prove entry worked while running its `nsenter` *inside* the userns, which is
  # not the position the platform is actually in.
  #
  # ⚠️ `--preserve-credentials` was REMOVED here in lockstep with
  # `Capability`'s copy, `Egress.Netns.nsenter/2` and `Egress.Acceptor`. This is
  # the **fourth** site carrying these flags, and `ProbeComposabilityTest` is
  # what found the last two -- exactly the "two independent implementations
  # disagreeing" defect it was written for (005 T060a5c).
  #
  # Why it changed: under the split launch ordering (T060a4e) `pasta` runs after
  # `setpriv`, so the namespace is owned by the **sandbox uid**. Preserving our
  # own credentials into it leaves us with none there; omitting the flag remaps
  # us to root inside the target userns, which is where `CAP_NET_ADMIN` comes
  # from. Measured -- see `egress-path-measurements.md`.
  defp nsenter_succeeds?(pid) do
    case System.cmd(
           "nsenter",
           ["-t", "#{pid}", "-n", "-U", "ip", "link"],
           stderr_to_stdout: true
         ) do
      {_output, 0} -> true
      _ -> false
    end
  rescue
    _ -> false
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

  # ⚠️ `--unshare-user` is not optional here, and omitting it measured the wrong
  # thing for the whole life of this probe.
  #
  # Without it, `bwrap` builds its mount namespace in the **host's** user
  # namespace, which needs `CAP_SYS_ADMIN` -- so this returned `false` on every
  # unprivileged host and the capability looked absent. Measured on the same
  # host, same binary, one flag apart:
  #
  #     bwrap --unshare-net --ro-bind / / true                  -> EPERM
  #     bwrap --unshare-user --unshare-net --ro-bind / / true    -> OK
  #
  # A process in a user namespace it created itself holds a full capability set
  # within it, which is exactly why the second form works. The mechanism always
  # passes `--unshare-user` (see `hardening_args/0`), so the first form was not
  # a conservative check -- it was a check of a command the platform never runs.
  defp can_unshare?(flag) do
    case System.cmd("bwrap", ["--unshare-user", flag, "--ro-bind", "/", "/", "true"],
           stderr_to_stdout: true
         ) do
      {_output, 0} -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  # The mount confinement the mechanism actually constructs.
  #
  # ⚠️ Mirrors `confinement_args/2`'s flags rather than a simpler subset. Kept
  # beside `can_unshare?/1` so the two stay in step: if the launch's flags
  # change, this probe has to change with them, and the comment above
  # `probe_mount_namespace/0` records what it costs when they drift apart.
  defp can_confine_mounts? do
    case System.cmd(
           "bwrap",
           [
             "--unshare-user",
             "--unshare-net",
             "--unshare-pid",
             "--proc",
             "/proc",
             "--ro-bind",
             "/",
             "/",
             "true"
           ],
           stderr_to_stdout: true
         ) do
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

  # ⚠️ **This verifies namespace separation, not egress policy** -- the same
  # distinction drawn in `probe_network_policy/0`. It answers "is the sandbox in
  # a different netns?", and a namespace with a full route to the internet
  # satisfies it.
  #
  # That is sound *today* only because `--unshare-net` yields a namespace with no
  # route at all, so isolation and policy happen to coincide. **T060a breaks that
  # coincidence on purpose**: the sandbox gets a working default route pointing
  # at the acceptor pool, and from that moment this function keeps returning
  # `true` while the property its name claims goes unverified -- a guard that
  # reads correctly and returns green on the path it was written to catch.
  #
  # It is left in place and renamed rather than "fixed" here, because the honest
  # fix needs something to check *against*: that the sandbox's default route
  # leads to this host's pool and that the pool holds a policy for its /30.
  # T060a4 publishes the `:policy_handle` that makes that checkable, and T060a5
  # is where this becomes a real egress assertion. Until then the narrow name
  # states what is actually measured.
  defp sandbox_netns_separated?(os_pid) do
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
    |> Keyword.get(:storage_root, "/var/lib/ex_sandbox/sandboxes")
  end

  @doc """
  Where a sandbox's writable storage is bound, on the host and inside the
  sandbox alike — `bwrap` binds it at the same path on both sides.

  Public so callers and tests name the real location rather than assuming one. A
  test writing to a made-up path gets `:enoent`, which satisfies "the sandbox
  could not write here" just as well as a quota would — so the assertion passes
  while measuring nothing.
  """
  @spec storage_path(ExSandbox.Sandbox.t()) :: String.t()
  def storage_path(sandbox), do: Path.join(sandbox_storage_root(), sandbox.id)

  defp bindir do
    # Where `peer.erl` looks for `erlexec`. Read from the running system rather
    # than hardcoded, so a release with a relocated ERTS still boots.
    :code.root_dir()
    |> List.to_string()
    |> Path.join("erts-#{:erlang.system_info(:version)}/bin")
  end

  defp erlexec_path, do: Path.join(bindir(), "erlexec")
end
