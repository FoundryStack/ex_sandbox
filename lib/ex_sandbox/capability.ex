defmodule ExSandbox.Capability do
  @moduledoc """
  What this library needs from its host, and whether it is actually there
  (012 T013, T022, FR-016).

  ## Determined, never assumed

  `FR-016` requires a library state what it needs and **report at runtime when
  it is unavailable**, rather than assuming it. The distinction is not academic:
  `005` R9 found that six of ten isolation criteria require Linux, and `013`
  Finding V2 found a capability that is absent under some container
  configurations. A library that assumed them would provide no isolation on
  those hosts while claiming to.

  ## Availability is evidence, not configuration

  A capability is reported available only on `FR-012a`'s evidence standard —
  observed behaviour, not the presence of a mechanism. `005` R9b measured the
  failure this guards against: `taskpolicy -m 100 sandbox-exec ... ./hog 300`
  allocates 300 MB under a nominal 100 MB cap and exits 0, because the limit is
  silently lost across the intervening `exec`. Every check short of *trigger a
  breach and watch it stop* reports that composition as working.

  So a check here answers "could this host enforce the cap at all", and it
  errs toward `false`. Whether a **particular mechanism** actually enforces it
  is `ExSandbox.Conformance`'s question, answered by breaching it.
  """

  # Bounded so a probe cannot hang the gateway's startup: `capabilities/0` is
  # called on the provisioning path. 2s total is far above the observed time for
  # `unshare` to enter its namespaces (single-digit milliseconds) and far below
  # anything a caller would notice.
  @netns_poll_attempts 40
  @netns_poll_interval_ms 50


  @type name ::
          :resource_limits
          | :filesystem_confinement
          | :privilege_separation
          | :network_restriction
          | :disk_quota

  @type t :: %__MODULE__{
          name: name(),
          available?: boolean(),
          detail: String.t() | nil
        }

  @enforce_keys [:name, :available?]
  defstruct [:name, :available?, :detail]

  @known [
    :resource_limits,
    :filesystem_confinement,
    :privilege_separation,
    :network_restriction,
    :disk_quota
  ]

  @doc "Every capability this library knows how to check."
  @spec known() :: [name()]
  def known, do: @known

  @doc """
  Checks one capability against the running host.

  Returns a report; it never raises, because "cannot determine" is a legitimate
  answer that must be *reported* rather than thrown (`FR-012b`).
  """
  @spec check(name() | atom()) :: t()
  def check(name) when name in @known do
    do_check(name, :os.type())
  end

  # ⚠️ An unknown name is **reported**, not raised. The docstring above promises
  # this function never raises because "cannot determine" is a legitimate answer,
  # and a `FunctionClauseError` here breaks that promise exactly where it matters
  # most: a mechanism whose `required_capabilities/0` names something this
  # library has not heard of would crash every caller that tried to check it --
  # including `ExSandbox.Conformance`, whose whole job is to *report* on hosts
  # rather than blow up on them. Measured: `Mechanism.Beam` returned
  # `:process_isolation` and the conformance suite died with a
  # `FunctionClauseError` instead of reporting anything.
  #
  # `available?: false` is the safe direction. An unrecognised capability is one
  # nothing has verified, and treating it as satisfied is the fail-open shape
  # this module exists to prevent.
  def check(name) when is_atom(name) do
    %__MODULE__{
      name: name,
      available?: false,
      detail:
        "unknown capability #{inspect(name)}; this library knows #{inspect(@known)}. " <>
          "A mechanism requiring it must either use a known name or extend this module."
    }
  end

  @doc "Checks every known capability."
  @spec check_all() :: [t()]
  def check_all, do: Enum.map(@known, &check/1)

  @doc """
  True when every capability in `required` is available.

  This is what an entry point calls before starting a sandbox: a mechanism whose
  required capability is missing must refuse rather than start unconfined
  (spec Edge Cases; `005` R9's macOS rule).
  """
  @spec satisfied?([name()]) :: boolean()
  def satisfied?(required) do
    Enum.all?(required, fn name -> check(name).available? end)
  end

  @doc """
  The capabilities in `required` that this host cannot provide.

  Returned rather than raised so a caller can report *which* one is missing —
  "unavailable" with no detail is the kind of message that gets ignored.
  """
  @spec missing([name()]) :: [t()]
  def missing(required) do
    required
    |> Enum.map(&check/1)
    |> Enum.reject(& &1.available?)
  end

  # cgroup v2 is the only mechanism here that caps memory in a way that survives
  # an intervening exec (005 R9b). Its absence is not a degraded mode -- it means
  # a cap can be configured and silently not apply, so this reports false.
  defp do_check(:resource_limits, {:unix, :linux}) do
    if File.exists?("/sys/fs/cgroup/cgroup.controllers") do
      available(:resource_limits)
    else
      unavailable(
        :resource_limits,
        "cgroup v2 is not mounted at /sys/fs/cgroup; memory and CPU caps cannot be enforced"
      )
    end
  end

  defp do_check(:resource_limits, {:unix, :darwin}) do
    unavailable(
      :resource_limits,
      "macOS `taskpolicy -m` applies to its immediate child only and is silently " <>
        "lost across an intervening exec (005 R9b), so a configured cap is not an " <>
        "enforced cap"
    )
  end

  # ⚠️ Both clauses below were presence checks, and `ExSandbox.CapabilityTest`'s
  # agreement guard caught them disagreeing with `Hardening.Linux` on macOS
  # (005 T060c). The moduledoc's rule -- availability is evidence, not
  # configuration -- was stated here and not followed here.
  #
  # The Linux clause accepted `/proc/self/ns/mnt` existing as evidence of mount
  # namespaces. That path exists in **every** Linux process, including one that
  # cannot unshare, so the fallback reported available unconditionally on Linux.
  # A host with unprivileged user namespaces disabled -- a common hardening
  # setting, and the default in several distributions -- passed this check and
  # then failed at launch.
  defp do_check(:filesystem_confinement, {:unix, :linux}) do
    cond do
      not executable?("bwrap") ->
        unavailable(
          :filesystem_confinement,
          "bubblewrap is not installed; the BEAM mechanism binds the sandbox filesystem " <>
            "with bwrap and has no fallback"
        )

      binds_root?() ->
        available(:filesystem_confinement)

      true ->
        unavailable(
          :filesystem_confinement,
          "bubblewrap is present but cannot bind a root filesystem; unprivileged " <>
            "user namespaces are likely disabled or restricted by the host policy"
        )
    end
  end

  # ⚠️ macOS reports unavailable even with `sandbox-exec` present, and the
  # previous `true` was a false available with a consumer.
  #
  # `ExSandbox.Mechanism.Beam.required_capabilities/0` names
  # `:filesystem_confinement` meaning *the mount namespace* -- its own comment
  # says so -- and that mechanism confines with `bwrap`, which does not exist on
  # macOS. Finding `sandbox-exec` on the PATH answered a question nobody asked:
  # it is not what the launch builds, so its presence said nothing about whether
  # the sandbox would be confined.
  #
  # This is the same shape as R9b's `taskpolicy -m`: a mechanism that exists,
  # looks applicable, and is not the one in the path being taken.
  defp do_check(:filesystem_confinement, {:unix, :darwin}) do
    unavailable(
      :filesystem_confinement,
      "macOS has no mount namespace, and `sandbox-exec` is not what the BEAM " <>
        "mechanism binds with (005 R9); the sandbox filesystem cannot be confined here"
    )
  end

  # ⚠️ Added late, and the lateness is the finding (005 T060c).
  #
  # `ExSandbox.Hardening.Linux` has probed `network_restriction` since it was
  # written, but nothing consulted the answer: it fed the capability map and
  # stopped there. `Capability.known/0` did not list it, no mechanism required
  # it, and the conformance suite had no network group. The result is that a
  # mechanism could implement the whole behaviour, pass every published check,
  # and confine nothing about the network -- `003-FR-002` asserted by a contract
  # that never tested it.
  #
  # Probed the way `Hardening.Linux` probes it, by *attempting* the unshare
  # rather than looking for bubblewrap on the PATH. A host can ship `bwrap` and
  # still deny network namespaces (unprivileged userns disabled, seccomp policy,
  # a container without `CAP_SYS_ADMIN`), and on those hosts the presence check
  # reports a boundary that would not be built.
  defp do_check(:network_restriction, {:unix, :linux}) do
    cond do
      not executable?("bwrap") ->
        unavailable(
          :network_restriction,
          "bubblewrap is not installed, so a network namespace cannot be created"
        )

      not unshares?("--unshare-net") ->
        unavailable(
          :network_restriction,
          "bubblewrap is present but `--unshare-net` failed; unprivileged user " <>
            "namespaces are likely disabled or restricted by the host policy"
        )

      # ⚠️ Everything below this line is what makes the namespace *policed*
      # rather than merely empty, and its absence was this probe's defect.
      #
      # `--unshare-net` alone yields a namespace with no interfaces. That denies
      # everything, which passes every denial check in the conformance suite
      # while enforcing no allowlist at all -- so reporting the capability
      # available on the strength of `--unshare-net` describes a boundary this
      # library will not build.
      #
      # ⚠️ It also *disagreed with the other probe for the same capability*.
      # `Hardening.Linux.probe_network_policy/0` has required pasta and the tap
      # device since T060a; this one did not. Because
      # `Conformance.Helpers.host_capability/1` consults **this** probe to
      # explain a third outcome, a host with bwrap and no pasta launched nothing
      # (hardening refused) while the census reported an undemonstrable check
      # with no cause attached -- the cause being known to the other probe, in
      # the same library, at the same moment.
      not executable?("pasta") ->
        unavailable(
          :network_restriction,
          "bubblewrap can unshare the network but `pasta` is not installed; " <>
            "`--unshare-net` gives isolation (a namespace with no route out) " <>
            "and not policy (a route leading somewhere the allowlist is " <>
            "enforced), so egress could be denied entirely but never permitted " <>
            "selectively (005 T060a)"
        )

      not File.exists?("/dev/net/tun") ->
        unavailable(
          :network_restriction,
          "`pasta` is installed but `/dev/net/tun` is absent; pasta needs the " <>
            "tap device to build the sandbox's route, and without it fails " <>
            "with `Failed to open() /dev/net/tun` at launch rather than here"
        )

      # ⚠️ The third condition, and the one that keeps this probe in step with
      # `Hardening.Linux.probe_network_policy/0`. The comment above warns about
      # exactly this class of disagreement -- and it recurred: once that probe
      # started testing whether a policed launch can be *composed*, this one
      # still reported `available` on the strength of pasta being installed.
      #
      # The consequence was not a wrong answer in isolation; it was 30 failed
      # conformance checks. `ExSandbox.provision/2` consults **this** probe,
      # found the capability available, and proceeded -- then `require_hardening/0`
      # consulted the *other* probe, found it missing, and refused with a bare
      # `:mechanism_error`. Every group scored that as a `guarantee_failure`,
      # so "this host cannot police egress" was reported as "halting the host
      # from inside the sandbox was not refused".
      #
      # Measured: `pasta` and `bwrap` do not compose. `pasta` starts its child
      # with `CapEff=0` in a user namespace whose mappings it could not write,
      # and `bwrap` then cannot create the mount namespace that is its entire
      # purpose. See `egress-path-measurements.md`.
      not policed_launch_composable?() ->
        unavailable(
          :network_restriction,
          "`pasta` and `/dev/net/tun` are both present but a policed launch " <>
            "cannot be composed: `pasta` starts its child with no capabilities " <>
            "in a user namespace it could not map, and `bwrap` then fails with " <>
            "`No permissions to create new namespace`. Egress could be denied " <>
            "entirely but never permitted selectively, and the tenant could not " <>
            "be confined either (005 T060a, egress-path-measurements.md)"
        )

      true ->
        available(:network_restriction)
    end
  end

  # ⚠️ macOS reports unavailable, and this is the change that makes provisioning
  # refuse where it previously succeeded (Principle II). `sandbox-exec` can deny
  # network operations by profile, but `005` R9's standard is enforcement that
  # survives an intervening exec, and the same measurement that disqualified
  # `taskpolicy -m` applies: a profile is inherited by the immediate child and
  # is not a namespace, so a sandbox that re-execs is no longer inside it.
  #
  # A host that cannot confine the network was never providing the guarantee.
  # It was only never asked.
  defp do_check(:network_restriction, {:unix, :darwin}) do
    unavailable(
      :network_restriction,
      "macOS has no network namespace; a `sandbox-exec` profile is not inherited " <>
        "across an intervening exec (005 R9b), so egress cannot be confined"
    )
  end

  # ⚠️ Found by the parity guard in `ExSandbox.CapabilityTest`, not by review --
  # the same defect as `:network_restriction`, one capability over. `disk_quota`
  # was probed by `Hardening.Linux`, constructed by `build_command/2` as the
  # sandbox's storage bind, and absent from this vocabulary, so no mechanism
  # could require it.
  #
  # A quota is only enforceable if the storage root sits on a filesystem that
  # supports one, which is asked of the filesystem rather than assumed. The root
  # is read from config for the same reason `Hardening.Linux.storage_path/1` is
  # public: a check against a made-up path answers about the wrong filesystem.
  defp do_check(:disk_quota, {:unix, :linux}) do
    root = sandbox_storage_root()

    cond do
      not File.dir?(root) ->
        unavailable(
          :disk_quota,
          "the sandbox storage root #{root} does not exist, so no quota can be applied " <>
            "to it (set :ex_sandbox, :beam, storage_root: ... or create the directory)"
        )

      quota_capable_filesystem?(root) ->
        available(:disk_quota)

      true ->
        unavailable(
          :disk_quota,
          "#{root} is not on a quota-capable filesystem (xfs, ext2/3/4, btrfs), " <>
            "so a configured disk limit would not be enforced"
        )
    end
  end

  # tmpfs and overlayfs, which is what a container without a mounted volume
  # gives you, take no project quota. Reported rather than assumed, for the same
  # reason as everywhere else here.
  defp do_check(:disk_quota, {:unix, :darwin}) do
    unavailable(
      :disk_quota,
      "APFS has no per-directory quota equivalent that survives the sandbox launch"
    )
  end

  defp do_check(:privilege_separation, {:unix, _}) do
    # Dropping to an unprivileged uid needs privilege to start with.
    case System.cmd("id", ["-u"], stderr_to_stdout: true) do
      {"0\n", 0} ->
        available(:privilege_separation)

      {_, 0} ->
        unavailable(
          :privilege_separation,
          "not running as root, so the sandbox cannot drop to a separate uid"
        )

      _ ->
        unavailable(:privilege_separation, "could not determine the effective uid")
    end
  end

  # Anything unrecognised reports unavailable rather than assuming. Under-
  # claiming on an unknown host is FR-012b's rule.
  defp do_check(name, os) do
    unavailable(name, "unsupported host: #{inspect(os)}")
  end

  # Evidence, not configuration (FR-012a): the confinement is actually built and
  # a process runs inside it, rather than bubblewrap being found on the PATH.
  #
  # ⚠️ The filesystem probe is a **bind**, not an unshare flag. An earlier
  # version of this probed `--unshare-ns`, which is not a bubblewrap flag at all
  # -- `build_command/2` unshares net, pid, ipc and uts, and confines the
  # filesystem with `--ro-bind`/`--bind`. Probing a flag the launch never uses
  # answers about the wrong thing even when it happens to return the right
  # boolean.
  defp binds_root?, do: bwrap_runs?([])

  # ⚠️ `--unshare-user` is not optional, and omitting it measured the wrong thing.
  #
  # Without it, `bwrap` builds its mount namespace in the **host's** user
  # namespace, needing `CAP_SYS_ADMIN` -- so this reported `false` on every
  # unprivileged host. Same host, same binary, one flag apart:
  #
  #     bwrap --unshare-net --ro-bind / / true                 -> EPERM
  #     bwrap --unshare-user --unshare-net --ro-bind / / true  -> OK
  #
  # The mechanism always passes `--unshare-user`, so the bare form was not a
  # conservative check but a check of a command the platform never runs.
  #
  # ⚠️ `binds_root?/0` above deliberately stays flagless: it asks whether plain
  # root binding works, which is a different question and must not acquire a
  # user namespace it does not need.
  defp unshares?(flag), do: bwrap_runs?(["--unshare-user", flag])

  defp bwrap_runs?(flags) do
    case System.cmd("bwrap", flags ++ ["--ro-bind", "/", "/", "true"], stderr_to_stdout: true) do
      {_output, 0} -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  # Deliberately duplicated from `Hardening.Linux` rather than delegated.
  # `ExSandbox.Capability` is consulted before a mechanism is chosen -- it is
  # how a caller learns whether provisioning would work at all -- so it must not
  # depend on one mechanism's hardening module. `ExSandbox.CapabilityTest`
  # asserts the two agree on this host, which is the property that matters and
  # the one a shared helper would make untestable.
  defp sandbox_storage_root do
    Application.get_env(:ex_sandbox, :beam, [])
    |> Keyword.get(:storage_root, "/var/lib/axonn/sandboxes")
  end

  defp quota_capable_filesystem?(path) do
    case System.cmd("stat", ["-f", "-c", "%T", path], stderr_to_stdout: true) do
      {output, 0} -> String.trim(output) in ["xfs", "ext2/ext3", "ext4", "btrfs"]
      _ -> false
    end
  rescue
    _ -> false
  end

  defp executable?(name), do: System.find_executable(name) != nil

  defp available(name), do: %__MODULE__{name: name, available?: true, detail: nil}

  # ⚠️ Asks by attempting, not by reading `CapEff`. The capability model here
  # has already produced two wrong answers: rootless Podman grants a full set
  # inside its own user namespace, `--cap-drop=ALL` grants none, and default
  # Docker grants a subset without `CAP_SYS_ADMIN` -- and `bwrap` fails in the
  # last two for reasons no single bit explains. Running the composition is the
  # only check that cannot be fooled by a capability set that looks sufficient.
  # ⚠️ Must stay identical to `ExSandbox.Hardening.Linux`'s copy. These two
  # probes answering differently about the same host is a defect this file has
  # already carried once (005 T060a5c): `provision/2` consults this one and
  # `require_hardening/0` the other, so a disagreement reports "this host cannot
  # police egress" as a pile of phantom conformance failures with no cause
  # attached.
  #
  # ⚠️ netns-**first**, and `bwrap` without `--unshare-net` so it inherits the
  # namespace rather than replacing it. The previous version ran pasta's spawn
  # mode, which fails for a reason about the mode rather than the tools.
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
           ["--user", "--map-root-user", "--net", "--", "bwrap", "--dev-bind", "/", "/", "--",
            "/bin/true"],
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
  # `--preserve-credentials` keeps the caller's uid rather than remapping to
  # root, which is what `util-linux` requires when joining a userns this process
  # is not already privileged in. RootlessKit passes the same pair for the same
  # reason.
  defp nsenter_succeeds?(pid) do
    case System.cmd(
           "nsenter",
           ["-t", "#{pid}", "-n", "-U", "--preserve-credentials", "ip", "link"],
           stderr_to_stdout: true
         ) do
      {_output, 0} -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  defp unavailable(name, detail),
    do: %__MODULE__{name: name, available?: false, detail: detail}
end
