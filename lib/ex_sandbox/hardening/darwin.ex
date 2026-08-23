defmodule ExSandbox.Hardening.Darwin do
  @moduledoc """
  OS-level confinement for the BEAM mechanism on macOS (014 T011 – T015, from
  `005` R9b and `014`'s re-measurement at
  `specs/014-desktop-deployment/spikes/darwin-hardening/baseline.md`).

  ## The composition, and why it has this exact shape

      sandbox-exec -f <profile>                       # filesystem + network
        /bin/sh -c 'ulimit -t <N>; exec …'            # RLIMIT_CPU
          taskpolicy -m <M>                           # memory
            <target> <args…>

  Measured on macOS 26.5 (25F71), the same build `005` R9b was measured on:
  `hog 300` under `-m 150` exits **137**, a spinner that does not limit itself
  exits **152** under `ulimit -t 2`, an ordinary crash exits **139**, and a
  program inside its caps exits **0**. Four outcomes, mutually distinguishable
  (`SC-002`, `FR-016`).

  ⚠️ **`taskpolicy` must be the IMMEDIATE PARENT of the target.** R9b measured
  `taskpolicy -m 100 sandbox-exec … ./hog 300` allocating 300 MB under a nominal
  100 MB cap and exiting 0 — the cap silently lost across the intervening exec,
  failing **open**. Reproduced here while writing this module: inverted, the hog
  prints `allocated 300 MB OK`.

  The rule that generalises from that trap is *`taskpolicy` immediately above
  the target*, **not** "no shell anywhere" (baseline Finding 3). A shell placed
  *before* `taskpolicy` that `exec`s keeps the memory cap, because `exec`
  replaces the shell image rather than forking. That is the only reason the CPU
  cap is reachable at all: `RLIMIT_CPU` needs something to call `ulimit`, and
  this is where it can stand without breaking the memory cap.

  ## ⚠️ The intervening shell is an injection surface, and it is closed by argv

  `ExSandbox.Hardening.Linux` composes argv directly and never reaches a shell.
  This composition does, and `/bin/sh -c` takes a **single string a shell
  parses** — so a target path or argument interpolated into that string is
  command injection through the sandbox's own command line, which no
  `sandbox-exec` profile closes.

  Nothing tenant-influenced is ever interpolated. The script is a constant plus
  two integers this module formats itself; the target and every argument are
  passed **after** the script, where `sh` binds them to `$0` and `$@`:

      /bin/sh -c 'ulimit -t 2; exec /usr/sbin/taskpolicy -m 150 "$0" "$@"' \\
        /path/to/target arg1 arg2

  They are therefore argv positions, not text, and never reach the parser.
  `ExSandbox.Hardening.DarwinTest` proves it by launching a target whose
  arguments carry `;`, `$(…)`, backticks, `|`, `&` and `>` with side effects
  aimed at a directory the profile permits writing, and asserting the bytes
  arrive literally and no side effect occurs.

  ## Why the profile starts from `(allow default)` — and what that costs

  `(deny default)` is **not viable** and this is measured, not assumed: it kills
  even `/bin/echo`, because `dyld` cannot start. R9b recorded it; the template
  this module renders (`specs/005-sandbox-beam/spikes/macos-isolation/work.sb`)
  carries the finding in its own first comment.

  So the profile is a **deny-list over a permissive default**, which is weaker
  than default-deny confinement: any operation nobody thought to deny is
  allowed. That gap is the reason `FR-013` exists — to *report* the isolation
  level honestly — and `:privilege_separation` stays `unavailable` on Darwin for
  exactly this reason (T021). It must not be papered over by describing this
  profile as confinement equivalent to `bwrap`'s.

  Note that `ExSandbox.Hardening.Confinement` reaches a stronger, near
  default-deny profile for a *control-plane* process, by enumerating the
  runtime's read set. That is a different problem: it confines one known binary
  to one known path. Here the target is arbitrary tenant code whose read set is
  unknown before it runs, and an incomplete permit list does not confine it —
  it kills it before its first instruction, which reads as every breach
  assertion passing (R30's measured `134` on every case, control included).

  ## ⚠️ `RLIMIT_AS`, `RLIMIT_DATA` and `RLIMIT_RSS` do not work on Darwin

  Measured on this host (T001, and R9b before it): `setrlimit` on all three
  fails with `EINVAL`, from a soft and hard limit of `RLIM_INFINITY`.
  `RLIMIT_CPU` is the one that sets.

  This matters to anyone porting the Linux mechanism: the address-space cap that
  would be the obvious memory limit is **unavailable**, which is why the memory
  cap here is `taskpolicy -m` and not a `setrlimit` call. A port that reached for
  `RLIMIT_AS` would cap nothing, silently, and every check short of breaching it
  would report success.

  ## ⚠️ `ulimit -t` is per-process and inherited, not pooled

  Each child gets its own fresh budget, so a target that forks multiplies the
  CPU it can consume. This is strictly weaker than a cgroup CPU quota, and it is
  a gap `FR-013a` must **report** rather than paper over. It is not a reason to
  omit the cap (`FR-014`): a per-process ceiling stops the single runaway loop,
  which is the case `US2` names.

  ## Refusal, never a spec with the cap missing

  Every function that cannot build a requested cap returns
  `{:error, {:cannot_enforce, capability, detail}}`. It never returns a launch
  spec with the cap omitted — that is the fail-open shape `ExSandbox.Hardening`'s
  docstring forbids, and it is indistinguishable from success at every layer that
  does not breach the cap to check.

  What is refused here, and why:

    * `:disk_mb` — **always**. Darwin has no per-process disk quota this
      composition can impose. A spec that quietly dropped it would report a disk
      cap that does not exist.
    * `:memory_mb` when `taskpolicy` is absent from the host.
    * `:cpu_millicores` without a `:wall_clock_seconds` budget — see
      `apply/3` for why the two are one number here.

  ## What this module does NOT enforce

  The wall-clock budget. `launch_spec/0` describes how to *start* a process;
  nothing in it can kill one later. The caller enforcing `:wall_clock_seconds`
  by killing the OS pid is the supervisor's job, and `014` T009 verifies the
  outcome is distinguishable from every exit status — there is none.
  """

  @behaviour ExSandbox.Hardening

  # `apply/2` is a callback name this module must answer to, and `Kernel.apply/2`
  # and `/3` are auto-imported. Without this the local definitions are a compile
  # error rather than a shadowing.
  import Kernel, except: [apply: 2, apply: 3]

  alias ExSandbox.Hardening.Confinement

  # Absolute paths, never bare names — the lesson `Hardening.Linux`'s
  # `systemd_run_path/0` records: probes resolve through `PATH` with
  # `System.cmd/3`, but the launcher spawns with `:spawn_executable`, which
  # requires a path it can `exec` directly. A bare name here fails at
  # `:peer.init/1` with `:enoent`, far from the cause.
  @sandbox_exec_fallback "/usr/bin/sandbox-exec"
  @taskpolicy_fallback "/usr/sbin/taskpolicy"
  @shell "/bin/sh"

  # Where generated profiles live. A directory of our own so `release/1` can
  # refuse to unlink anything it did not write.
  @profile_dir_name "ex_sandbox_darwin_profiles"

  # Paired on purpose: `sandbox-<suffix>.sb` grants `work-<suffix>`, so one name
  # yields the other and `release/1` needs no second handle.
  @profile_prefix "sandbox-"
  @workdir_prefix "work-"

  @typedoc "What `available?/0` found, per capability this backend constructs."
  @type capability_map :: %{
          process_separation: boolean(),
          memory_cap: boolean(),
          cpu_cap: boolean(),
          filesystem_confinement: boolean()
        }

  @doc """
  True only when every facility this composition needs is present **and the
  composition actually runs**.

  ⚠️ The launch is attempted, not inferred. Reading `:os.type()` and checking two
  binaries onto `PATH` would report `true` on a host where `sandbox-exec` refuses
  the generated profile — and that is the silent-failure mode this whole slice
  exists to remove. So this renders a real profile, runs `/usr/bin/true` through
  the full four-layer composition, and requires exit `0`. Measured cost: ~13 ms.

  ⚠️ It establishes that the composition **runs**, never that a cap **holds**.
  Only breaching a cap establishes that, which is `ExSandbox.Conformance`'s job
  and `ExSandbox.Hardening.DarwinTest`'s (`012-FR-012a`).
  """
  @spec available?() :: boolean()
  def available? do
    capabilities() |> Map.values() |> Enum.all?()
  end

  @doc """
  What this host can construct, per capability.

  Deliberately narrower than `ExSandbox.Hardening.Linux.capabilities/0`:
  `:network_restriction` and `:disk_quota` are absent because this backend does
  not claim them. `(deny network*)` is in the profile and denies egress, but the
  allowlisted-egress construction `:network_restriction` names on Linux has no
  counterpart here, and `:disk_quota` is refused outright by `apply/3`.
  """
  @spec capabilities() :: capability_map()
  def capabilities do
    darwin? = match?({:unix, :darwin}, :os.type())
    taskpolicy? = darwin? and not is_nil(System.find_executable("taskpolicy"))
    composes? = darwin? and smoke_launch_succeeds?()

    %{
      process_separation: composes?,
      memory_cap: taskpolicy? and composes?,
      cpu_cap: composes?,
      filesystem_confinement: composes?
    }
  end

  @impl ExSandbox.Hardening
  @doc """
  Capabilities this backend requires of the host.

  `:disk_quota` is deliberately absent: it is not required, it is **refused**.
  Requiring it would make every macOS host report this backend unavailable for a
  limit most callers never set, while a caller who *does* set it would get a
  vague "unavailable" instead of the specific `{:cannot_enforce, :disk_quota, …}`
  that names what is actually missing.
  """
  @spec required_capabilities() :: [atom()]
  def required_capabilities do
    [:process_separation, :memory_cap, :cpu_cap, :time_budget, :filesystem_confinement]
  end

  @doc """
  Builds the launch specification enforcing `limits` for `command`.

  The caller launches **this**, not the command it asked about — `cmd` is
  `sandbox-exec` and the requested command is buried four layers down.

  ## Options

    * `:workdir` — the one directory the target may write. Created if absent.
      Defaults to a fresh directory under the system temp dir.
    * `:home` — the home directory whose `Documents` and `.ssh` the profile
      denies reading. Defaults to `System.user_home!/0`.
    * `:env` — the environment allowlist, passed through unchanged. Defaults to
      `[]`; this module does not filter it, and a caller passing platform
      secrets has made a mistake `Hardening.Linux.build_command/2` catches.
    * `:cd` — working directory. Defaults to `:workdir`. ⚠️ Not a boundary; the
      boundary is the profile. It defaults to the workdir because a process
      whose cwd the profile denies **reading** cannot `getcwd`, and `/bin/sh`
      then prints `shell-init: error retrieving current directory` on every
      launch (measured, from a cwd under `~/Documents`).

  ## The CPU cap is one number derived from two limits

  `ulimit -t` is a ceiling on **CPU-seconds consumed**, not on the *rate* of
  consumption — Darwin offers this composition no rate cap at all. So the two
  are related by the budget the process is allowed to run for:

      cpu_seconds = ceil(wall_clock_seconds × cpu_millicores ÷ 1000)

  At one core (`cpu_millicores: 1000`) that is the wall-clock budget itself: a
  process spinning flat out hits the CPU ceiling exactly when its budget runs
  out, and one trying to use two cores hits it in half the time.

  ⚠️ This derivation is **this module's choice**, not a measured fact. What was
  measured is only that `ulimit -t N` kills a non-self-limiting spinner at 152.
  A `:cpu_millicores` with no `:wall_clock_seconds` is therefore refused rather
  than defaulted: there is no budget to derive a ceiling from, and a default here
  would impose a CPU cap nobody chose while reading as the one they asked for.
  """
  @impl ExSandbox.Hardening
  @spec apply({String.t(), [String.t()]}, ExSandbox.Hardening.limits(), keyword()) ::
          {:ok, ExSandbox.Hardening.launch_spec()}
          | {:error, {:cannot_enforce, atom(), String.t()}}
  def apply({command, args}, limits, opts \\ [])
      when is_binary(command) and is_list(args) and is_map(limits) and is_list(opts) do
    # ⚠️ Every refusal is decided BEFORE anything is created on disk. A
    # `{:cannot_enforce, …}` returned after the profile was written leaves a
    # `.sb` file that no `release/1` will ever be called for, because the caller
    # never received a handle to it — a leak that grows once per rejected launch.
    with :ok <- require_darwin(),
         :ok <- refuse_disk_quota(limits),
         {:ok, memory_args} <- memory_layer(limits),
         {:ok, cpu_prefix} <- cpu_layer(limits),
         # ⚠️ ONE suffix for the profile and the workdir it grants, so the two
         # are siblings with matching names. That is what lets `release/1`
         # reclaim both from the profile path alone — the only handle
         # `build_command/3` hands back, since its `{cmd, argv}` return has
         # nowhere to carry a workdir.
         suffix = unique_suffix(),
         {:ok, workdir} <- resolve_workdir(opts, suffix),
         home = Path.expand(Keyword.get(opts, :home) || System.user_home!()),
         {:ok, profile_path} <- write_profile(workdir, home, suffix) do
      {:ok,
       %{
         cmd: sandbox_exec_path(),
         args:
           ["-f", profile_path, @shell, "-c", cpu_prefix <> memory_exec(memory_args)] ++
             [Confinement.resolve_executable(command) | args],
         env: Keyword.get(opts, :env, []),
         cd: Keyword.get(opts, :cd, workdir)
       }}
    end
  end

  @doc """
  The composed command alone, in `ExSandbox.Hardening.Linux.build_command/2`'s
  return shape.

  Public for the same reason `compose_for_inspection/2` is over there: the
  ordering regression test (`014` T017) has to assert on the argv this backend
  emits, and re-deriving it in the test would let the test and the module drift
  apart in the one place where drift is the defect being guarded against.
  """
  @spec build_command({String.t(), [String.t()]}, ExSandbox.Hardening.limits(), keyword()) ::
          {:ok, {String.t(), [String.t()]}} | {:error, {:cannot_enforce, atom(), String.t()}}
  def build_command({command, args}, limits, opts \\ []) do
    case apply({command, args}, limits, opts) do
      {:ok, %{cmd: cmd, args: argv}} -> {:ok, {cmd, argv}}
      {:error, _} = error -> error
    end
  end

  @doc """
  Removes the `.sb` profile this backend generated for a sandbox.

  Accepts the launch spec `apply/3` returned, or the profile path directly.

  Idempotent, for the reason `destroy/1` is: a release that raises on an already
  released handle turns every crash-and-retry into a stuck sandbox, and the
  caller has no way to ask whether it already ran.

  ⚠️ It unlinks **only** a `.sb` file inside this module's own profile directory.
  The path arrives inside a launch spec that a caller may have built, edited, or
  read from configuration, and `File.rm/1` on whatever it names would make this
  function an arbitrary-delete primitive reachable from the launch path.
  """
  @impl ExSandbox.Hardening
  @spec release(term()) :: :ok | {:error, term()}
  def release(%{args: args}) when is_list(args), do: release(profile_path_from_args(args))

  def release(nil), do: :ok

  def release(path) when is_binary(path) do
    if ours?(path) do
      reclaim_default_workdir(path)

      case File.rm(path) do
        :ok -> :ok
        {:error, :enoent} -> :ok
        {:error, reason} -> {:error, reason}
      end
    else
      # Not an error: a caller releasing a spec built by another backend, or one
      # whose profile lives elsewhere, has not failed at anything.
      :ok
    end
  end

  def release(_other), do: :ok

  @doc """
  Renders the `sandbox-exec` profile for `workdir` and `home`.

  Public so a test can read the profile this backend would generate without
  launching anything, and so the substitution can be asserted on directly.
  """
  @spec render_profile(String.t(), String.t()) :: String.t()
  def render_profile(workdir, home) when is_binary(workdir) and is_binary(home) do
    # Verbatim from the R9b-verified template at
    # `specs/005-sandbox-beam/spikes/macos-isolation/work.sb`, with `@WORKDIR@`
    # and `@HOME@` substituted. Embedded rather than read from `specs/` at
    # runtime because this library ships without that tree — a profile read from
    # a path that does not exist in a release is a launch failure at the worst
    # possible moment, and a silently empty profile would be worse.
    #
    # ⚠️ Rule order is load-bearing: later rules win in SBPL, so the blanket
    # `(deny file-write*)` must come before the workdir grant.
    """
    ; Generated by ExSandbox.Hardening.Darwin from 005 R9b's work.sb.
    ; (deny default) is NOT viable — it kills even /bin/echo (dyld cannot start).
    (version 1)
    (allow default)
    (deny network*)
    (deny file-write*)
    (allow file-write* (subpath #{sb_string(workdir)}) (literal "/dev/null") (literal "/dev/stdout") (literal "/dev/stderr"))
    (deny file-read* (subpath #{sb_string(Path.join(home, "Documents"))}) (subpath #{sb_string(Path.join(home, ".ssh"))}))
    """
  end

  @doc """
  The directory generated profiles are written to.

  Public because `release/1`'s refusal to unlink anything outside it is a safety
  property a test has to be able to name.
  """
  @spec profile_dir() :: String.t()
  def profile_dir, do: Path.join(System.tmp_dir!(), @profile_dir_name)

  # -- Layers ---------------------------------------------------------------

  defp require_darwin do
    case :os.type() do
      {:unix, :darwin} ->
        :ok

      other ->
        {:error,
         {:cannot_enforce, :process_separation,
          "ExSandbox.Hardening.Darwin requires a darwin host; this is #{inspect(other)}. " <>
            "sandbox-exec and taskpolicy do not exist elsewhere"}}
    end
  end

  # ⚠️ Refused, never dropped. There is no per-process disk quota on Darwin that
  # this composition can impose, and a launch spec that omitted the request would
  # report a disk cap that is not there — the exact fail-open shape the behaviour
  # docstring forbids (014 T014).
  defp refuse_disk_quota(limits) do
    case Map.get(limits, :disk_mb) do
      nil ->
        :ok

      0 ->
        :ok

      mb ->
        {:error,
         {:cannot_enforce, :disk_quota,
          "a #{mb} MB disk quota was requested; Darwin has no per-process disk quota this " <>
            "composition can impose. sandbox-exec confines WHERE a process may write, never " <>
            "HOW MUCH"}}
    end
  end

  defp memory_layer(limits) do
    case Map.get(limits, :memory_mb) do
      nil ->
        {:ok, nil}

      mb when is_integer(mb) and mb > 0 ->
        case System.find_executable("taskpolicy") do
          nil ->
            if File.regular?(@taskpolicy_fallback) do
              {:ok, {@taskpolicy_fallback, mb}}
            else
              {:error,
               {:cannot_enforce, :memory_cap,
                "a #{mb} MB memory cap was requested but `taskpolicy` is not on PATH and " <>
                  "#{@taskpolicy_fallback} does not exist. Darwin's setrlimit alternatives " <>
                  "(RLIMIT_AS, RLIMIT_DATA, RLIMIT_RSS) all fail EINVAL, so there is no " <>
                  "fallback that caps anything"}}
            end

          path ->
            {:ok, {path, mb}}
        end

      other ->
        {:error,
         {:cannot_enforce, :memory_cap,
          "memory_mb must be a positive integer, got #{inspect(other)}"}}
    end
  end

  defp cpu_layer(limits) do
    case {Map.get(limits, :cpu_millicores), Map.get(limits, :wall_clock_seconds)} do
      {nil, nil} ->
        {:ok, ""}

      {nil, budget} when is_integer(budget) and budget > 0 ->
        {:ok, "ulimit -t #{budget}; "}

      {millicores, budget}
      when is_integer(millicores) and millicores > 0 and is_integer(budget) and budget > 0 ->
        {:ok, "ulimit -t #{max(ceil(budget * millicores / 1000), 1)}; "}

      {millicores, nil} when is_integer(millicores) ->
        {:error,
         {:cannot_enforce, :cpu_cap,
          "a #{millicores} millicore CPU cap was requested with no :wall_clock_seconds. " <>
            "Darwin offers this composition no CPU *rate* cap; `ulimit -t` is a ceiling on " <>
            "CPU-seconds consumed, and there is no budget to derive one from. Supply " <>
            ":wall_clock_seconds, or omit the CPU cap deliberately"}}

      {millicores, budget} ->
        {:error,
         {:cannot_enforce, :cpu_cap,
          "cpu_millicores and wall_clock_seconds must be positive integers, got " <>
            "#{inspect(millicores)} and #{inspect(budget)}"}}
    end
  end

  # ⚠️ Everything below is a CONSTANT or an integer this module formatted. The
  # target and its arguments are appended after this string as argv, where `sh`
  # binds them to `$0` and `$@` — see the moduledoc. Nothing tenant-influenced
  # is ever interpolated here.
  defp memory_exec(nil), do: ~S|exec "$0" "$@"|

  defp memory_exec({taskpolicy, mb}) when is_integer(mb) do
    # The path came from `System.find_executable/1` or a compile-time constant,
    # so it is not tenant-influenced. Checked anyway: this is the one string that
    # a shell parses, and a check costs nothing next to what it would cost to be
    # wrong about where a PATH entry came from.
    if Regex.match?(~r/\A[A-Za-z0-9_\/.\-]+\z/, taskpolicy) do
      ~s|exec #{taskpolicy} -m #{mb} "$0" "$@"|
    else
      # Falls back to the constant rather than emitting the path: an
      # un-interpolatable taskpolicy path means no memory cap, and `memory_layer/1`
      # has already established one was requested, so this must not silently drop
      # it. Raising here is the fail-closed direction — the caller cannot receive
      # a spec whose memory layer went missing.
      raise ArgumentError,
            "refusing to interpolate a taskpolicy path containing shell metacharacters: " <>
              inspect(taskpolicy)
    end
  end

  # -- Profile --------------------------------------------------------------

  defp resolve_workdir(opts, suffix) do
    workdir =
      case Keyword.get(opts, :workdir) do
        nil -> Path.join(profile_dir(), @workdir_prefix <> suffix)
        given when is_binary(given) -> Path.expand(given)
      end

    case File.mkdir_p(workdir) do
      :ok ->
        # ⚠️ Resolved, not merely expanded. MEASURED in `Hardening.Confinement`:
        # `System.tmp_dir!()` on macOS is `/var/folders/…`, a symlink to
        # `/private/var/folders/…`, and the kernel evaluates the profile against
        # the RESOLVED path. Permitting the unresolved spelling denies the very
        # directory it was asked to permit.
        {:ok, resolve_symlinks(workdir)}

      {:error, reason} ->
        {:error,
         {:cannot_enforce, :filesystem_confinement,
          "cannot create workdir #{inspect(workdir)}: #{inspect(reason)}. A profile whose " <>
            "writable subpath does not exist permits writing nowhere, which reads as " <>
            "confinement while actually being a broken launch"}}
    end
  end

  defp write_profile(workdir, home, suffix) do
    case sandbox_exec_available() do
      {:ok, _path} ->
        dir = profile_dir()
        path = Path.join(dir, @profile_prefix <> suffix <> ".sb")

        with :ok <- File.mkdir_p(dir),
             :ok <- File.write(path, render_profile(workdir, home)) do
          {:ok, path}
        else
          {:error, reason} ->
            {:error,
             {:cannot_enforce, :filesystem_confinement,
              "cannot write the sandbox profile to #{inspect(path)}: #{inspect(reason)}"}}
        end

      {:error, _} = error ->
        error
    end
  end

  defp sandbox_exec_available do
    cond do
      path = System.find_executable("sandbox-exec") ->
        {:ok, path}

      File.regular?(@sandbox_exec_fallback) ->
        {:ok, @sandbox_exec_fallback}

      true ->
        {:error, {:cannot_enforce, :filesystem_confinement, "`sandbox-exec` is not present"}}
    end
  end

  defp sandbox_exec_path do
    System.find_executable("sandbox-exec") || @sandbox_exec_fallback
  end

  # A path containing `"` or `\` would otherwise end the SBPL string literal and
  # let the rest be read as profile syntax — profile injection in the one place
  # that decides the boundary. Same escaping as
  # `ExSandbox.Hardening.Confinement.sb_string/1`, which is private there.
  defp sb_string(path) do
    escaped = path |> String.replace("\\", "\\\\") |> String.replace("\"", "\\\"")
    "\"" <> escaped <> "\""
  end

  # Follows the symlink chain component by component, the way the kernel will,
  # because macOS puts the symlink at `/var` rather than at the leaf.
  defp resolve_symlinks(path) do
    path
    |> Path.expand()
    |> Path.split()
    |> Enum.reduce([], fn part, acc ->
      candidate = Path.join(acc ++ [part])

      case File.read_link(candidate) do
        {:ok, target} ->
          if Path.type(target) == :absolute,
            do: Path.split(target),
            else: acc ++ Path.split(target)

        _ ->
          acc ++ [part]
      end
    end)
    |> Path.join()
  end

  defp unique_suffix do
    Integer.to_string(System.unique_integer([:positive])) <>
      "-" <> Integer.to_string(:erlang.phash2(self()))
  end

  defp profile_path_from_args(args) do
    case args do
      ["-f", path | _] -> path
      _ -> nil
    end
  end

  # The sibling workdir this module invented, if it invented one — a caller who
  # supplied `:workdir` gets a directory outside `profile_dir/0`, which the
  # `ours?/1` guard on the join below excludes.
  #
  # ⚠️ `File.rmdir/1`, never `File.rm_rf/1`. It removes the directory only when
  # it is empty, so a workdir still holding a tenant's output survives. This
  # function must not become a delete-the-tenant's-work primitive reachable from
  # the launch path.
  defp reclaim_default_workdir(profile_path) do
    suffix =
      profile_path
      |> Path.basename()
      |> String.replace_prefix(@profile_prefix, "")
      |> String.replace_suffix(".sb", "")

    candidate = Path.join(profile_dir(), @workdir_prefix <> suffix)
    if ours?(candidate, ""), do: File.rmdir(candidate)
  end

  defp ours?(path, extname \\ ".sb") do
    dir = profile_dir()
    Path.extname(path) == extname and String.starts_with?(Path.expand(path), dir <> "/")
  end

  # -- Probe ----------------------------------------------------------------

  # Runs `/usr/bin/true` through the full four-layer composition. Anything short
  # of this is inference: `Hardening.Linux`'s moduledoc records that probes must
  # attempt the operation they report on, and a profile `sandbox-exec` rejects
  # would pass every presence check.
  defp smoke_launch_succeeds? do
    case apply({"/usr/bin/true", []}, %{memory_mb: 64, wall_clock_seconds: 5}) do
      {:ok, spec} ->
        try do
          {_out, status} =
            System.cmd(spec.cmd, spec.args, cd: spec.cd, stderr_to_stdout: true, env: [])

          status == 0
        rescue
          _ -> false
        after
          release(spec)
        end

      {:error, _} ->
        false
    end
  end
end
