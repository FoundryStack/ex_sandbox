defmodule ExSandbox.Hardening.Confinement do
  @moduledoc """
  Confines a **control-plane** process to one filesystem path (015 T107, from
  research R16 and R30).

  ## This is the mirror image of a sandbox, not a smaller one

  `ExSandbox.Hardening.Linux` confines untrusted tenant code. This confines a
  *trusted* process that holds a credential — the delegated Claude Code CLI —
  and the difference is not degree but direction. R16 found that the sandbox
  guarantee never covered it: `confinement_args/2` binds storage into the
  **sandboxed process's** mount namespace (`linux.ex:316-345`), and a
  control-plane process is not in that namespace, so every sandbox's storage is
  an ordinary host path to it. `storage_path/1` makes them siblings under one
  root (`linux.ex:1101`), so the next tenant along is a `..` away, and above
  that sits the platform's own deployment unit — database, billing, and model
  credentials, per `013`.

  ## ⚠️ The posture is INVERTED on both counts, which is why this is a separate module

  A tenant sandbox strips credentials and denies the network. This profile must
  do neither:

    * **The environment passes through**, credential included. The CLI cannot
      reach the model without it.
    * **Egress is permitted.** `--unshare-net` would deny the model endpoint.

  ⚠️ **It is a distinct entry point rather than a flag on the tenant profile,
  and that is a safety property.** A boolean like `strip_credentials: false`
  would put unstripping a *tenant* sandbox one wrong argument away. There is no
  argument here that can widen `ExSandbox.Hardening.Linux`, because this code
  never touches it.

  ⚠️ **`@forbidden_env_fragments` is NOT widened to admit the credential.** R14
  requires "a deliberate separate channel, never a weakening of that list", and
  that list is what keeps credentials out of every sandbox (`015-FR-005`). This
  module is that separate channel.

  ## Both platforms enforce it — measured, not assumed (R30)

  T107 named `bwrap` and `sandbox-exec` as though symmetric, and the honest
  expectation was that macOS would have to refuse: `012` R9b measured
  `sandbox-exec`'s *sibling* mechanism, `taskpolicy -m`, failing **open** across
  an intervening exec.

  ⚠️ That expectation was wrong, and inheriting it would have shipped a needless
  refusal. R30 measured a deny-by-default `sandbox-exec` profile on darwin
  25.5.0: the permitted path readable and writable, a sibling denied, `..`
  denied, the restriction surviving **three** nested execs, not widenable by
  re-invoking `sandbox-exec` under itself, and not defeated by a symlink out of
  the permitted subtree. A credential-shaped variable survived.

  ⚠️ **This does not contradict `capability.ex`'s macOS refusals, and must not be
  gated on them.** `:filesystem_confinement` reports unavailable on macOS
  because it means *the mount namespace the BEAM mechanism binds with*
  (`capability.ex:182-199`) — a statement about the tenant profile's
  construction, not about whether macOS can restrict paths. Requiring that
  capability here would refuse on macOS for a reason that does not apply, which
  is precisely the error its own comment warns about one capability over: *"a
  mechanism that exists, looks applicable, and is not the one in the path being
  taken."* `:network_restriction`'s macOS refusal stands and is irrelevant —
  this profile **wants** egress.

  ## ⚠️ A profile that names too little kills the process instead of confining it

  R30's first two attempted profiles exited **134 on every case, including the
  control**: the runtime's own read set was not permitted, so the process died
  before reaching any path. Every breach looked "denied". A suite asserting only
  on denials would have reported a boundary that did not exist.

  This is why `runtime_read_paths/0` below is generous about the *runtime* while
  the *data* boundary stays a single path, and why `ExSandbox.Hardening.ConfinementTest`
  runs a control first. The two are one mechanism: a permit list wide enough to
  execute, a data boundary narrow enough to matter.

  ## A working directory is not a boundary (T109)

  ⚠️ `:cd` decides where a process **begins**, never where it can go. `015` T109
  VERIFIED that no caller passes it at all, so today's CLI inherits the BEAM's
  own working directory — the platform's deployment root — meaning it starts
  *among* the files this module exists to put out of reach. Setting `:cd` to a
  tenant's directory would improve where it starts and confine nothing; there is
  no `--cwd` flag on the CLI (T045), so scope is decided at launch or nowhere.
  Callers MUST treat `permit_path` as the boundary and `:cd` as a convenience.
  """

  @typedoc """
  How to launch the confined process.

  Deliberately the same shape as `ExSandbox.Hardening.launch_spec/0`: the caller
  launches **this**, not the command it asked about, because the returned `cmd`
  is the confinement wrapper.
  """
  @type launch_spec :: %{
          cmd: String.t(),
          args: [String.t()],
          env: [{String.t(), String.t()}],
          cd: String.t()
        }

  @doc """
  Builds a launch specification confining `command` to `permit_path`.

  ## Options

    * `:permit_path` (required) — the one directory the process may read and
      write. Everything else is denied, including sibling directories and any
      path reachable by `..`.
    * `:env` — environment passed through **unmodified**, credential included.
      Defaults to `[]`.
    * `:cd` — working directory. A starting point, not a boundary; see above.
      Defaults to the resolved `:permit_path`, and the caller has to launch
      with it — see "⚠️ The working directory is part of the boundary".
    * `:permit_extra_subpaths` — additional directories the process may read and
      write, **on top of** `:permit_path`. Defaults to `[]`, which is the only
      value this library ever chooses for itself.

  ## ⚠️ The working directory is part of the boundary

  `:cd` used to default to `nil`, leaving the child in whatever directory the
  caller happened to be in. That is not neutral. The directory is denied by the
  profile by construction — it is not `:permit_path` — so a confined process
  started there resolves every relative path outside its own boundary, and on
  darwin cannot read its own working directory at all.

  MEASURED 2026-08-25, and the shape of the measurement is the interesting
  part. A VM started in X that `chdir`s to Y before spawning gives the child a
  cwd of Y that the child cannot `getcwd`:

      cwd=…/apps/ex_sandbox status=0 out=""                      # started there
      cwd=…/apps/ex_sandbox status=0 out="shell-init: error …"   # chdir'd there

  Same directory, same profile, different result — so `sh` under confinement
  wrote a diagnostic to stderr in an umbrella `mix test` (Mix `chdir`s into
  each app) and wrote nothing at all when the same suite ran from the app's own
  directory. `ConfinementExtraSubpathsTest` failed on exactly that, and reading
  it as a flake was wrong: it was reproducible from one directory and
  unreproducible from the other.

  Defaulting to `:permit_path` puts the child inside the one directory the
  profile fully grants. `Axonn.ModelAccess.Backend.DelegatedCli` already passed
  `cd: storage_path` by hand, which is the same value — so this makes the
  contract say what the only production caller had already worked out, rather
  than leaving each caller to rediscover it.

  ## ⚠️ `:permit_extra_subpaths` is opaque here, and that is the whole design

  This library does not know, and must not learn, which program is being
  confined or why one of them needs a path outside its own storage. `012` is an
  extraction boundary: naming a particular CLI's scratch directory here would
  put an application's workaround inside a generic hardening module, where the
  next reader cannot tell a measured necessity from an accident.

  So the list arrives already decided. The caller is what reads its own
  configuration, derives whatever the path depends on, and answers for the cost
  of each entry. Every entry widens the boundary this module exists to draw —
  `[]` is the default precisely so that widening is something a caller has to
  write down.

  Each entry is resolved the way `:permit_path` is, and is emitted **after** the
  blanket deny, because later rules win in a `sandbox-exec` profile.

  Returns `{:error, {:cannot_enforce, capability, detail}}` when this host
  cannot build the profile, matching `ExSandbox.Hardening`'s contract. It never
  returns a spec with the confinement omitted — that is the fail-open shape
  `005` R9b measured, and it is indistinguishable from success at every layer
  that does not attempt a breach.
  """
  @spec confine({String.t(), [String.t()]}, keyword()) ::
          {:ok, launch_spec()} | {:error, {:cannot_enforce, atom(), String.t()}}
  def confine({command, args}, opts) when is_binary(command) and is_list(args) do
    case Keyword.fetch(opts, :permit_path) do
      {:ok, permit_path} when is_binary(permit_path) ->
        build(command, args, Path.expand(permit_path), opts)

      _ ->
        {:error,
         {:cannot_enforce, :path_confinement,
          "no :permit_path given; a profile with nothing to permit denies everything, " <>
            "which passes every breach assertion for the wrong reason"}}
    end
  end

  @doc """
  Resolves `command` the way the kernel will: a bare name through `PATH`, then
  the symlink chain, component by component.

  Public because the grant and the invocation **must agree**, and they are
  written in two different places. MEASURED on Linux (D14a): binding the
  symlink's *target* while invoking the *symlink* fails outright. Resolving
  first is what deletes that failing case, and a second implementation of the
  rule is how the two ends drift back apart.

  ⚠️ macOS makes the same demand from the other direction: SBPL **resolves
  symlinks before matching a path filter**, so a grant written against a
  symlink silently never matches. Nothing fails; the path is simply denied.

  Returns `command` unchanged when it is not on `PATH` and cannot be resolved,
  so an unlaunchable command still reaches the exec and earns the operating
  system's own error rather than a substituted one.
  """
  @spec resolve_executable(String.t()) :: String.t()
  def resolve_executable(command) when is_binary(command) do
    if Path.type(command) == :absolute do
      resolve(command)
    else
      case System.find_executable(command) do
        nil -> command
        found -> resolve(found)
      end
    end
  end

  defp build(command, args, permit_path, opts) do
    env = Keyword.get(opts, :env, [])
    cd = Keyword.get(opts, :cd)

    # ⚠️ Resolved HERE so that everything downstream -- the grant, the bind and
    # the exec -- names the same file. See `resolve_executable/1`.
    command = resolve_executable(command)

    # ⚠️ Resolved, not merely expanded. MEASURED: `System.tmp_dir!()` on macOS is
    # `/var/folders/…`, a symlink to `/private/var/folders/…`, and the kernel
    # evaluates the profile against the RESOLVED path. Permitting the unresolved
    # spelling denies the very path it was asked to permit -- the control failed
    # on exactly this, reporting `Operation not permitted` for P itself.
    permit_path = resolve(permit_path)

    # ⚠️ Resolved for the same reason, and it is not academic: the only caller
    # that passes anything names a path under `/tmp`, and `/tmp` is a symlink to
    # `/private/tmp` on darwin. A grant written against the unresolved spelling
    # builds cleanly, reads correctly, and matches nothing.
    extras = extra_subpaths(opts, permit_path)

    with :ok <- ensure_permit_path(permit_path),
         {:ok, cmd, wrapped} <- wrap(:os.type(), command, args, permit_path, extras) do
      # ⚠️ The RESOLVED path, for the same reason the grant uses it: on darwin
      # `System.tmp_dir!()` is a symlink, and a `cd` into the unresolved
      # spelling lands the child somewhere the profile does not name.
      {:ok, %{cmd: cmd, args: wrapped, env: env, cd: cd || permit_path}}
    end
  end

  # `[]` unless the caller said otherwise, and no branch here can produce a
  # non-empty list on its own.
  #
  # Entries already covered by `permit_path` are dropped: on darwin a duplicate
  # grant is merely noise, but on Linux binding underneath an existing bind
  # makes `bwrap` mount over its own mount, which it rejects outright -- the
  # same failure `nested_in_other?/2` exists to avoid for the runtime set.
  defp extra_subpaths(opts, permit_path) do
    opts
    |> Keyword.get(:permit_extra_subpaths, [])
    |> Enum.filter(&is_binary/1)
    |> Enum.map(&resolve/1)
    |> Enum.uniq()
    |> Enum.reject(&(&1 == permit_path or nested_in_other?(&1, [permit_path])))
  end

  # `bwrap` refuses a bind whose source does not exist, and `sandbox-exec`
  # happily permits a subpath that is not there. Both end as "the process could
  # not read P" -- the control failing for a reason that has nothing to do with
  # confinement. Checked here so the error names the real cause.
  # Follows the symlink chain the way the kernel will, component by component,
  # because macOS puts a symlink at `/var` rather than at the leaf. Returns the
  # expanded path unchanged when a component cannot be resolved, so a
  # non-existent path still reaches `ensure_permit_path/1` and earns a named
  # error rather than a crash.
  defp resolve(path) do
    path
    |> Path.expand()
    |> Path.split()
    |> Enum.reduce([], &resolve_component/2)
    |> Path.join()
  end

  defp resolve_component(part, acc) do
    candidate = Path.join(acc ++ [part])

    case File.read_link(candidate) do
      {:ok, target} ->
        if Path.type(target) == :absolute,
          do: Path.split(target),
          else: acc ++ Path.split(target)

      _ ->
        acc ++ [part]
    end
  end

  defp ensure_permit_path(permit_path) do
    if File.dir?(permit_path) do
      :ok
    else
      {:error,
       {:cannot_enforce, :path_confinement,
        "permit_path #{inspect(permit_path)} is not an existing directory"}}
    end
  end

  defp wrap({:unix, :linux}, command, args, permit_path, extras) do
    if System.find_executable("bwrap") do
      {:ok, "bwrap", bwrap_args(command, args, permit_path, extras)}
    else
      {:error,
       {:cannot_enforce, :path_confinement,
        "bubblewrap (`bwrap`) is not on PATH; the path boundary cannot be built"}}
    end
  end

  defp wrap({:unix, :darwin}, command, args, permit_path, extras) do
    case System.find_executable("sandbox-exec") do
      nil ->
        {:error,
         {:cannot_enforce, :path_confinement,
          "`sandbox-exec` is not on PATH; the path boundary cannot be built"}}

      sandbox_exec ->
        # `-p` takes the profile inline, so there is no temporary file to create,
        # secure, or leak. `release/1` has nothing to clean up as a result.
        {:ok, sandbox_exec, ["-p", sandbox_profile(permit_path, command, extras), command | args]}
    end
  end

  defp wrap(other, _command, _args, _permit_path, _extras) do
    {:error,
     {:cannot_enforce, :path_confinement,
      "no path-confinement facility is known for #{inspect(other)}"}}
  end

  # ⚠️ `--ro-bind` the runtime, `--bind` exactly one data path. Note what is
  # ABSENT and deliberately so, against the tenant profile at `linux.ex:316-345`:
  # no `--unshare-net`, because this process must reach the model endpoint.
  defp bwrap_args(command, args, permit_path, extras) do
    runtime_read_paths()
    |> Enum.flat_map(&["--ro-bind", &1, &1])
    |> Kernel.++(command_bind(command, permit_path))
    |> Kernel.++(extra_binds(extras))
    |> Kernel.++([
      "--bind",
      permit_path,
      permit_path,
      "--proc",
      "/proc",
      "--dev",
      "/dev",
      # Namespaces that do NOT touch the network. `--die-with-parent` is what
      # keeps `FR-011`'s reaping from regressing through the added process
      # level (T108).
      "--unshare-pid",
      "--unshare-ipc",
      "--unshare-uts",
      "--die-with-parent",
      command
    ])
    |> Kernel.++(args)
  end

  # ⚠️ Deny-by-default, then permit the runtime read set. R30 measured that
  # omitting this set does not deny reads -- it kills the process with 134
  # before any read happens, so every breach assertion "passes" while the
  # control fails. The order matters: later rules win in a `sandbox-exec`
  # profile, so the permitted subpath must come after the blanket deny.
  defp sandbox_profile(permit_path, command, extras) do
    runtime =
      runtime_read_paths()
      |> Enum.map(&"(subpath #{sb_string(&1)})")
      |> Enum.join(" ")

    ancestors =
      permit_path
      |> ancestor_dirs()
      |> Enum.map(&"(literal #{sb_string(&1)})")
      |> Enum.join(" ")

    """
    (version 1)
    (allow default)
    (deny file-read* file-write*)
    (allow file-read* #{runtime})
    (allow file-read* #{ancestors})
    (allow file-read-metadata)
    (allow file-read* file-write* (subpath #{sb_string(permit_path)}))
    #{writable_devices()}
    #{executable_grant(command, permit_path)}
    #{extra_grants(extras)}
    """
  end

  # ⚠️ LAST in the profile, and that placement is load-bearing rather than
  # aesthetic: `sandbox-exec` lets later rules win, so a grant written above the
  # blanket `(deny file-read* file-write*)` is silently undone by it.
  #
  # MEASURED 2026-08-24 against the profile above with one such line appended
  # for `/private/tmp/claude-501`: `ls` of that directory went from `Operation
  # not permitted` to exit 0, `touch` inside it exit 0, and the control -- `ls
  # ~/.ssh` -- stayed `Operation not permitted`. The grant reaches what it names
  # and does not leak sideways.
  defp extra_grants([]), do: ""

  defp extra_grants(extras) do
    Enum.map_join(extras, "\n", fn path ->
      "(allow file-read* file-write* (subpath #{sb_string(path)}))"
    end)
  end

  # ⚠️ Only what exists, which is the one asymmetry between the platforms here:
  # `bwrap` refuses a bind whose source is missing and fails the whole launch,
  # while `sandbox-exec` happily permits a subpath that is not there. Filtering
  # keeps a caller's grant from turning into a refusal to launch on a host where
  # the directory has not been created yet.
  #
  # Paths under the runtime read set are dropped for the mount-over-its-own-mount
  # reason on `grantable_command?/2`; `extra_subpaths/2` has already dropped the
  # ones under `permit_path`.
  defp extra_binds(extras) do
    extras
    |> Enum.filter(&File.exists?/1)
    |> Enum.reject(&nested_in_other?(&1, runtime_read_paths()))
    |> Enum.flat_map(&["--bind", &1, &1])
  end

  # ⚠️ Two device nodes by name, NOT `file-write*` on `(subpath "/dev")`.
  #
  # MEASURED: under this profile `echo x > /dev/null` fails with `Operation not
  # permitted`. `/dev` is in `runtime_read_paths/0` and so is granted
  # `file-read*` only, while `file-write*` exists solely inside `permit_path`.
  # The comment on `runtime_read_paths/0` says `/dev` is there "because a
  # process denied `/dev/null` and `/dev/urandom` dies rather than being
  # confined" -- the read half was implemented and the write half was not.
  #
  # The narrow form is chosen because `/dev` is not a directory of harmless
  # sinks. It also holds `/dev/disk*` and `/dev/rdisk*`, which are raw block
  # devices for every mounted volume on the host: `file-write*` over the subpath
  # would hand a confined process the ability to write the operator's disks
  # directly, straight past every path rule above. That is a strictly larger
  # hole than the one this module exists to close, opened to fix a redirect.
  #
  # MEASURED after this change: `echo x > /dev/null` and
  # `head -c 4 /dev/urandom > /dev/null` both succeed.
  defp writable_devices do
    "(allow file-write* (literal \"/dev/null\") (literal \"/dev/urandom\"))"
  end

  # ⚠️ `(literal …)`, NEVER `(subpath …)` -- for a sharper reason than the
  # ancestors above. The resolved CLI lives at `…/versions/<v>`, so a subpath
  # grant on its parent re-permits **every retained old version** (self-update
  # never deletes them), and a subpath grant on `~/.local/bin` re-permits every
  # other tool the operator has installed.
  #
  # ## Why a grant at all, when exec already works
  #
  # ⚠️ MEASURED, and it refutes the obvious premise: on macOS a confined child
  # **already execs** a binary under a denied path with no grant of any kind.
  # `(deny file-read* file-write*)` does not govern `process-exec*`; `(allow
  # default)` does. So this is not what makes the launch possible.
  #
  # What it makes possible is the binary **reading its own file at runtime** --
  # an embedded payload, an update check. MEASURED on this profile: without the
  # grant a process reading its own executable gets `Operation not permitted`;
  # with it, the read succeeds, and a sibling in the same directory stays
  # denied. That matters because `028/spec.md:248-252` records this CLI's
  # failure signature for a denied path as **exit 0, zero bytes, no complaint**
  # -- a green run that produced nothing. One line makes the question moot.
  #
  # `process-exec` is granted alongside `file-read*` and `file-map-executable`
  # (the operation governing `mmap` with `PROT_EXEC`) even though `(allow
  # default)` already permits it here, so the grant stays correct if that
  # default is ever tightened. A grant that is only complete by accident is one
  # someone has to rediscover.
  defp executable_grant(command, permit_path) do
    if grantable_command?(command, permit_path) do
      "(allow process-exec file-read* file-map-executable (literal #{sb_string(command)}))"
    else
      ""
    end
  end

  # Nothing to grant for a command that is not an absolute path to an existing
  # file: a name still to be looked up cannot be named in a rule, and a
  # non-existent path would produce a grant that matches nothing while reading
  # as though it protected something.
  #
  # Already-covered paths are skipped too. On Linux that is load-bearing rather
  # than tidy: binding a path underneath an existing bind makes `bwrap` mount
  # over its own mount, which it rejects outright -- the same failure
  # `nested_in_other?/2` exists to avoid for the runtime set.
  defp grantable_command?(command, permit_path) do
    Path.type(command) == :absolute and File.regular?(command) and
      not nested_in_other?(command, runtime_read_paths() ++ [permit_path])
  end

  defp command_bind(command, permit_path) do
    if grantable_command?(command, permit_path),
      do: ["--ro-bind", command, command],
      else: []
  end

  # ⚠️ `(literal …)`, NEVER `(subpath …)`.
  #
  # A process cannot reach the permitted subtree without traversing the
  # directories above it: denying `/` and `/private` does not deny the read, it
  # kills the process with 134 before any read happens (R30, and MEASURED again
  # here -- the control caught it while both breach assertions still "passed").
  #
  # `(literal …)` permits the directory node itself and nothing inside it, which
  # is what keeps this from undoing the boundary: MEASURED that a sibling under
  # an ancestor is still `Operation not permitted`, both by absolute path and by
  # `..` from inside the permitted subtree. `(subpath …)` on an ancestor would
  # re-permit exactly the sibling directories this module exists to deny.
  #
  # ⚠️ It does leave ancestor directories **listable** — `ls` on the parent
  # names its entries. That is metadata, not content, and it is inherent to
  # reaching a nested path at all; the same is true of the `bwrap` bind, whose
  # parent mount points are visible. Names of sibling directories are not the
  # secret; their contents are, and those stay denied.
  defp ancestor_dirs(path) do
    path
    |> Path.expand()
    |> Path.split()
    |> Enum.scan(&Path.join(&2, &1))
    |> Enum.drop(-1)
  end

  # A path containing `"` or `\` would otherwise end the string literal and let
  # the rest be read as profile syntax -- a profile-injection hole in the one
  # place that decides the boundary.
  defp sb_string(path) do
    escaped = path |> String.replace("\\", "\\\\") |> String.replace("\"", "\\\"")
    "\"" <> escaped <> "\""
  end

  # The runtime's own read set. Generous on purpose (see the moduledoc): this is
  # what the process needs to *execute*, and it is not where the boundary lives.
  # `/dev` is included because a process denied `/dev/null` and `/dev/urandom`
  # dies rather than being confined. ⚠️ That grants READS only; the write half
  # lives in `writable_devices/0`, narrowly, and was missing until D14a measured
  # `echo x > /dev/null` failing.
  #
  # ⚠️ `/etc` is here for DNS, and its absence was this module's own unnamed bug.
  # MEASURED: without it, `getent hosts` and `curl` both fail **instantly**
  # (`getent` exit 2, `curl` exit 6 "Couldn't resolve host") because neither can
  # read `/etc/resolv.conf` or `/etc/nsswitch.conf` -- this profile denies `/etc`
  # like everything else not named here. The delegated CLI does not fail the
  # same way: lacking a working resolver, its bundled Node/c-ares stack falls
  # back through some slower internal path and MEASURED taking **~190-195s**
  # before either succeeding or printing the bare-text "Request timed out" that
  # `Reply.decode/1` then (correctly) reports as an unparseable plan. This is
  # what the moduledoc's own `pinned_config_args/1` docstring recorded as an
  # unexplained "FR-017 pre-first-byte stall" and ruled out confinement as a
  # cause for -- confinement WAS the cause, just not the flag that research
  # tested. With `/etc` granted, MEASURED: `getent`/`curl` resolve and connect
  # in double-digit milliseconds, same as unconfined.
  defp runtime_read_paths do
    [
      to_string(:code.root_dir()),
      "/usr",
      "/lib",
      "/lib64",
      "/bin",
      "/sbin",
      "/System",
      "/dev",
      "/etc"
    ]
    |> Enum.uniq()
    |> Enum.filter(&File.exists?/1)
    |> Enum.reject(&nested_in_other?(&1, ["/usr", "/lib", "/System"]))
  end

  # Binding a path already covered by a parent bind makes `bwrap` mount over its
  # own mount, which it rejects (`linux.ex:381-386`).
  defp nested_in_other?(path, parents) do
    Enum.any?(parents, fn parent ->
      path != parent and String.starts_with?(path, parent <> "/")
    end)
  end
end
