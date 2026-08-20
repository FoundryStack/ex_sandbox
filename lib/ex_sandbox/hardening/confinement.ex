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
          cd: String.t() | nil
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

  defp build(command, args, permit_path, opts) do
    env = Keyword.get(opts, :env, [])
    cd = Keyword.get(opts, :cd)

    # ⚠️ Resolved, not merely expanded. MEASURED: `System.tmp_dir!()` on macOS is
    # `/var/folders/…`, a symlink to `/private/var/folders/…`, and the kernel
    # evaluates the profile against the RESOLVED path. Permitting the unresolved
    # spelling denies the very path it was asked to permit -- the control failed
    # on exactly this, reporting `Operation not permitted` for P itself.
    permit_path = resolve(permit_path)

    with :ok <- ensure_permit_path(permit_path),
         {:ok, cmd, wrapped} <- wrap(:os.type(), command, args, permit_path) do
      {:ok, %{cmd: cmd, args: wrapped, env: env, cd: cd}}
    end
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

  defp wrap({:unix, :linux}, command, args, permit_path) do
    if System.find_executable("bwrap") do
      {:ok, "bwrap", bwrap_args(command, args, permit_path)}
    else
      {:error,
       {:cannot_enforce, :path_confinement,
        "bubblewrap (`bwrap`) is not on PATH; the path boundary cannot be built"}}
    end
  end

  defp wrap({:unix, :darwin}, command, args, permit_path) do
    case System.find_executable("sandbox-exec") do
      nil ->
        {:error,
         {:cannot_enforce, :path_confinement,
          "`sandbox-exec` is not on PATH; the path boundary cannot be built"}}

      sandbox_exec ->
        # `-p` takes the profile inline, so there is no temporary file to create,
        # secure, or leak. `release/1` has nothing to clean up as a result.
        {:ok, sandbox_exec, ["-p", sandbox_profile(permit_path), command | args]}
    end
  end

  defp wrap(other, _command, _args, _permit_path) do
    {:error,
     {:cannot_enforce, :path_confinement,
      "no path-confinement facility is known for #{inspect(other)}"}}
  end

  # ⚠️ `--ro-bind` the runtime, `--bind` exactly one data path. Note what is
  # ABSENT and deliberately so, against the tenant profile at `linux.ex:316-345`:
  # no `--unshare-net`, because this process must reach the model endpoint.
  defp bwrap_args(command, args, permit_path) do
    runtime_read_paths()
    |> Enum.flat_map(&["--ro-bind", &1, &1])
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
  defp sandbox_profile(permit_path) do
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
    """
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
  # dies rather than being confined.
  defp runtime_read_paths do
    [to_string(:code.root_dir()), "/usr", "/lib", "/lib64", "/bin", "/sbin", "/System", "/dev"]
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
