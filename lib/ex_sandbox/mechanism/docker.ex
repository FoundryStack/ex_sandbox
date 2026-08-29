defmodule ExSandbox.Mechanism.Docker do
  @moduledoc """
  A sandbox is one container, managed through the `docker` CLI.

  ## Why this exists beside `ExSandbox.Mechanism.Beam`

  `Beam` confines a process with the **host's** kernel -- cgroup v2, user and
  mount namespaces, `bwrap`. On macOS none of those exist, so
  `ExSandbox.Capability.check/1` reports every gating name unavailable and the
  gate refuses before `provision/1` is reached. That refusal is correct and it
  leaves a developer on a Mac with nowhere to run tenant code.

  This mechanism brings its own kernel. The Linux VM behind Docker Desktop has
  cgroup v2 (`docker info` reports `cgroup=2`, driver `cgroupfs`), so the caps
  are real limits inside the container regardless of what the host can do --
  which is why it declares `c:ExSandbox.Mechanism.constructed_capabilities/0`
  and the host probe is asked only about what is left over.

  ## What it does NOT claim, and the measurement behind that

  ⚠️ **No `:disk_quota`.** MEASURED 2026-08-28, Docker Desktop engine 27.4.0,
  `linux/arm64`, storage driver **overlayfs**:

      docker run --rm --storage-opt size=16M alpine \\
        sh -c 'dd if=/dev/zero of=/big bs=1M count=64; df -h /'
      → 67108864 bytes copied, exit=0
      → overlay  54.8G  30.4G  21.6G  59% /

  64 MB written into a nominal 16 MB quota, exit 0. `docker create
  --storage-opt size=1G` also returns success. The option is accepted and
  ignored -- the same shape as `005` R9b, where a cap was invoked and did not
  hold.

  So a sandbox under this mechanism **can fill the host filesystem**, and that
  is stated rather than hidden. Requiring `:disk_quota` instead would refuse on
  every overlayfs host, which is every Docker Desktop for Mac -- the host this
  mechanism exists to serve -- and a mechanism that refuses everywhere is not a
  safer mechanism, it is no mechanism.

  ## A sandbox that names a port trades the deny-all posture for reachability

  A sandbox with `service_port: nil` joins **no** network: `--network none`,
  which is what every sandbox this mechanism created before the field existed
  got, and still gets.

  A sandbox that names a `service_port` joins the default bridge and has that
  port published to the host's loopback interface. What this gives up, stated
  rather than implied: the container has **outbound** access, so the
  deny-by-default posture does not hold for it -- code inside can install
  dependencies at runtime and can reach the internet. `ExSandbox.Egress`'s
  allowlist does not apply here; narrowing outbound traffic to an allowlist over
  this bridge is a separate change with its own evidence.

  What still constrains it, and is unchanged: the filesystem the container sees
  is the image plus the one bind-mounted workspace, its process tree is its own,
  and the memory and CPU caps are still applied at create time. Inbound is
  narrower than the deny-all posture suggests, not wider: exactly one port,
  bound to `127.0.0.1`, so the application answers the platform on the same host
  and answers no other machine at all.

  ## The image comes from `template_ref`

  `t:ExSandbox.Sandbox.t/0` names `owner_ref`, `mechanism_ref` and `context` as
  opaque, and `template_ref` deliberately not: it is the one field a mechanism
  is meant to interpret as "what to create this from". Here it is a container
  image reference. A sandbox that names no template gets `alpine:3`, which
  is a floor for a workspace mount, not a recommendation.
  """

  @behaviour ExSandbox.Mechanism

  alias ExSandbox.Sandbox

  # Written at create time and read back by `list_running/0`, so this mechanism
  # never claims a container somebody else started -- the reconciliation sweep
  # `003-FR-015` describes would otherwise adopt, and later destroy, whatever
  # else happens to be running on the developer's machine.
  @mechanism_label "ex_sandbox.mechanism=docker"
  @id_label "ex_sandbox.sandbox_id"

  @default_image "alpine:3"

  # PID 1 has to outlive `provision/1` or there is nothing to `docker exec`
  # into. `tail -f /dev/null` rather than `sleep infinity`: busybox `sleep`
  # rejects a non-numeric argument on older Alpine, and the failure mode is a
  # container that exits immediately and reports `:stopped` for no visible
  # reason.
  @keepalive ["tail", "-f", "/dev/null"]

  # Where a sandbox's workspace appears inside the container. Fixed rather than
  # derived from the host path: the host path contains a tenant id, and putting
  # it inside the container would tell tenant code the shape of this
  # deployment's storage layout for no benefit to it.
  @workspace_mountpoint "/workspace"

  # This library's guard against waiting forever, used only when the caller
  # declared no ceiling of its own. See `timeouts/1` for why the two are not the
  # same limit.
  @default_exec_timeout_ms 15_000

  # How often the capture files are read while a command is running. Only
  # consulted when a caller passed `:on_output`; nothing polls for a sink that
  # does not exist.
  @poll_interval_ms 25

  @read_chunk_bytes 64 * 1024

  # A build log is worth keeping and a runaway `yes` is not. Truncation is
  # reported rather than silent (`truncated?`), because a silently cut log is
  # how a real error disappears from a diagnosis.
  @capture_limit_bytes 1024 * 1024

  @doc false
  def default_image, do: @default_image

  @doc "Where `workspace_path` is mounted inside the container."
  @spec workspace_mountpoint() :: String.t()
  def workspace_mountpoint, do: @workspace_mountpoint

  @doc """
  Whether a container runtime answered on this host, right now.

  ⚠️ Asked of the **daemon**, not of the executable. Docker Desktop leaves its
  client on `PATH` with the VM stopped, so finding the binary answers a question
  nobody asked -- the same shape as `Capability.check(:filesystem_confinement)`
  finding `sandbox-exec` on macOS and reporting a confinement the launch does
  not build.

  ⚠️ Deliberately **not** cached. A host acquires a container runtime by the
  operator starting one, and the caller for this is a refusal message telling
  them to do exactly that; an answer cached at boot would keep saying "install a
  runtime" to somebody who just did.
  """
  @spec runtime_available?() :: boolean()
  def runtime_available? do
    match?({:ok, _output}, docker(["version", "--format", "{{.Server.Version}}"]))
  end

  @impl true
  def required_capabilities do
    # What the launch needs in order to mean what it says. Every name here is
    # also in `constructed_capabilities/0`, so the gate asks the host for
    # nothing -- which is the point: on macOS the host answers `unavailable` to
    # all five gating names, and a mechanism that brings its own kernel must not
    # be refused for lacking a kernel facility it does not use.
    #
    # ⚠️ Two names that `Mechanism.Beam` requires are deliberately absent, and
    # each absence is a stated reduction rather than an oversight:
    #
    #   * `:disk_quota` -- MEASURED not enforced on this host (see the moduledoc).
    #   * `:privilege_separation` -- the container's process is root in the
    #     container, and under rootful Docker that root maps to host root. The
    #     name means "a dropped uid composed with a mount namespace and a
    #     default-deny filesystem" (`ExSandbox.Capability`); a default container
    #     supplies the middle term only. Claiming it would present this
    #     mechanism as equivalent to `bwrap` plus `setpriv`.
    [:resource_limits, :filesystem_confinement, :network_restriction]
  end

  @impl true
  def constructed_capabilities do
    # ⚠️ Nothing in the behaviour verifies this list. What backs it is
    # `ExSandbox.Mechanism.DockerConfinementTest` and
    # `ExSandbox.Mechanism.DockerExecuteTest`, which breach each of these three
    # and watch the breach stopped -- a memory allocation killed by the cgroup,
    # a busy loop throttled by `--cpus`, a literal IP unreachable with no
    # interface to reach it from, and the host's own tree absent inside the
    # container.
    #
    # Adding a name here without adding its breach converts an observation back
    # into an assertion. `005` R9b and D4 both measured what that costs: a cap
    # invoked, accepted, and silently not applied.
    [:resource_limits, :filesystem_confinement, :network_restriction]
  end

  @impl true
  def provision(%Sandbox{} = sandbox) do
    with :ok <- check_workspace(sandbox.workspace_path) do
      create(sandbox)
    end
  end

  # ⚠️ Refused rather than created. `docker create` happily creates a missing
  # bind source **as root**, and the host process that is supposed to share
  # those files then cannot write to them -- a failure that surfaces later, in
  # another process, as a permission error naming nothing. Whoever owns the
  # directory owns creating it; this mechanism only mounts what is already
  # there.
  defp check_workspace(nil), do: :ok

  defp check_workspace(path) when is_binary(path) do
    cond do
      Path.type(path) != :absolute -> {:error, {:workspace_not_absolute, path}}
      not File.dir?(path) -> {:error, {:workspace_not_a_directory, path}}
      true -> :ok
    end
  end

  defp check_workspace(other), do: {:error, {:workspace_not_absolute, other}}

  defp create(%Sandbox{} = sandbox) do
    case docker(["create" | create_args(sandbox)]) do
      {:ok, output} ->
        case container_id(output) do
          {:ok, id} -> {:ok, %{sandbox | mechanism_ref: id}}
          :error -> {:error, {:unexpected_output, output}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def start(%Sandbox{mechanism_ref: nil}), do: {:error, :not_provisioned}

  def start(%Sandbox{mechanism_ref: ref} = sandbox) do
    with {:ok, _output} <- docker(["start", ref]), do: {:ok, sandbox}
  end

  @impl true
  def stop(%Sandbox{mechanism_ref: nil}), do: {:error, :not_provisioned}

  def stop(%Sandbox{mechanism_ref: ref} = sandbox) do
    with {:ok, _output} <- docker(["stop", ref]), do: {:ok, sandbox}
  end

  @impl true
  def destroy(%Sandbox{mechanism_ref: nil}), do: :ok

  def destroy(%Sandbox{mechanism_ref: ref}) do
    case docker(["rm", "--force", ref]) do
      {:ok, _output} ->
        :ok

      # ⚠️ Idempotence is a requirement, not a courtesy (`003-FR-013`). A
      # crash-recovery sweep destroys whatever it finds in the record, and half
      # of that is already gone; an error here turns every sweep into spurious
      # failures and trains an operator to ignore them.
      {:error, {:docker_error, _status, message}} ->
        if absent?(message), do: :ok, else: {:error, {:docker_error, message}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def status(%Sandbox{mechanism_ref: nil}), do: {:ok, :absent}

  def status(%Sandbox{mechanism_ref: ref}) do
    case docker(["inspect", "--format", "{{.State.Status}}", ref]) do
      {:ok, output} ->
        {:ok, output |> String.trim() |> map_state()}

      {:error, {:docker_error, _status, message}} ->
        # ⚠️ The distinction this clause exists for. "No such container" is
        # `:absent` -- it is definitely not there. A daemon that did not answer
        # is `:unknown` -- we could not determine. `003-FR-024` keeps them
        # apart because a caller that reads "unobservable" as "gone" destroys
        # the record of a container that is still running and still billing.
        cond do
          absent?(message) -> {:ok, :absent}
          unreachable?(message) -> {:ok, :unknown}
          true -> {:error, {:docker_error, message}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def address(%Sandbox{mechanism_ref: nil}), do: {:ok, nil}

  def address(%Sandbox{service_port: nil}), do: {:ok, nil}

  def address(%Sandbox{mechanism_ref: ref, service_port: port}) do
    # ⚠️ Asked of the daemon rather than remembered from `create`.
    #
    # The host port is the daemon's to choose, and a container that was
    # recreated -- by a reconciliation sweep, or by a person -- has a different
    # one. A cached answer would keep pointing at a port that now belongs to
    # something else, and the caller would render a frame of somebody else's
    # application rather than a broken one.
    case docker(["port", ref, "#{port}/tcp"]) do
      {:ok, output} ->
        {:ok, first_binding(output)}

      {:error, {:docker_error, _status, message}} ->
        # A container that is not running has no published binding, and that is
        # an ordinary state rather than a failure -- see the callback docs.
        #
        # ⚠️ `No public port` is the message a **created but not started**
        # container gives, and a stopped one gives it too: the daemon realises
        # the binding at start and drops it at stop, so the port a create was
        # asked for is not a port anything answers on. MEASURED against Docker
        # 27.4: `docker port <id> 8080/tcp` exits 1 with that message in both
        # states. Treating it as an error would make a stopped sandbox raise
        # where a running one returns, for a difference the caller cannot act
        # on.
        if absent?(message) or unreachable?(message) or message =~ "is not running" or
             message =~ "No public port" do
          {:ok, nil}
        else
          {:error, {:docker_error, message}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def list_running do
    args = [
      "ps",
      "--filter",
      "label=#{@mechanism_label}",
      "--filter",
      "status=running",
      "--format",
      "{{.ID}}"
    ]

    case docker(args) do
      {:ok, output} -> {:ok, output |> String.split("\n", trim: true) |> Enum.map(&String.trim/1)}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def usage(%Sandbox{mechanism_ref: nil}), do: {:error, :not_provisioned}

  def usage(%Sandbox{mechanism_ref: ref}) do
    args = ["stats", "--no-stream", "--format", "{{.CPUPerc}};{{.MemUsage}}", ref]

    case docker(args) do
      {:ok, output} -> {:ok, parse_usage(output)}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def execute(sandbox, command, opts \\ [])

  def execute(%Sandbox{mechanism_ref: nil}, _command, _opts) do
    {:error, {:could_not_run, :not_provisioned}}
  end

  def execute(%Sandbox{} = sandbox, {cmd, args}, opts)
      when is_binary(cmd) and is_list(args) and is_list(opts) do
    {declared_timeout, timeout} = timeouts(opts)
    capture_dir = capture_dir()

    try do
      stdout_path = Path.join(capture_dir, "stdout")
      stderr_path = Path.join(capture_dir, "stderr")

      port =
        Port.open({:spawn_executable, shell()}, [
          :binary,
          :exit_status,
          :hide,
          args: ["-c", exec_script(sandbox, cmd, args, stdout_path, stderr_path)]
        ])

      port
      |> await(stdout_path, stderr_path, opts[:on_output], timeout)
      |> interpret(sandbox, declared_timeout, timeout, stdout_path, stderr_path, opts)
    after
      File.rm_rf(capture_dir)
    end
  end

  # ⚠️ Redirection into two files, rather than one merged stream or a port's
  # `:stderr_to_stdout`. `stdout` and `stderr` are separate in
  # `t:ExSandbox.Mechanism.completion/0` because a merged stream cannot
  # attribute a failure, and a port gives no second channel -- without the
  # redirect the container's stderr is inherited by the emulator and lost to the
  # console.
  #
  # `exec` so the shell is replaced rather than left waiting: otherwise the port
  # holds a shell whose child is the thing we actually want the exit status of.
  defp exec_script(%Sandbox{mechanism_ref: ref}, cmd, args, stdout_path, stderr_path) do
    words = ["docker", "exec", ref, cmd | args]

    "exec " <>
      Enum.map_join(words, " ", &shell_quote/1) <>
      " >" <> shell_quote(stdout_path) <> " 2>" <> shell_quote(stderr_path)
  end

  # Single quotes stop the shell interpreting anything at all, and the one
  # character they cannot contain is closed, escaped, and reopened. A command
  # arriving here is tenant input; the alternative -- trusting it not to contain
  # a metacharacter -- is a shell injection with the sandbox's own privileges.
  defp shell_quote(word) do
    "'" <> String.replace(word, "'", "'\\''") <> "'"
  end

  defp shell do
    System.find_executable("sh") || "/bin/sh"
  end

  defp capture_dir do
    dir =
      Path.join(
        System.tmp_dir!(),
        "ex_sandbox-exec-#{System.unique_integer([:positive, :monotonic])}"
      )

    File.mkdir_p!(dir)
    dir
  end

  # `{declared, effective}`. A caller's own ceiling is a statement about the
  # tenant's work and tripping it is a limit being enforced; this library's
  # default ceiling is only its guard against waiting forever, and tripping that
  # says nothing about the tenant -- so the two produce different returns and
  # have to stay distinguishable here. `Mechanism.Beam` draws the same line.
  defp timeouts(opts) do
    case Keyword.get(opts, :timeout) do
      nil -> {nil, @default_exec_timeout_ms}
      declared -> {declared, declared}
    end
  end

  defp await(port, stdout_path, stderr_path, on_output, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    await_loop(port, %{stdout: {stdout_path, 0}, stderr: {stderr_path, 0}}, on_output, deadline)
  end

  defp await_loop(port, cursors, on_output, deadline) do
    cursors = if on_output, do: drain(cursors, on_output), else: cursors
    remaining = deadline - System.monotonic_time(:millisecond)

    cond do
      remaining <= 0 ->
        close(port)
        :timeout

      true ->
        # ⚠️ The wait is bounded by the poll interval only when somebody is
        # listening. With no `:on_output` there is nothing to poll for, so the
        # call blocks on the port for the whole remaining budget rather than
        # waking up to read files nobody reads.
        wait = if on_output, do: min(@poll_interval_ms, remaining), else: remaining

        receive do
          {^port, {:exit_status, status}} ->
            if on_output, do: drain(cursors, on_output)
            {:exited, status}
        after
          wait ->
            await_loop(port, cursors, on_output, deadline)
        end
    end
  end

  # ⚠️ Byte offsets, not lines. `015` R17 measured a line buffer corrupting
  # output past 256 bytes, and `t:ExSandbox.Mechanism.output_chunk/0` is
  # explicit that a chunk is a chunk: a caller wanting lines assembles them,
  # where a long line arrives late rather than mangled.
  defp drain(cursors, on_output) do
    Map.new(cursors, fn {stream, {path, offset}} ->
      case read_from(path, offset) do
        "" ->
          {stream, {path, offset}}

        chunk ->
          on_output.({stream, chunk})
          {stream, {path, offset + byte_size(chunk)}}
      end
    end)
  end

  defp read_from(path, offset) do
    case File.open(path, [:read, :binary]) do
      {:ok, file} ->
        try do
          case :file.pread(file, offset, @read_chunk_bytes) do
            {:ok, data} -> data
            :eof -> ""
            {:error, _reason} -> ""
          end
        after
          File.close(file)
        end

      {:error, _reason} ->
        ""
    end
  end

  defp close(port) do
    Port.close(port)
  rescue
    ArgumentError -> :ok
  end

  defp interpret(:timeout, _sandbox, declared, timeout, _stdout, _stderr, _opts) do
    if declared do
      {:error, {:limit_exceeded, :wall_clock}}
    else
      {:error, {:could_not_run, {:timeout, timeout}}}
    end
  end

  defp interpret({:exited, status}, sandbox, _declared, _timeout, stdout_path, stderr_path, opts) do
    limit = Keyword.get(opts, :limit_bytes, @capture_limit_bytes)
    {stdout, stdout_cut?} = capture(stdout_path, limit)
    {stderr, stderr_cut?} = capture(stderr_path, limit)

    completion = %{
      exit_status: status,
      stdout: stdout,
      stderr: stderr,
      truncated?: stdout_cut? or stderr_cut?
    }

    cond do
      # ⚠️ The client's own failure, not the command's. `008-FR-016` rests on an
      # unperformed check being distinguishable from a failed one, so a sandbox
      # that was gone must never arrive as an exit status.
      #
      # Classified by the daemon's wording because the exit status cannot do it:
      # `docker exec` exits 1 both for "No such container" and for a command
      # that itself exited 1.
      client_error?(stderr) ->
        {:error, {:could_not_run, String.trim(stderr)}}

      oom_killed?(sandbox, status) ->
        {:error, {:limit_exceeded, :memory}}

      true ->
        {:ok, completion}
    end
  end

  defp capture(path, limit) do
    case File.read(path) do
      {:ok, data} when byte_size(data) > limit -> {binary_part(data, 0, limit), true}
      {:ok, data} -> {data, false}
      {:error, _reason} -> {"", false}
    end
  end

  # `docker port` prints one binding per line, and a stopped container prints
  # nothing at all -- so an empty output is `nil` rather than an error.
  #
  # Only the first line is taken. A container published on both IPv4 and IPv6
  # prints two, and the two are the same application: a caller needs one address
  # to fetch, not a set to choose between.
  defp first_binding(output) do
    output
    |> String.split("\n", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> List.first()
  end

  defp client_error?(stderr) do
    absent?(stderr) or unreachable?(stderr) or stderr =~ "is not running" or
      stderr =~ "is paused and must be unpaused"
  end

  # ⚠️ Asked of the kernel, not inferred from the number. 137 is 128 + SIGKILL
  # and SIGKILL has many senders; reporting `:limit_exceeded` on the status
  # alone would attribute an operator's `kill -9` to a memory cap. `memory.events`
  # is the cgroup's own counter, so a positive `oom_kill` is the kernel saying
  # it did this.
  defp oom_killed?(%Sandbox{memory_limit_mb: nil}, _status), do: false

  defp oom_killed?(%Sandbox{mechanism_ref: ref}, 137) do
    case docker(["exec", ref, "cat", "/sys/fs/cgroup/memory.events"]) do
      {:ok, output} ->
        Regex.match?(~r/^oom_kill\s+[1-9]/m, output)

      {:error, _reason} ->
        false
    end
  end

  defp oom_killed?(_sandbox, _status), do: false

  ## Command construction

  # Public, and `@doc false`, so the arguments can be asserted on a host with no
  # Docker daemon. The network posture is decided here and observable nowhere
  # else until a container is already running -- which is too late to be a test
  # that runs everywhere.
  @doc false
  def create_args(%Sandbox{} = sandbox) do
    [
      "--label",
      @mechanism_label,
      "--label",
      "#{@id_label}=#{sandbox.id}"
    ] ++
      limit_args(sandbox) ++
      network_args(sandbox) ++
      workspace_args(sandbox.workspace_path) ++
      [image(sandbox) | @keepalive]
  end

  # ⚠️ `:disk_quota_mb` is deliberately not translated. See the moduledoc: on
  # this host `--storage-opt size` is accepted and ignored, and passing a flag
  # that does nothing is how a cap becomes a claim nobody checked.
  defp limit_args(%Sandbox{} = sandbox) do
    memory_args(sandbox.memory_limit_mb) ++ cpu_args(sandbox.cpu_limit)
  end

  defp memory_args(nil), do: []
  defp memory_args(mb) when is_integer(mb) and mb > 0, do: ["--memory", "#{mb}m"]
  defp memory_args(_other), do: []

  # `cpu_limit` is millicores (`003-FR-004`); `--cpus` is fractional cores.
  defp cpu_args(nil), do: []

  defp cpu_args(millicores) when is_integer(millicores) and millicores > 0 do
    ["--cpus", :erlang.float_to_binary(millicores / 1000, decimals: 3)]
  end

  defp cpu_args(_other), do: []

  # Deny-all, and in the strong sense: the container joins no network, so there
  # is no interface to leak through and none of the egress machinery applies. An
  # allowlist over an internal bridge is the follow-up change -- starting there
  # would put a partial allowlist in the tree, which is the failure mode
  # `ExSandbox.Egress` exists to prevent.
  #
  # A sandbox that names a `service_port` is asking to be reachable, and gets
  # the second posture instead. See the moduledoc for what that gives up.
  defp network_args(%Sandbox{service_port: nil}), do: ["--network", "none"]

  defp network_args(%Sandbox{service_port: port}) when is_integer(port) and port > 0 do
    # ⚠️ `127.0.0.1::<port>` -- and the host address is the load-bearing half.
    #
    # `-p <port>` and `-p 0.0.0.0::<port>` both work, both make the preview
    # answer, and both publish the tenant's application on every interface the
    # host has. The difference is invisible from the browser that reads it and
    # total from the network the host sits on, which is exactly the shape of
    # defect that ships: nothing about the working case distinguishes them.
    #
    # The **host** port is left empty so the daemon allocates a free one. A port
    # this library chose would have to be checked for availability first, and
    # the gap between that check and the bind is a race two concurrent
    # provisions lose to each other. `address/1` reads back what was allocated.
    ["--network", "bridge", "-p", "127.0.0.1::#{port}"]
  end

  defp network_args(%Sandbox{}), do: ["--network", "none"]

  # ⚠️ A bind mount, so host and container see ONE filesystem rather than two
  # copies. A copy-in/copy-out would be the safer-looking choice and it is the
  # wrong one here: the point of the workspace is that an agent's edit is
  # visible to the thing that builds it, and a copy makes that true only at
  # whatever moments somebody remembered to synchronise.
  #
  # `--workdir` as well as the mount: a command that runs `docker exec` without
  # one lands in the image's own working directory, which for most base images
  # is `/`, and every relative path a tenant writes then misses the workspace
  # entirely.
  defp workspace_args(nil), do: []

  defp workspace_args(path) when is_binary(path) do
    [
      "--mount",
      "type=bind,source=#{path},target=#{@workspace_mountpoint}",
      "--workdir",
      @workspace_mountpoint
    ]
  end

  defp image(%Sandbox{template_ref: ref}) when is_binary(ref) and ref != "", do: ref
  defp image(_sandbox), do: @default_image

  ## Output parsing

  # ⚠️ The LAST id-shaped line, not the first and not the whole output. `docker
  # create` pulls a missing image and writes that progress to stderr, which is
  # merged here; taking the whole trimmed output as an id would hand a
  # `mechanism_ref` containing pull chatter to every later call.
  defp container_id(output) do
    output
    |> String.split("\n", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.filter(&Regex.match?(~r/^[0-9a-f]{12,64}$/, &1))
    |> List.last()
    |> case do
      nil -> :error
      id -> {:ok, id}
    end
  end

  defp map_state("created"), do: :provisioned
  defp map_state("running"), do: :running
  defp map_state("restarting"), do: :starting
  defp map_state("removing"), do: :stopping
  defp map_state("exited"), do: :stopped
  defp map_state("paused"), do: :stopped
  defp map_state("dead"), do: :stopped
  # A state this mechanism has not been taught. `:unknown` rather than a guess:
  # inventing `:stopped` for an unrecognised word is how a running container
  # gets reported reclaimable.
  defp map_state(_other), do: :unknown

  # ⚠️ No `:disk_mb`. Reporting a disk figure beside a quota that is not
  # enforced invites a caller to act on it as though something would stop the
  # growth it measures.
  defp parse_usage(output) do
    case output |> String.trim() |> String.split(";", parts: 2) do
      [cpu, memory] ->
        %{}
        |> put_if(:cpu_millicores, parse_cpu_percent(cpu))
        |> put_if(:memory_mb, parse_memory(memory))

      _other ->
        %{}
    end
  end

  defp put_if(map, _key, nil), do: map
  defp put_if(map, key, value), do: Map.put(map, key, value)

  # `docker stats` reports CPU as a percentage of one core, so 250% is 2500
  # millicores -- the same unit `cpu_limit` is expressed in.
  defp parse_cpu_percent(field) do
    case Float.parse(String.trim_trailing(String.trim(field), "%")) do
      {percent, _rest} -> round(percent * 10)
      :error -> nil
    end
  end

  # "12.34MiB / 64MiB" -- the first half is what this sandbox is using.
  defp parse_memory(field) do
    field
    |> String.split("/", parts: 2)
    |> List.first()
    |> to_mb()
  end

  defp to_mb(nil), do: nil

  defp to_mb(value) do
    value = String.trim(value)

    case Float.parse(value) do
      {number, unit} -> round(number * unit_multiplier(String.trim(unit)))
      :error -> nil
    end
  end

  defp unit_multiplier("GiB"), do: 1024
  defp unit_multiplier("GB"), do: 1000
  defp unit_multiplier("MiB"), do: 1
  defp unit_multiplier("MB"), do: 1
  defp unit_multiplier("KiB"), do: 1 / 1024
  defp unit_multiplier("kB"), do: 1 / 1000
  defp unit_multiplier("B"), do: 1 / (1024 * 1024)
  defp unit_multiplier(_other), do: 1

  ## Error classification

  # Matched on the daemon's own wording, which is the only signal the CLI gives:
  # both cases exit 1, so the exit status cannot tell them apart.
  defp absent?(message) do
    message =~ "No such container" or message =~ "No such object" or
      message =~ "is already in progress"
  end

  defp unreachable?(message) do
    message =~ "Cannot connect to the Docker daemon" or
      message =~ "error during connect" or message =~ "docker daemon is not running"
  end

  ## The CLI

  defp docker(args) do
    case System.cmd("docker", args, stderr_to_stdout: true) do
      {output, 0} -> {:ok, output}
      {output, status} -> {:error, {:docker_error, status, output}}
    end
  rescue
    # The executable vanished, or was never there. A raise would reach the
    # caller as a crash rather than as the refusal every other failure here
    # returns.
    error -> {:error, {:docker_unavailable, Exception.message(error)}}
  end
end
