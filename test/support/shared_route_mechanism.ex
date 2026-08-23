defmodule ExSandbox.SharedRouteMechanism do
  @moduledoc """
  A mechanism with a real, unwritable allowlist and **one shared route between
  all sandboxes** (005 T060a7; `003-FR-002`).

  ## The mistake a shared bridge makes

  Put every sandbox on one bridge, hang an egress allowlist off it, and the
  result passes every check that looks *outward*. Denied destinations are
  refused. The permitted destination is reachable. The policy is enforced by
  the host and tenant code cannot touch it — `FR-011b` holds, honestly.

  What it does not do is separate the sandboxes from **each other**. They share
  a link, so sandbox A can open a socket to sandbox B's address, and no
  outward-facing check ever notices. `005-FR-011c` calls out "no shared bridge"
  for exactly this reason, and `003-FR-002` is the guarantee it protects.

  ## Why this fixture is needed even though the check already exists

  The peer-crossing check exists, but nothing proves it can *fail*. Against
  `PorousMechanism` it reports the third outcome (no `:address` declared), and
  against `OpenNetworkMechanism` it fails alongside every other check — so a
  green meta-test there says only "something failed", not "the peer crossing
  was detected". Both are consistent with a check that never actually attempts
  the crossing.

  This mechanism separates the two. It is conformant in every respect except
  peer isolation, so if the peer-crossing check does not fail here, it is not
  attempting a real crossing — it is trusting the topology, which is the
  weakness T060a8 requires the eventual implementation to be measured against.

  ⚠️ The crossing is real. `connect/2` reaches a socket this module actually
  listens on, so a suite that attempts the connection observes it succeed. A
  fixture that merely *claimed* peers were reachable would let a check pass by
  reading a declaration instead of crossing a boundary.
  """
  @behaviour ExSandbox.Mechanism

  # ⚠️ The enforced policy is **held in host memory**, and it took two measured
  # failures to get here. Both are worth keeping, because each one is the same
  # mistake at a different depth.
  #
  # **First:** the policy was a file in `/tmp` like the other fixtures. But
  # `context.exec` runs in the host's own shell, so tenant code appended to it,
  # and the mechanism failed `FR-011b` as well as `003-FR-002` -- making the
  # peer-crossing failure unattributable. The meta-test's attribution guard
  # caught it.
  #
  # **Second:** the fix was mode `0444`, which made `>>` fail on macOS as a
  # non-root user. It was verified there, in the one environment where it
  # works. The container runs the suite as **root**, and root ignores mode bits
  # entirely -- measured: appending to a `0444` file as uid 0 succeeds. The
  # guard fired again, on the platform that actually matters.
  #
  # So permission was never the right mechanism: any mode bit is a permission
  # question, and root always wins that argument. The policy now lives in
  # `:persistent_term`, where the sandbox's shell has no path to it at all --
  # not because it is forbidden, but because there is nothing on the filesystem
  # to open. That holds at any privilege level.
  @policy {__MODULE__, :policy}

  # ⚠️ `:policy_handle` must still be a **path** -- `FR-011e` has the suite
  # attack it, and a handle it cannot even attempt to write would make the
  # widening check vacuous rather than passing. This names a path that is
  # deliberately absent from the filesystem: writing to it is refused for a
  # reason unrelated to the policy, and the policy it *claims* to name cannot be
  # reached from inside at all.
  @policy_handle "/proc/ex-sandbox/shared-route-allowlist"

  # Every sandbox on this "bridge" registers its listener here, which is what
  # makes one sandbox reachable from another. `:persistent_term` rather than
  # ETS: an ETS table dies with the process that created it, and these outlive
  # any single test's process (measured -- see `BookkeepingMechanism`).
  @bridge {__MODULE__, :bridge}

  @impl true
  def required_capabilities, do: []

  @impl true
  def provision(sandbox), do: {:ok, %{sandbox | mechanism_ref: "shared-route-" <> sandbox.id}}

  @impl true
  def start(sandbox) do
    # Host-side, in memory. No file to chmod, no file to race, and nothing for a
    # second sandbox on the bridge to collide with.
    :persistent_term.put(@policy, ["127.0.0.1/32"])

    # A real listening socket, so a peer crossing can genuinely be attempted
    # and genuinely succeed.
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listener)

    join_bridge(port, listener)

    context =
      (sandbox.context || %{})
      |> Map.put(:exec, &host_exec/1)
      |> Map.put(:address, {"127.0.0.1", port})
      |> Map.put(:permitted, {"127.0.0.1", port})
      |> Map.put(:policy_handle, @policy_handle)
      |> Map.put(:connect, &shared_route_connect/2)

    {:ok, %{sandbox | context: context}}
  end

  @impl true
  def stop(sandbox), do: {:ok, sandbox}

  @impl true
  def destroy(sandbox) do
    case sandbox.context do
      %{address: {_host, port}} -> leave_bridge(port)
      _ -> :ok
    end

    :ok
  end

  @impl true
  def status(_sandbox), do: {:ok, :running}

  @impl true
  def list_running, do: {:ok, []}

  @impl true
  def usage(_sandbox), do: {:ok, %{}}

  # This fixture isolates nothing and runs nothing. `:could_not_run` is the
  # honest answer and the one the suite must not score as a pass: an attempt
  # that never happened has demonstrated neither a limit holding nor a limit
  # failing.
  @impl true
  def execute(_sandbox, {_cmd, _args}, _opts \\ []) do
    {:error, {:could_not_run, :not_supported}}
  end

  # ⚠️ The whole defect, in one clause: anything on the bridge is reachable.
  # Off-bridge destinations still obey the allowlist, so every outward-facing
  # check passes and only the peer crossing exposes the shared link.
  defp shared_route_connect(host, port) do
    cond do
      on_bridge?(port) -> :connected
      permitted?(host, port) -> :connected
      true -> :refused
    end
  end

  # The platform's own listener is NOT on the bridge and not in the allowlist,
  # so that check is refused honestly.
  defp permitted?(host, port) do
    allowed = :persistent_term.get(@policy, [])
    Enum.any?(allowed, &(&1 == "#{host}/32")) and on_bridge?(port)
  end

  defp on_bridge?(port), do: Map.has_key?(bridge(), port)

  defp bridge, do: :persistent_term.get(@bridge, %{})

  defp join_bridge(port, listener),
    do: :persistent_term.put(@bridge, Map.put(bridge(), port, listener))

  defp leave_bridge(port) do
    case Map.pop(bridge(), port) do
      {nil, _} ->
        :ok

      {listener, rest} ->
        :gen_tcp.close(listener)
        :persistent_term.put(@bridge, rest)
    end
  end

  defp host_exec(command) do
    {output, _status} = System.cmd("sh", ["-c", command], stderr_to_stdout: true)
    {:ok, output}
  rescue
    error -> {:error, error}
  end
end
