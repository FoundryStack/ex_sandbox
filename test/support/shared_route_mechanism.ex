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

  # ⚠️ Host-side and genuinely **unwritable**, and getting this right took a
  # measured failure. The first version wrote the policy to `/tmp` like the
  # other fixtures. But `context.exec` here runs in the host's own shell, so
  # tenant code appended to it and this mechanism failed `FR-011b` as well as
  # `003-FR-002` -- which made the peer-crossing failure unattributable and
  # tripped the meta-test's own attribution guard.
  #
  # That is the fixture equivalent of the defect species this suite keeps
  # finding: a control that looks correct until it is executed. The file is now
  # created read-only, so `>>` is refused for a real reason and the mechanism
  # fails exactly one guarantee.
  @policy_path "/tmp/ex-sandbox-shared-route-allowlist"

  # Owner-read-only. `File.write!` would reset the mode, so the write happens
  # first and the mode is applied after.
  @policy_mode 0o444

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
    # ⚠️ `File.chmod!` after the write, and `File.rm` before it: an existing
    # 0444 file cannot be overwritten, so a second sandbox on the bridge would
    # crash here rather than start.
    File.rm(@policy_path)
    File.write!(@policy_path, "127.0.0.1/32\n")
    File.chmod!(@policy_path, @policy_mode)

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
      |> Map.put(:policy_handle, @policy_path)
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

    # Restore write permission so the next run can replace it.
    File.chmod(@policy_path, 0o644)
    :ok
  end

  @impl true
  def status(_sandbox), do: {:ok, :running}

  @impl true
  def list_running, do: {:ok, []}

  @impl true
  def usage(_sandbox), do: {:ok, %{}}

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
    File.read!(@policy_path) |> String.contains?("#{host}/32") and on_bridge?(port)
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
