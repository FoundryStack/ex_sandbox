defmodule ExSandbox.SeparatedPeersMechanism do
  @moduledoc """
  A mechanism whose peers are **live and unreachable from each other**
  (029 T034a; `029-FR-017`).

  ## The fixture the peer rule could not otherwise pass on merit

  `ExSandbox.SharedRouteMechanism` proves the peer-handle check can *fail*: its
  sandboxes listen on a shared bridge and one genuinely reaches another. Nothing
  proved it can *pass* for a reason.

  The only mechanism the existing peer check passes against is
  `ExSandbox.EditablePolicyMechanism`, and it passes there because **nothing
  listens at the address it publishes** — its own comment says so. A refusal
  against a dead port is what a mechanism with no boundary at all produces, so
  that pass establishes nothing about `FR-017`; it is the `:refused`-scored-as-
  the-boundary-holding hazard, already in the suite rather than arriving with a
  dialable address.

  This module is that fixture with the one defect removed. Every sandbox listens
  on a real socket the **platform** can open a connection to — so the check's
  liveness control succeeds and the handle is genuinely exercised — and
  `connect/2` refuses every one of those sockets from inside another sandbox.
  The refusal is then attributable to the boundary and to nothing else.

  ⚠️ Conformant in every other respect, for the same attribution reason
  `EditablePolicyMechanism` is: a real allowlist the sandbox cannot reach,
  a permitted destination that connects, denied destinations refused. If a check
  other than the peer one moves here, the peer result is not attributable to
  peer separation.
  """
  @behaviour ExSandbox.Mechanism

  # Host-side and in memory, for the reason `SharedRouteMechanism` records at
  # length: a policy file is appendable by tenant code (`context.exec` runs in
  # the host's shell), and mode bits lose to root, which is what the container
  # runs as.
  @policy {__MODULE__, :policy}
  @policy_handle "/proc/ex-sandbox/separated-peers-allowlist"

  # The listeners of every sandbox this mechanism has started. Refusing exactly
  # these is what makes the fixture a peer-separation fixture rather than a
  # deny-everything one.
  @peers {__MODULE__, :peers}

  # Reachable by this fixture's own `connect/2`, so the permitted half of
  # `FR-011d` passes and the peer verdict stays attributable.
  @permitted {"127.0.0.1", 9}

  @impl true
  def required_capabilities, do: []

  @impl true
  def provision(sandbox), do: {:ok, %{sandbox | mechanism_ref: "separated-" <> sandbox.id}}

  @impl true
  def start(sandbox) do
    :persistent_term.put(@policy, [@permitted])

    # ⚠️ A **real** listener, and that is the whole point of this fixture. The
    # check gates on the platform reaching the handle; a fixture that declared
    # an address nothing answered on would report the third outcome and prove
    # nothing about a pass.
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listener)

    join(port, listener)

    context =
      (sandbox.context || %{})
      |> Map.put(:exec, &host_exec/1)
      |> Map.put(:address, {"127.0.0.1", port})
      |> Map.put(:permitted, @permitted)
      |> Map.put(:policy_handle, @policy_handle)
      |> Map.put(:connect, &separated_connect/2)

    {:ok, %{sandbox | context: context}}
  end

  @impl true
  def stop(sandbox), do: {:ok, sandbox}

  @impl true
  def destroy(sandbox) do
    case sandbox.context do
      %{address: {_host, port}} -> leave(port)
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

  @impl true
  def execute(_sandbox, {_cmd, _args}, _opts \\ []) do
    {:error, {:could_not_run, :not_supported}}
  end

  # ⚠️ The peer clause comes FIRST and is unconditional. A sandbox's own handle
  # is in this set too, so the fixture refuses a sandbox dialling itself as
  # well -- which is correct and also the conservative direction: it cannot
  # produce a pass by accidentally permitting the one crossing under test.
  defp separated_connect(host, port) do
    cond do
      peer_listener?(port) -> :refused
      {host, port} in :persistent_term.get(@policy, []) -> :connected
      true -> :refused
    end
  end

  defp peer_listener?(port), do: Map.has_key?(peers(), port)

  defp peers, do: :persistent_term.get(@peers, %{})

  defp join(port, listener), do: :persistent_term.put(@peers, Map.put(peers(), port, listener))

  defp leave(port) do
    case Map.pop(peers(), port) do
      {nil, _} ->
        :ok

      {listener, rest} ->
        :gen_tcp.close(listener)
        :persistent_term.put(@peers, rest)
    end
  end

  defp host_exec(command) do
    {output, _status} = System.cmd("sh", ["-c", command], stderr_to_stdout: true)
    {:ok, output}
  rescue
    error -> {:error, error}
  end
end
