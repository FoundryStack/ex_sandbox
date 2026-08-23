defmodule ExSandbox.OpenNetworkMechanism do
  @moduledoc """
  A mechanism that **declares** every network handle and confines nothing
  (005 T060b).

  ## Why this exists alongside `ExSandbox.PorousMechanism`

  `PorousMechanism` runs commands on the unconfined host but declares no
  `:address`, `:permitted`, or `:policy_handle`. The network group therefore
  reports the third outcome for the checks that need them — correctly, because
  a mechanism that never claimed to confine the network has not violated a
  guarantee it never made (`FR-011e`).

  That leaves a gap a meta-test written only against `PorousMechanism` cannot
  close: **a mechanism that declares the handles and then lets everything
  through**. It is the dangerous shape — it looks finished, it produces real
  answers for every check, and every "unavailable" excuse is gone. Against this
  module the group must report **failures**, not third outcomes.

  Without it, relaxing the meta-test to accept "unavailable" for a
  denial check would silently accept it from a mechanism that had declared its
  boundary and breached it.
  """
  @behaviour ExSandbox.Mechanism

  @impl true
  def required_capabilities, do: []

  @impl true
  def provision(sandbox), do: {:ok, %{sandbox | mechanism_ref: "open-net-" <> sandbox.id}}

  @impl true
  def start(sandbox) do
    path = policy_path(sandbox)

    context =
      (sandbox.context || %{})
      |> Map.put(:exec, &host_exec/1)
      # Declared, and every one of them a lie about a boundary that does not
      # exist. `connect` reports :connected unconditionally -- the mechanism
      # claims a policy and enforces none.
      |> Map.put(:address, {"127.0.0.1", 65_535})
      |> Map.put(:permitted, {"127.0.0.1", 65_535})
      |> Map.put(:policy_handle, path)
      |> Map.put(:connect, fn _host, _port -> :connected end)

    File.write!(path, "0.0.0.0/0\n")

    {:ok, %{sandbox | context: context}}
  end

  @impl true
  def stop(sandbox), do: {:ok, sandbox}

  @impl true
  def destroy(sandbox) do
    File.rm(policy_path(sandbox))
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

  # Per sandbox, because the file is real even though the boundary is not. A
  # fixed path is one file shared by every test that starts this mechanism, so
  # two of them at once -- in one suite run, or in two concurrent `mix test`
  # invocations -- truncate the policy the other's widening check is appending
  # to. `sandbox.id` is unique across VM runs
  # (`Conformance.Helpers.build_sandbox/1`), which a bare counter is not.
  #
  # `destroy/1` removes it for the same reason: one file per sandbox rather
  # than one file forever means somebody has to clean up.
  defp policy_path(sandbox), do: "/tmp/open-network-allowlist-#{sandbox.id}"

  defp host_exec(command) do
    {output, _status} = System.cmd("sh", ["-c", command], stderr_to_stdout: true)
    {:ok, output}
  rescue
    error -> {:error, error}
  end
end
