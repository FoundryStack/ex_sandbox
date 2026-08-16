defmodule ExSandbox.PorousMechanism do
  @moduledoc """
  A mechanism that runs commands **directly on the host** and isolates nothing
  (003 T045).

  Distinct from `ExSandbox.EchoMechanism`, which carries no runner at all and so
  cannot attempt a hostile act. This one attempts every act and succeeds at all
  of them, because "inside the sandbox" here means "in the host's own shell".

  That is the dangerous shape, and the reason this module exists. A mechanism
  with no runner fails the isolation group by being inconclusive, which is easy
  to notice. A mechanism that runs commands somewhere *real* but unconfined
  produces genuine, plausible output for every check — and if the isolation
  tests were written as "assert nothing leaked" rather than "attempt the breach
  and require refusal", it would sail through all of them.

  `ExSandbox.ConformanceMetaTest` points the isolation group at this module and
  requires that **every** check fails. If one passes, that check is asserting
  the absence of an observation rather than the refusal of an act, which is the
  failure mode `003` T044 and the Constitution's Isolation Review gate exist to
  prevent.
  """
  @behaviour ExSandbox.Mechanism

  @impl true
  def required_capabilities, do: []

  @impl true
  def provision(sandbox), do: {:ok, %{sandbox | mechanism_ref: "porous-" <> sandbox.id}}

  @impl true
  def start(sandbox) do
    # The whole point: `exec` runs on the host, unconfined. Every hostile act
    # the isolation group attempts therefore genuinely succeeds.
    {:ok, %{sandbox | context: Map.put(sandbox.context || %{}, :exec, &host_exec/1)}}
  end

  @impl true
  def stop(sandbox), do: {:ok, sandbox}

  @impl true
  def destroy(_sandbox), do: :ok

  @impl true
  def status(_sandbox), do: {:ok, :running}

  @impl true
  def list_running, do: {:ok, []}

  @impl true
  def usage(_sandbox), do: {:ok, %{}}

  defp host_exec(command) do
    {output, _status} = System.cmd("sh", ["-c", command], stderr_to_stdout: true)
    {:ok, output}
  rescue
    error -> {:error, error}
  end
end
