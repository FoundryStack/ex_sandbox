defmodule ExSandbox.BrokenMechanism do
  @moduledoc """
  A mechanism with a deliberate, specific lifecycle defect (012 T029).

  It errors on a second `destroy/1`, violating `003-FR-013`. Chosen over a
  more dramatic break because it is the realistic one: "already gone" is an
  error condition a mechanism author would naturally report, and the reason it
  must not be is a property of the *system* — crash-recovery sweeps run against
  sandboxes that may already have been cleaned up — that the author has no way
  to know from their own code.

  That makes it the right subject for `ExSandbox.ConformanceFailureNamingTest`:
  the failure message has to explain the guarantee, because the assertion alone
  would tell an author only that `:ok` was expected and `{:error, :not_found}`
  was returned, which reads like the suite being pedantic.
  """
  @behaviour ExSandbox.Mechanism

  @impl true
  def required_capabilities, do: []

  @impl true
  def provision(sandbox) do
    ref = "broken-" <> sandbox.id
    destroyed(:reset, ref)
    {:ok, %{sandbox | mechanism_ref: ref}}
  end

  @impl true
  def start(sandbox), do: {:ok, sandbox}

  @impl true
  def stop(sandbox), do: {:ok, sandbox}

  @impl true
  def destroy(sandbox) do
    if destroyed?(sandbox.mechanism_ref) do
      # The defect. Plausible, and wrong.
      {:error, :not_found}
    else
      destroyed(:mark, sandbox.mechanism_ref)
      :ok
    end
  end

  @impl true
  def status(_sandbox), do: {:ok, :running}

  @impl true
  def list_running, do: {:ok, []}

  @impl true
  def usage(_sandbox), do: {:ok, %{memory_mb: 1}}

  # This fixture isolates nothing and runs nothing. `:could_not_run` is the
  # honest answer and the one the suite must not score as a pass: an attempt
  # that never happened has demonstrated neither a limit holding nor a limit
  # failing.
  @impl true
  def execute(_sandbox, {_cmd, _args}, _opts \\ []) do
    {:error, {:could_not_run, :not_supported}}
  end

  defp destroyed?(ref), do: ref in Process.get(:broken_destroyed, [])

  defp destroyed(:reset, ref) do
    Process.put(:broken_destroyed, List.delete(Process.get(:broken_destroyed, []), ref))
  end

  defp destroyed(:mark, ref) do
    Process.put(:broken_destroyed, [ref | Process.get(:broken_destroyed, [])])
  end
end
