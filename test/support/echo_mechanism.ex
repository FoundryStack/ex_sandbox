defmodule ExSandbox.EchoMechanism do
  @moduledoc """
  A mechanism that does nothing but hand back what it was given (012 T018).

  Exists so the opacity test can watch an opaque value make a full
  provision→start→stop→destroy round trip through the library's own code paths.
  A mechanism that transformed its input would make the test measure the
  mechanism rather than the library.
  """
  @behaviour ExSandbox.Mechanism

  # Declared so `ExSandbox`'s capability gate does not refuse before the library
  # code under test runs. This mechanism isolates nothing and requires nothing.
  @impl true
  def required_capabilities, do: []

  @impl true
  def provision(sandbox), do: {:ok, %{sandbox | mechanism_ref: sandbox.mechanism_ref}}

  @impl true
  def start(sandbox), do: {:ok, sandbox}

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
end
