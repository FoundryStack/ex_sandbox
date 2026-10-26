defmodule ExSandbox.BudgetMechanism do
  @moduledoc """
  A mechanism whose sandboxes are rows in an ETS table and whose `call/5`
  applies in the gateway's VM, so a measurement of the gateway reads the
  gateway and its bookkeeping alone. `serve/1` runs a gateway over it in a
  peer VM.
  """
  @behaviour ExSandbox.Mechanism

  @doc "Starts a gateway over this mechanism and parks the calling process."
  def serve(opts) do
    :ets.new(__MODULE__, [:named_table, :public])
    {:ok, _gateway} = ExSandbox.Gateway.start_link([mechanism: __MODULE__] ++ opts)
    Process.sleep(:infinity)
  end

  @impl true
  def required_capabilities, do: []

  @impl true
  def provision(sandbox), do: {:ok, %{sandbox | mechanism_ref: "budget-" <> sandbox.id}}

  @impl true
  def start(sandbox) do
    :ets.insert(__MODULE__, {sandbox.id, sandbox})
    {:ok, sandbox}
  end

  @impl true
  def stop(sandbox) do
    :ets.delete(__MODULE__, sandbox.id)
    {:ok, sandbox}
  end

  @impl true
  def destroy(sandbox) do
    :ets.delete(__MODULE__, sandbox.id)
    :ok
  end

  @impl true
  def status(sandbox),
    do: {:ok, if(:ets.member(__MODULE__, sandbox.id), do: :running, else: :absent)}

  @impl true
  def list_running,
    do: {:ok, for({id, _sandbox} <- :ets.tab2list(__MODULE__), do: "budget-" <> id)}

  @impl true
  def usage(_sandbox), do: {:ok, %{}}

  @impl true
  def execute(_sandbox, _command, _opts \\ []), do: {:error, {:could_not_run, :not_supported}}

  @impl true
  def update_egress(sandbox, _allowed), do: {:ok, sandbox}

  def call(_sandbox, module, function, args, _timeout), do: {:ok, apply(module, function, args)}
end
