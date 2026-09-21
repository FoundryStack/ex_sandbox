defmodule ExSandbox.Mechanism.Beam.Table do
  @moduledoc """
  Owns the ETS table in which `ExSandbox.Mechanism.Beam` records launched
  nodes.

  ⚠️ An ETS table dies with the process that created it. The table used to be
  created lazily by whichever process first provisioned a sandbox -- a job, an
  HTTP request -- and when that process exited every row went with it, for
  every sandbox. OBSERVED 2026-09-21 on a host publishing a generated app:
  "sandbox is absent while its record reads running", repeatedly, for a
  sandbox that had just been provisioned. Started under `ExSandbox.Supervisor`,
  the table lives as long as the library does.
  """
  use GenServer

  @doc false
  def start_link(name), do: GenServer.start_link(__MODULE__, name, name: __MODULE__)

  @impl true
  def init(name) do
    case :ets.whereis(name) do
      :undefined -> :ets.new(name, [:named_table, :public, :set])
      _existing -> :ok
    end

    {:ok, name}
  end
end
