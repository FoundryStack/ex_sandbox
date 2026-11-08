defmodule ExSandbox.Mechanism.Beam.ListRunningTest do
  use ExUnit.Case, async: false

  alias ExSandbox.Mechanism.Beam

  setup do
    table = Beam.registry_table()
    if :ets.whereis(table) == :undefined, do: :ets.new(table, [:named_table, :public, :set])
    ids = ["list-running-live", "list-running-stopped", "list-running-unlisted"]
    on_exit(fn -> Enum.each(ids, &:ets.delete(table, &1)) end)
    %{table: table}
  end

  test "lists a launched sandbox that carries no :stopped key, and skips stopped and unlisted ones",
       %{table: table} do
    :ets.insert(table, {"list-running-live", %{listed: true}})
    :ets.insert(table, {"list-running-stopped", %{listed: true, stopped: true}})
    :ets.insert(table, {"list-running-unlisted", %{listed: false}})

    assert {:ok, ids} = Beam.list_running()
    assert "list-running-live" in ids
    refute "list-running-stopped" in ids
    refute "list-running-unlisted" in ids
  end
end
