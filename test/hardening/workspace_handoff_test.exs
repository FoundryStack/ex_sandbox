defmodule ExSandbox.Hardening.WorkspaceHandoffTest do
  @moduledoc """
  `sandbox/FR-343`: a gateway whose workspace is handed off on another host
  skips its own hand-off, and a refused hand-off is an error in the log
  where the process maps the sandbox's uid.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Hardening.Linux
  alias ExSandbox.Mechanism.Beam.NodeLauncher

  defmodule Recording do
    @moduledoc false
    def prepare_workspace(%{id: id}) do
      send(self(), {:prepared, id})
      :ok
    end
  end

  setup do
    beam = Application.get_env(:ex_sandbox, :beam, [])
    hardening = Application.get_env(:ex_sandbox, :hardening_module)
    Application.put_env(:ex_sandbox, :hardening_module, Recording)

    on_exit(fn ->
      Application.put_env(:ex_sandbox, :beam, beam)

      if hardening,
        do: Application.put_env(:ex_sandbox, :hardening_module, hardening),
        else: Application.delete_env(:ex_sandbox, :hardening_module)
    end)

    %{beam: beam}
  end

  defp sandbox, do: %ExSandbox.Sandbox{id: "h-1", owner_ref: "o", template_ref: "t"}

  test "the gateway hands off its own workspace by default", %{beam: beam} do
    Application.put_env(:ex_sandbox, :beam, Keyword.delete(beam, :workspace_handoff))
    assert :ok = NodeLauncher.prepare_workspace(sandbox())
    assert_received {:prepared, "h-1"}
  end

  test "workspace_handoff: :elsewhere skips it, and hand_off_workspace still runs it", %{
    beam: beam
  } do
    Application.put_env(:ex_sandbox, :beam, Keyword.put(beam, :workspace_handoff, :elsewhere))
    assert :ok = NodeLauncher.prepare_workspace(sandbox())
    refute_received {:prepared, _}

    assert :ok = NodeLauncher.hand_off_workspace(sandbox())
    assert_received {:prepared, "h-1"}
  end

  @status_root "Name:\tbeam.smp\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"
  @status_user "Name:\tbeam.smp\nUid:\t501\t501\t501\t501\n"
  @gateway_map "         0        110          1\n         1     200000      65536\n"

  test "a refusal is expected to succeed only as root of a namespace mapping the uid" do
    assert Linux.hand_off_expected?(@gateway_map, @status_root, 36_876)
    refute Linux.hand_off_expected?(@gateway_map, @status_root, 70_000)
    refute Linux.hand_off_expected?(@gateway_map, @status_user, 36_876)
    refute Linux.hand_off_expected?("", @status_root, 36_876)
  end
end
