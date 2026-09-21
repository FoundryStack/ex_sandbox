defmodule ExSandbox.Hardening.WorkspaceBindTest do
  @moduledoc """
  A Beam sandbox with a `workspace_path` sees it at `/workspace`, and can use it.

  ## The bug this exists to prevent

  OBSERVED 2026-09-21 on production: a deployment's build ran
  `. /workspace/.axonn-db.env` inside a Beam sandbox and got "No such file or
  directory". `confinement_args/2` bound the sandbox's storage and nothing else,
  so the workspace the platform had written the file into was not in the
  sandbox's mount view at all -- while Docker, which binds it, passed.

  Binding it is half. The platform writes into the workspace as itself, and the
  sandbox runs as a derived uid that cannot read a `0600` file it does not own.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Hardening.Linux

  defp sandbox(workspace_path) do
    %ExSandbox.Sandbox{
      id: "ws-#{System.unique_integer([:positive])}",
      owner_ref: "owner-1",
      template_ref: "tpl",
      memory_limit_mb: 256,
      cpu_limit: 500,
      disk_quota_mb: 1024,
      workspace_path: workspace_path
    }
  end

  defp args(sandbox) do
    {:ok, {_prog, args}} = Linux.compose_for_inspection(sandbox, [])
    args
  end

  defp bind_targets(args) do
    args
    |> Enum.chunk_every(3, 1, :discard)
    |> Enum.filter(fn [flag | _] -> flag == "--bind" end)
    |> Enum.map(fn [_, source, target] -> {source, target} end)
  end

  describe "the bind" do
    test "puts workspace_path at /workspace, read-write" do
      assert {"/srv/ws/app", "/workspace"} in bind_targets(args(sandbox("/srv/ws/app")))
    end

    test "binds nothing at /workspace when there is no workspace" do
      refute Enum.any?(bind_targets(args(sandbox(nil))), fn {_, target} ->
               target == "/workspace"
             end)
    end
  end

  describe "the hand-off" do
    test "keeps .git the platform's and does not follow symlinks" do
      assert {"chown", ["-R", "-h", "4242:4242", "--", "/ws/lib", "/ws/.axonn-db.env"]} =
               Linux.workspace_handoff(["lib", ".git", ".axonn-db.env"], "/ws", 4242)
    end

    test "runs nothing for a workspace holding only .git" do
      assert Linux.workspace_handoff([".git"], "/ws", 4242) == nil
      assert Linux.workspace_handoff([], "/ws", 4242) == nil
    end

    @tag :tmp_dir
    test "opens the root to the sandbox's group without giving it away", %{tmp_dir: dir} do
      File.write!(Path.join(dir, "mix.exs"), "")
      %{uid: owner} = File.stat!(dir)

      assert :ok = Linux.prepare_workspace(sandbox(dir))

      stat = File.stat!(dir)
      assert Bitwise.band(stat.mode, 0o777) == 0o770
      assert stat.uid == owner
    end

    test "does nothing without a workspace" do
      assert :ok = Linux.prepare_workspace(sandbox(nil))
    end
  end
end
