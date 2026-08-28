defmodule ExSandbox.Mechanism.DockerWorkspaceTest do
  @moduledoc """
  The workspace is one directory seen from two places.

  ⚠️ The assertions are deliberately in **both** directions. A mount that is
  visible one way and stale the other is the failure this exists to prevent: an
  agent's edit that the build never sees looks exactly like an agent that did
  not edit anything.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Mechanism.Docker
  alias ExSandbox.Sandbox

  @moduletag :docker

  setup do
    workspace =
      Path.join(System.tmp_dir!(), "ex-sandbox-workspace-#{System.unique_integer([:positive])}")

    File.mkdir_p!(workspace)
    on_exit(fn -> File.rm_rf(workspace) end)

    {:ok, workspace: workspace}
  end

  defp running(overrides) do
    sandbox =
      struct!(
        %Sandbox{
          id: "docker-workspace-#{System.unique_integer([:positive])}",
          owner_ref: "test",
          template_ref: Docker.default_image()
        },
        overrides
      )

    {:ok, provisioned} = Docker.provision(sandbox)
    {:ok, started} = Docker.start(provisioned)
    on_exit(fn -> Docker.destroy(started) end)
    started
  end

  describe "a sandbox with a workspace" do
    test "sees a file the host wrote", %{workspace: workspace} do
      File.write!(Path.join(workspace, "from-host.txt"), "written on the host")

      sandbox = running(workspace_path: workspace)

      assert {:ok, completion} =
               Docker.execute(sandbox, {"cat", ["from-host.txt"]}, [])

      assert completion.exit_status == 0
      assert completion.stdout == "written on the host"
    end

    test "starts in the workspace rather than in the image's own directory", %{
      workspace: workspace
    } do
      sandbox = running(workspace_path: workspace)

      assert {:ok, completion} = Docker.execute(sandbox, {"pwd", []}, [])

      assert String.trim(completion.stdout) == Docker.workspace_mountpoint(),
             "a relative path written by tenant code would miss the workspace entirely"
    end

    test "a file it writes is visible on the host", %{workspace: workspace} do
      sandbox = running(workspace_path: workspace)

      assert {:ok, %{exit_status: 0}} =
               Docker.execute(
                 sandbox,
                 {"sh", ["-c", "echo written inside > from-sandbox.txt"]},
                 []
               )

      assert File.read!(Path.join(workspace, "from-sandbox.txt")) == "written inside\n"
    end
  end

  describe "a sandbox with no workspace" do
    test "mounts nothing rather than something sensible" do
      sandbox = running([])

      assert {:ok, completion} =
               Docker.execute(sandbox, {"sh", ["-c", "test -d /workspace; echo $?"]}, [])

      assert String.trim(completion.stdout) == "1",
             "a nil workspace produced a mount anyway"
    end
  end

  describe "a workspace that is not usable" do
    test "a missing directory is refused rather than created as root" do
      # ⚠️ `docker create` would create it, owned by root, and the host process
      # that is meant to share those files would then fail to write them --
      # later, elsewhere, with a permission error naming nothing.
      missing = Path.join(System.tmp_dir!(), "ex-sandbox-no-such-#{System.unique_integer()}")

      assert {:error, {:workspace_not_a_directory, ^missing}} =
               Docker.provision(%Sandbox{
                 id: "docker-workspace-missing",
                 owner_ref: "test",
                 template_ref: Docker.default_image(),
                 workspace_path: missing
               })

      refute File.exists?(missing), "the refusal created the directory it refused"
    end

    test "a relative path is refused" do
      assert {:error, {:workspace_not_absolute, "workspaces/mine"}} =
               Docker.provision(%Sandbox{
                 id: "docker-workspace-relative",
                 owner_ref: "test",
                 template_ref: Docker.default_image(),
                 workspace_path: "workspaces/mine"
               })
    end
  end
end
