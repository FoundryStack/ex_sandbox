defmodule ExSandbox.Mechanism.DockerUserTest do
  @moduledoc """
  Which uid a sandbox's processes run as, and why a host gets to say.

  A `workspace_path` is one directory two processes write: the sandbox, and the
  host process that supplied the directory and later has to read, copy, stage or
  delete what the sandbox left in it. When the two run as different uids, every
  path the sandbox creates is one the host cannot touch. `check_workspace/1`
  already names this failure class in its own comment -- *a failure that
  surfaces later, in another process, as a permission error naming nothing* --
  and stops at existence and absoluteness, because whoever owns the directory
  owns creating it. The uid the container writes as belongs to that same owner.

  ⚠️ Asserted on the argument list rather than on a running container, for the
  reason `DockerNetworkPostureTest` gives: the flag is the only place the two
  postures differ, and asserting there means the check runs on a host with no
  daemon.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Mechanism.Docker
  alias ExSandbox.Sandbox

  defp sandbox(overrides) do
    struct!(
      %Sandbox{
        id: "docker-user-#{System.unique_integer([:positive])}",
        owner_ref: "test",
        template_ref: Docker.default_image()
      },
      overrides
    )
  end

  defp user_flag(args) do
    case Enum.find_index(args, &(&1 == "--user")) do
      nil -> nil
      index -> Enum.at(args, index + 1)
    end
  end

  describe "a sandbox that names no user" do
    test "is created without the flag, so the image still decides" do
      refute "--user" in Docker.create_args(sandbox(user: nil)),
             """
             A sandbox that asked for no uid was given one anyway.

             `nil` is the posture every sandbox had before this field existed,
             and a caller that never sets it must keep it.
             """
    end

    test "an empty string is the same as none, not a flag with no value" do
      refute "--user" in Docker.create_args(sandbox(user: ""))
    end
  end

  describe "a sandbox that names a user" do
    test "runs as it" do
      assert "1000" == user_flag(Docker.create_args(sandbox(user: "1000")))
    end

    test "carries a group through untouched" do
      # Passed through rather than parsed: `--user` takes a uid, a name, and
      # either with a group after a colon, and deciding here which a caller
      # meant would be this library ruling on the host's own accounts.
      assert "1000:1000" == user_flag(Docker.create_args(sandbox(user: "1000:1000")))
      assert "app:staff" == user_flag(Docker.create_args(sandbox(user: "app:staff")))
    end

    test "the flag precedes the image, so it configures the container rather than the command" do
      args = Docker.create_args(sandbox(user: "1000", workspace_path: nil))

      assert Enum.find_index(args, &(&1 == "--user")) <
               Enum.find_index(args, &(&1 == Docker.default_image())),
             """
             `--user` landed after the image reference, where `docker create`
             reads it as part of the command to run inside the container.
             """
    end
  end
end
