defmodule ExSandbox.Mechanism.DockerNetworkPostureTest do
  @moduledoc """
  What the container is given a network for, and where it publishes it
  (`studio/FR-007/S4`, design D12).

  ⚠️ These assertions are on the **argument list**, not on a running container,
  and that is deliberate rather than a convenience. The difference between a
  port published on `127.0.0.1` and the same port published on `0.0.0.0` is
  invisible to any request the platform itself makes -- both answer -- so a test
  that fetches the preview and finds it working cannot tell them apart. The one
  place the two differ is the flag, and asserting there also means this check
  runs on a host with no Docker daemon, where the exposure would otherwise go
  unnoticed until it reached one that had.

  `ExSandbox.Mechanism.DockerAddressTest` is the other half: that a container
  launched with these arguments really does answer where `address/1` says.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Mechanism.Docker
  alias ExSandbox.Sandbox

  defp sandbox(overrides) do
    struct!(
      %Sandbox{
        id: "docker-network-#{System.unique_integer([:positive])}",
        owner_ref: "test",
        template_ref: Docker.default_image()
      },
      overrides
    )
  end

  describe "a sandbox that names no service port" do
    test "joins no network at all" do
      args = Docker.create_args(sandbox(service_port: nil))

      assert ["--network", "none"] == network_flags(args)

      refute Enum.any?(args, &(&1 in ["-p", "--publish"])),
             """
             A sandbox that asked for no reachability got a published port.

             This is the posture every sandbox had before `service_port`
             existed, and it is what a host that never sets the field keeps.
             """
    end
  end

  describe "a sandbox that names a service port" do
    test "publishes it on the loopback interface and not on every interface" do
      args = Docker.create_args(sandbox(service_port: 4000))

      assert "127.0.0.1::4000" == published(args),
             """
             The application port is not published to loopback only.

             `-p 4000` and `-p 0.0.0.0::4000` both make the preview answer, and
             both put the tenant's application on every interface this host has.
             Nothing about the working case distinguishes them, which is why the
             assertion is here.
             """

      refute Enum.any?(args, &String.contains?(&1, "0.0.0.0"))
    end

    test "does not leave the host to choose which host port is free" do
      # The host half of the binding is empty: the daemon allocates. A number
      # here would have to be checked for availability first, and the gap
      # between that check and the bind is a race two concurrent provisions lose
      # to each other.
      assert "127.0.0.1::4000" == published(Docker.create_args(sandbox(service_port: 4000)))
    end

    test "joins a network, since a published port on no network reaches nothing" do
      args = Docker.create_args(sandbox(service_port: 4000))

      assert ["--network", "bridge"] == network_flags(args)
    end
  end

  defp network_flags(args) do
    case Enum.find_index(args, &(&1 == "--network")) do
      nil -> []
      index -> Enum.slice(args, index, 2)
    end
  end

  defp published(args) do
    case Enum.find_index(args, &(&1 in ["-p", "--publish"])) do
      nil -> nil
      index -> Enum.at(args, index + 1)
    end
  end
end
