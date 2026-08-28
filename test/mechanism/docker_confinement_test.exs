defmodule ExSandbox.Mechanism.DockerConfinementTest do
  @moduledoc """
  What this mechanism claims to construct, and the breach behind each claim.

  ⚠️ `c:ExSandbox.Mechanism.constructed_capabilities/0` is a **claim**, and the
  behaviour verifies nothing about it -- a mechanism may name any capability it
  likes and the gate will believe it. That is the price of letting a mechanism
  bring its own kernel, and the only thing that makes it safe is that every name
  on the list has a test here watching a breach be stopped.

  The two names deliberately absent are as much the subject of this file as the
  three present. An omission that nobody notices becomes a claim by default the
  first time somebody "completes" the list.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Mechanism.Docker
  alias ExSandbox.Sandbox

  @moduletag :docker

  defp running do
    sandbox = %Sandbox{
      id: "docker-confinement-#{System.unique_integer([:positive])}",
      owner_ref: "test",
      template_ref: Docker.default_image(),
      memory_limit_mb: 64,
      cpu_limit: 500,
      disk_quota_mb: 16
    }

    {:ok, provisioned} = Docker.provision(sandbox)
    {:ok, started} = Docker.start(provisioned)
    on_exit(fn -> Docker.destroy(started) end)
    started
  end

  describe "the network is denied, and the denial is observed" do
    test "a literal IP is unreachable from inside" do
      # ⚠️ A literal address, never a hostname. With `--network none` there is no
      # resolver either, so a hostname fails at DNS -- and a DNS failure is
      # indistinguishable from a name that does not exist. That test would pass
      # against a container with full connectivity and a typo in the hostname,
      # which is the shape of check `ExSandbox.Egress` exists to prevent.
      assert {:ok, completion} =
               Docker.execute(
                 running(),
                 {"wget", ["-T", "3", "-q", "-O", "-", "http://1.1.1.1/"]},
                 timeout: 30_000
               )

      refute completion.exit_status == 0,
             """
             A sandbox launched with `--network none` reached 1.1.1.1.

             Remove `--network none` from `network_args/0` and this test must go red. \
             If it stays green either way, it is measuring this machine's connectivity \
             rather than the sandbox's confinement.
             """
    end

    test "no interface carries an address to leak through" do
      # The stronger statement, and the reason `:network_restriction` is claimed
      # in the strong sense rather than as a filtered egress: not "the packets
      # are dropped" but "there is nowhere to send them from".
      #
      # ⚠️ Asked of the ADDRESSES, not of `/sys/class/net`. An empty network
      # namespace still lists the kernel's default tunnel devices -- MEASURED
      # here: `erspan0`, `gre0`, `ip6tnl0`, `sit0`, `tunl0` and friends, all of
      # them down and unaddressed. A test spelled `interfaces == ["lo"]` fails
      # against a correctly confined sandbox, and the natural way to "fix" that
      # is to allowlist the names -- at which point a real interface appearing
      # among them goes unnoticed.
      assert {:ok, completion} =
               Docker.execute(running(), {"ip", ["-o", "addr", "show"]}, [])

      addressed =
        completion.stdout
        |> String.split("\n", trim: true)
        |> Enum.map(fn line -> line |> String.split(~r/\s+/, trim: true) |> Enum.at(1) end)
        |> Enum.reject(&is_nil/1)
        |> Enum.uniq()
        |> Enum.sort()

      assert addressed == ["lo"],
             "expected loopback to be the only addressed interface, got #{inspect(addressed)}"
    end
  end

  describe "the filesystem is confined, and the confinement is observed" do
    test "the host's own tree is not visible from inside" do
      # This file's directory exists on the host and must not exist in the
      # container. A bind mount is how a workspace gets in later; nothing is
      # mounted here, so nothing of the host should be reachable.
      host_path = __ENV__.file

      assert {:ok, completion} =
               Docker.execute(running(), {"sh", ["-c", "test -e '#{host_path}'; echo $?"]}, [])

      assert String.trim(completion.stdout) == "1",
             "the host path #{host_path} was visible inside the sandbox"
    end
  end

  describe "the capability lists" do
    test "every claimed name has a breach observed in this file" do
      claimed = Docker.constructed_capabilities()

      assert Enum.sort(claimed) ==
               Enum.sort([:resource_limits, :filesystem_confinement, :network_restriction]),
             """
             #{inspect(claimed)} is not the list this file has evidence for.

             `:resource_limits` rests on the memory and CPU breaches in \
             `ExSandbox.Mechanism.DockerExecuteTest`; `:network_restriction` and \
             `:filesystem_confinement` rest on the breaches above. Adding a name here \
             without adding its breach turns the claim back into an assertion, which is \
             what `005` R9b and D4 both measured going wrong.
             """
    end

    test ":disk_quota is claimed nowhere, because this host does not enforce one" do
      # ⚠️ D4, MEASURED: `docker run --storage-opt size=16M` accepted, 64 MB
      # written, exit 0, overlayfs reporting the whole host filesystem. The
      # sandbox above declares `disk_quota_mb: 16` precisely so that a future
      # edit which starts honouring it has to come past this test.
      refute :disk_quota in Docker.constructed_capabilities(),
             "a quota that is accepted and ignored is not a quota"

      refute :disk_quota in Docker.required_capabilities(),
             "requiring it would refuse on every overlayfs host, which is every " <>
               "Docker Desktop for Mac -- the host this mechanism exists to serve"
    end

    test ":privilege_separation is claimed nowhere, and this is not an oversight" do
      # The container's process is root in the container. Under rootful Docker
      # that root maps to host root, so the "dropped uid composed with a mount
      # namespace" that `Capability.check/1` means by this name is not what a
      # default container gives. Claiming it would describe this mechanism as
      # equivalent to `bwrap` plus `setpriv`, which is exactly the
      # weakly-isolated-presented-as-isolated failure `FR-013` exists to report.
      refute :privilege_separation in Docker.constructed_capabilities()
      refute :privilege_separation in Docker.required_capabilities()
    end

    test "nothing is required that is not also constructed" do
      # ⚠️ The gate subtracts the constructed list from the required one and asks
      # the host probe about the remainder. On macOS every gating name is
      # unavailable, so any remainder refuses -- and this mechanism exists
      # because that refusal left a developer with nowhere to run tenant code.
      assert Docker.required_capabilities() -- Docker.constructed_capabilities() == [],
             "a leftover name refuses this mechanism on the host it was written for"
    end
  end
end
