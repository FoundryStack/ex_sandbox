defmodule ExSandbox.Mechanism.Beam.HardeningVerifiedTest do
  @moduledoc """
  Confinement is actually in force, and its absence is refused (005 T033).

  ## The negative case is the one that matters

  The positive tests below inspect a launched sandbox's uid and cgroup limits on
  a correctly configured host. They are worth having, and they are also the easy
  half: a host with `setpriv`, `bwrap`, and cgroup v2 present will pass them
  whether or not the code would notice their absence.

  Production hosts fail by being **misconfigured**, not by being correct. So the
  second describe block removes `setpriv` from `PATH` and asserts provisioning
  *refuses* — because the alternative to refusing is starting tenant code
  unconfined while every layer above reports it contained, which is the failure
  `Principle II` exists to prevent.
  """
  use ExUnit.Case, async: false

  @moduletag :isolation

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  defp sandbox do
    %Sandbox{
      id: "hv-#{System.unique_integer([:positive])}",
      owner_ref: "owner-hv",
      template_ref: "conformance-template",
      cpu_limit: 500,
      memory_limit_mb: 128,
      disk_quota_mb: 256
    }
  end

  describe "a launched sandbox on a correctly configured host" do
    test "runs as a non-root uid with cgroup limits actually set" do
      sb = sandbox()
      assert {:ok, provisioned} = Beam.provision(sb)
      on_exit(fn -> Beam.destroy(provisioned) end)

      node = String.to_atom(provisioned.mechanism_ref)
      os_pid = :erpc.call(node, :os, :getpid, [], 10_000) |> to_string() |> String.to_integer()

      # Read from the OS, not from the launch configuration. What was requested
      # and what is in force are different questions, and only the second one
      # is a guarantee (R9b: `taskpolicy -m` requests a cap and silently loses
      # it across an exec).
      assert :ok = ExSandbox.Hardening.Linux.verify_applied(os_pid)

      uid = :erpc.call(node, :os, :cmd, [~c"id -u"], 10_000) |> to_string() |> String.trim()
      refute uid == "0", "sandbox is running as root"

      cgroup = File.read!("/proc/#{os_pid}/cgroup")

      refute cgroup =~ ~r{^0::/$}m,
             "sandbox process is in the root cgroup, so no limits are applied to it"
    end
  end

  describe "a misconfigured host" do
    setup do
      previous = System.get_env("PATH")
      on_exit(fn -> System.put_env("PATH", previous) end)
      {:ok, previous_path: previous}
    end

    test "refuses to provision when setpriv is missing rather than running unconfined" do
      # A PATH with the hardening tools removed. This is the shape of a real
      # misconfiguration: everything else works, so the sandbox would launch
      # perfectly well -- just without privilege separation.
      sanitized =
        System.get_env("PATH")
        |> String.split(":")
        |> Enum.reject(fn dir -> File.exists?(Path.join(dir, "setpriv")) end)
        |> Enum.join(":")

      System.put_env("PATH", sanitized)

      assert System.find_executable("setpriv") == nil,
             "precondition failed: setpriv is still on PATH, so this test proves nothing"

      refute ExSandbox.Hardening.Linux.available?(),
             "hardening reports available with setpriv missing -- it is not probing honestly"

      assert {:error, :mechanism_error} = Beam.provision(sandbox()),
             """
             provisioning SUCCEEDED on a host that cannot drop privileges.

             Tenant code would now be running unconfined while the registry
             records it as sandboxed -- worse than a refusal, because nothing
             above this layer has any way to notice.
             """
    end
  end
end
