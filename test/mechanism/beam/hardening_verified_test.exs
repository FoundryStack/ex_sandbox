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

      # ⚠️ The host's pid, from the mechanism -- **never** `:os.getpid()` asked of
      # the sandbox. Under `--unshare-pid` the sandbox reports its
      # namespace-local pid (`2`) while the host knows it by something else
      # entirely, so verification would read `/proc/2` and report on an unrelated
      # process. The same mistake, in production code, is what
      # `NodeLauncher.host_os_pid/1` exists to prevent.
      assert {:ok, os_pid} = Beam.host_pid(provisioned)

      # Read from the OS, not from the launch configuration. What was requested
      # and what is in force are different questions, and only the second one
      # is a guarantee (R9b: `taskpolicy -m` requests a cap and silently loses
      # it across an exec).
      #
      # `{:ok, applied}` carries the limits actually in force. Asserting a bare
      # `:ok` here would not compile against the real return value -- and did
      # not, until the pid above was corrected and this assertion was reached
      # for the first time.
      assert {:ok, applied} = ExSandbox.Hardening.Linux.verify_applied(os_pid)

      assert applied.uid != 0, "sandbox is running as root"
      assert applied.mount_confined, "sandbox shares the platform's mount namespace"
      assert applied.egress_restricted, "sandbox shares the platform's network namespace"

      assert applied.memory_limit_mb == 128,
             "cgroup reports #{inspect(applied.memory_limit_mb)} rather than the requested 128 MB"

      # Asked of the sandbox as well, so the uid is confirmed from both sides:
      # the host's `/proc` view and the tenant's own.
      #
      # ⚠️ Read from `/proc/self/status` rather than by shelling out to `id`.
      # The sandbox's filesystem is confined to a handful of read-only binds and
      # `id` is not among them -- `:os.cmd/1` answers "sh: 1: id: not found",
      # which is a string, not a uid, and would fail this assertion for a reason
      # that has nothing to do with privilege separation.
      assert {:ok, status} = Beam.call(provisioned, :file, :read_file, ["/proc/self/status"])

      assert [_, sandbox_uid] = Regex.run(~r/^Uid:\s+(\d+)/m, to_string(status))
      assert String.to_integer(sandbox_uid) == applied.uid

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
