defmodule ExSandbox.Mechanism.Beam.HostPidTest do
  @moduledoc """
  The pid handed to `verify_applied/1` must be the **host's** view of the
  sandbox process, not the sandbox's view of itself (005 T036h, FR-007, FR-008).

  ## The bug this exists to prevent

  The launcher read the pid with `:peer.call(peer, :os, :getpid, [])` — which
  runs *inside* the sandbox. The sandbox is launched under `--unshare-pid`, so it
  has its own pid namespace and sees itself as pid `2`. Measured in the container:

  | Source | Value |
  |---|---|
  | `:os.getpid()` inside the sandbox | `2` |
  | `Port.info(port)[:os_pid]` on the host | `1565` |

  `verify_applied/1` then read `/proc/2`, which on the host is an unrelated
  kernel thread, and returned `:unverifiable` — so every launch was terminated
  as unhardened despite being correctly confined.

  This is the same shape as the `:erpc` bug one layer up: a value that is
  perfectly correct in the sandbox's frame of reference, used in the host's.
  `--unshare-pid` is doing exactly its job; the mistake is asking the confined
  process to describe itself to the confiner.

  ## Why the port's os_pid is the right source

  `:peer` spawns through `open_port({:spawn_executable, _}, ...)` and the port
  belongs to the **host** VM. Its `:os_pid` is the pid the host's `/proc` can
  resolve, which is what every check in `verify_applied/1` needs. It also
  requires no cooperation from the sandbox — a compromised one cannot lie about
  its pid to defeat verification, which it could if the host asked it.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Mechanism.Beam.NodeLauncher

  describe "the pid used for verification" do
    test "comes from the host-side port, not from inside the sandbox" do
      source = File.read!("lib/ex_sandbox/mechanism/beam/node_launcher.ex")

      refute source =~ ~r/:peer\.call\([^)]*:os,\s*:getpid/,
             """
             The OS pid is read by calling `:os.getpid()` inside the sandbox.
             Under `--unshare-pid` that returns the namespace-local pid (2), and
             `/proc/2` on the host is a different process entirely — so
             `verify_applied/1` inspects the wrong thing and reports
             `:unverifiable` for a correctly confined sandbox.
             """
    end

    test "is obtained from the port :peer spawned" do
      source = File.read!("lib/ex_sandbox/mechanism/beam/node_launcher.ex")

      assert source =~ ":os_pid",
             "The host-side pid comes from `Port.info(port)[:os_pid]`."
    end
  end

  describe "host_os_pid/1" do
    test "returns the pid of a port this VM spawned" do
      port =
        Port.open({:spawn_executable, System.find_executable("sleep")}, [:binary, args: ["5"]])

      on_exit(fn -> if Port.info(port), do: Port.close(port) end)

      assert {:ok, pid} = NodeLauncher.host_os_pid(port)
      assert is_integer(pid)
      assert pid > 0

      # The decisive check: this pid is resolvable *here*, on the host — which
      # is precisely what a namespace-local pid would not be.
      assert {_, 0} = System.cmd("ps", ["-p", Integer.to_string(pid)], stderr_to_stdout: true)
    end

    test "reports an error rather than a bogus pid when the port is gone" do
      port = Port.open({:spawn_executable, System.find_executable("true")}, [:binary])
      if Port.info(port), do: Port.close(port)

      assert {:error, _} = NodeLauncher.host_os_pid(port)
    end
  end
end
