defmodule ExSandbox.Egress.AcceptorReclaimTest do
  @moduledoc """
  Reclaiming the acceptor on destroy (005 T060a6, `003-FR-013`).

  ## Why this needs a test

  ⚠️ The acceptor does **not** die with the namespace it serves. Measured in the
  isolation image: after `kill -9` on the namespace holder the acceptor was
  still running, and `/proc/<acceptor>/ns/net` still named the same namespace —
  it was holding a dead netns open.

  So every destroy would leak one process *and* one namespace, with no symptom
  until the host ran out of one of them. That is a slow failure with a cause far
  from its effect, which is the kind this suite exists to catch early.
  """
  # ⚠️ `async: false`. These tests spawn real OS processes and assert on their
  # liveness, and the isolation suite runs 28 cases concurrently -- several of
  # which launch and reap sandbox processes of their own. The
  # "terminates a running process" case failed in the container and passed on
  # macOS for exactly that reason: a `kill -0` liveness check reads global state
  # that a concurrent test can disturb.
  #
  # Serial is the honest fix. Retrying harder would have hidden a real race
  # behind a longer timeout.
  use ExUnit.Case, async: false

  alias ExSandbox.Mechanism.Beam.NodeLauncher

  describe "stop_acceptor/1" do
    test "a sandbox launched with no egress path reclaims nothing" do
      # `nil` is ordinary, not exceptional: it is every sandbox on a host with
      # no egress path, which is every developer machine that is not Linux.
      assert NodeLauncher.stop_acceptor(nil) == :ok
    end

    test "terminates a running process" do
      port =
        Port.open({:spawn_executable, System.find_executable("sleep")},
          args: ["30"]
        )

      {:os_pid, os_pid} = Port.info(port, :os_pid)
      assert alive?(os_pid)

      assert NodeLauncher.stop_acceptor(os_pid) == :ok
      assert eventually(fn -> not alive?(os_pid) end)
    end

    test "is idempotent, because a second destroy must be safe" do
      # ⚠️ `003-FR-013`. Reclamation that fails on an already-reclaimed sandbox
      # is reclamation nobody can retry -- and a destroy that raises after
      # releasing the binding leaves the caller unable to tell what was undone.
      port =
        Port.open({:spawn_executable, System.find_executable("sleep")},
          args: ["30"]
        )

      {:os_pid, os_pid} = Port.info(port, :os_pid)

      assert NodeLauncher.stop_acceptor(os_pid) == :ok
      assert eventually(fn -> not alive?(os_pid) end)

      # The pid is gone; asking again must still succeed.
      assert NodeLauncher.stop_acceptor(os_pid) == :ok
      assert NodeLauncher.stop_acceptor(os_pid) == :ok
    end
  end

  describe "the destroy path" do
    test "calls stop_acceptor with the pid it recorded" do
      # ⚠️ Wiring, not behaviour. `stop_acceptor/1` being correct is worth
      # nothing if `destroy/1` never calls it, and that is the exact shape of
      # four earlier defects in this feature -- an unsupervised pool, an
      # unreferenced Binding, an unwired relay, a probe flag the mechanism never
      # passed. Each was correct code that nothing reached.
      #
      # Read from source because `destroy/1` needs a launched sandbox, and a
      # launch needs Linux. The alternative is verifying this only where the
      # whole launch works, which is the arrangement that let those four
      # survive.
      source = File.read!(Path.join([__DIR__, "..", "..", "lib", "ex_sandbox", "mechanism", "beam.ex"]))

      assert source =~ "stop_acceptor",
             """
             `destroy/1` never stops the acceptor, so every destroy leaks one
             process and keeps one dead network namespace open.
             """

      assert source =~ ~r/acceptor_os_pid.*stop_acceptor|stop_acceptor\(launched\.acceptor_os_pid\)/s,
             "the acceptor pid recorded at launch is not the one passed to stop_acceptor"
    end

    test "the launcher records the acceptor pid on the launched row" do
      # Without a field that outlives the launch frame, `destroy/1` has no route
      # to the pid at all -- the same reason `:binding` exists.
      source =
        File.read!(
          Path.join([__DIR__, "..", "..", "lib", "ex_sandbox", "mechanism", "beam", "node_launcher.ex"])
        )

      assert source =~ "acceptor_os_pid:",
             "the launched row carries no acceptor pid, so destroy cannot reclaim it"
    end
  end

  defp alive?(os_pid) do
    {_out, code} = System.cmd("kill", ["-0", "#{os_pid}"], stderr_to_stdout: true)
    code == 0
  end

  # Bounded wait rather than a fixed sleep: SIGTERM delivery is asynchronous, so
  # asserting immediately after `kill` is a race in the other direction.
  defp eventually(fun, attempts \\ 100) do
    Enum.reduce_while(1..attempts, false, fn _, _ ->
      if fun.() do
        {:halt, true}
      else
        Process.sleep(20)
        {:cont, false}
      end
    end)
  end
end
