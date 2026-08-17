defmodule ExSandbox.Egress.PastaTest do
  @moduledoc """
  Identifying the process that holds a sandbox's network namespace (T060a3).

  ## The wrong implementation this is written against

  One that trusts `pasta`'s pidfile. Measured in the isolation container:

      pidfile pid = 10 -> ns net:[4026534462]   <- the HOST namespace
      tenant  pid = 11 -> ns net:[4026534599]   <- the sandbox namespace

  `nsenter -t 10 -n nft add rule ...` does not fail. It installs the sandbox's
  redirect **into the host's own namespace**, leaving the tenant completely
  unpoliced while the host acquires a NAT rule redirecting its outbound TCP.
  Nothing in the launch reports a problem, and every denial check still passes.

  ⚠️ That is why these tests exist at all, and why they run on macOS. The rule
  they check cannot be exercised where it matters -- `/proc` and `nsenter` are
  Linux -- so it is verified against a **synthetic `/proc`** here. Left to the
  container, the single most dangerous line in the egress path would be covered
  only by a run that is skipped on every developer machine.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Pasta

  @host_ns "net:[4026534462]"
  @sandbox_ns "net:[4026534599]"

  # A synthetic `/proc` with the exact topology measured in the container:
  # pasta in the host namespace, its child in a different one.
  defp proc_tree(entries) do
    root = Path.join(System.tmp_dir!(), "proc-#{System.unique_integer([:positive])}")

    for {pid, ppid, ns} <- entries do
      dir = Path.join([root, "#{pid}", "ns"])
      File.mkdir_p!(dir)
      # Field 2 may contain spaces and parens; the parse must survive that.
      File.write!(Path.join([root, "#{pid}", "stat"]), "#{pid} (some cmd) S #{ppid} 0 0")
      File.ln_s!(ns, Path.join(dir, "net"))
    end

    self_dir = Path.join([root, "self", "ns"])
    File.mkdir_p!(self_dir)
    File.ln_s!(@host_ns, Path.join(self_dir, "net"))

    on_exit(fn -> File.rm_rf!(root) end)
    root
  end

  describe "holder identification" do
    test "the child in a different namespace is the holder, not pasta itself" do
      proc = proc_tree([{10, 8, @host_ns}, {11, 10, @sandbox_ns}])

      assert {:ok, 11} = Pasta.find(10, proc_root: proc, timeout_ms: 0)
    end

    test "a child sharing our namespace is never returned" do
      # ⚠️ The catastrophe, stated as a test. A process in the host namespace
      # is not a sandbox, and returning it sends the redirect to the host.
      # There is no caller for whom "the host namespace" is a useful answer.
      proc = proc_tree([{10, 8, @host_ns}, {11, 10, @host_ns}])

      assert {:error, :no_holder} = Pasta.find(10, proc_root: proc, timeout_ms: 0)
    end

    test "an unrelated process in another namespace is not mistaken for the holder" do
      # Another sandbox's tenant is in a different namespace too. Only a *child*
      # of this pasta counts -- otherwise a busy host hands one sandbox's
      # redirect to another sandbox's namespace.
      proc =
        proc_tree([
          {10, 8, @host_ns},
          {11, 10, @host_ns},
          {99, 1, "net:[4026599999]"}
        ])

      assert {:error, :no_holder} = Pasta.find(10, proc_root: proc, timeout_ms: 0)
    end

    test "pasta having no children at all is refused, not defaulted" do
      proc = proc_tree([{10, 8, @host_ns}])
      assert {:error, :no_holder} = Pasta.find(10, proc_root: proc, timeout_ms: 0)
    end

    test "an unreadable self namespace refuses rather than guessing" do
      # Without our own namespace there is nothing to compare against, and the
      # only available fallback -- "trust the first child" -- is precisely what
      # this module exists to prevent.
      root = Path.join(System.tmp_dir!(), "proc-#{System.unique_integer([:positive])}")
      File.mkdir_p!(root)
      on_exit(fn -> File.rm_rf!(root) end)

      assert {:error, :unreadable_self} = Pasta.find(10, proc_root: root, timeout_ms: 0)
    end
  end

  describe "waiting for the tenant" do
    test "a holder that appears late is still found" do
      # ⚠️ pasta forks the tenant *after* configuring the namespace. A single
      # check immediately after launch finds no child and reports what reads as
      # an architectural refusal -- "nothing entered a different namespace" --
      # when the truth is only that nothing has yet. Measured: at t+2s the child
      # did not exist. This cost one probe cycle and nearly a wrong conclusion
      # about whether the design was possible at all.
      proc = proc_tree([{10, 8, @host_ns}])
      test_pid = self()

      spawn(fn ->
        Process.sleep(120)
        dir = Path.join([proc, "11", "ns"])
        File.mkdir_p!(dir)
        File.write!(Path.join([proc, "11", "stat"]), "11 (tenant) S 10 0 0")
        File.ln_s!(@sandbox_ns, Path.join(dir, "net"))
        send(test_pid, :created)
      end)

      assert {:ok, 11} =
               Pasta.find(10, proc_root: proc, timeout_ms: 3_000, poll_interval_ms: 25)

      assert_received :created
    end

    test "waiting gives up rather than blocking forever" do
      proc = proc_tree([{10, 8, @host_ns}])

      started = System.monotonic_time(:millisecond)

      assert {:error, :no_holder} =
               Pasta.find(10, proc_root: proc, timeout_ms: 150, poll_interval_ms: 25)

      elapsed = System.monotonic_time(:millisecond) - started
      assert elapsed < 2_000, "find/2 must bound its wait; a launch cannot hang on this"
    end
  end
end
