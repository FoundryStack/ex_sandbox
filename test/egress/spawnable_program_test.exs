defmodule ExSandbox.Egress.SpawnableProgramTest do
  @moduledoc """
  The program a policed launch execs must be spawnable by `:peer` (005 T060a).

  ## The defect this pins

  `NodeLauncher.exec_from_plan/1` hands the head of the plan's command to `:peer` as the program to
  start. `:peer` spawns it with
  `:erlang.open_port({:spawn_executable, prog}, ...)`, and **`spawn_executable`
  performs no `PATH` resolution** -- it opens a file. With the bare name
  `"pasta"` every policed launch died before the tenant existed:

      ** (ErlangError) Erlang error: :enoent:
         * 1st argument: invalid port name
         :erlang.open_port({:spawn_executable, ~c"pasta"}, ...)

  ## Why it survived every probe

  `docker/wired-egress-e2e.sh`, `netns-first-e2e.sh`, `acceptor-e2e.sh` and the
  rest run the mechanism's emitted commands **through a shell**, and a shell
  resolves `PATH`. The commands were therefore correct everywhere they had ever
  been measured, and wrong on the single path that launches a real tenant.

  It surfaced only when the conformance suite gained an allowlist and began
  taking the policed branch at all -- the permit direction, where every other
  defect in this feature has also hidden. A suite that only tests denial never
  runs this code.

  ## Why the assertion is a property, not a string

  The three tests that already covered the plan's head asserted
  `prog == "pasta"`. That is the bare name, so they did not merely fail to catch
  this -- they **required** it. The property that matters is "a path `:peer` can
  spawn", which is what these assert.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.LaunchPlan
  alias ExSandbox.Mechanism.Beam.NodeLauncher

  @confined [
    "/usr/bin/systemd-run",
    "--scope",
    "--unit=sandbox-x.scope",
    "-p",
    "MemoryMax=128M",
    "setpriv",
    "--reuid=4242",
    "--regid=4242",
    "--clear-groups",
    "--no-new-privs",
    "bwrap",
    "--unshare-net",
    "--die-with-parent",
    "erlexec"
  ]

  describe "the head of a policed launch command" do
    test "is an absolute path rather than a bare name" do
      {:ok, plan} = LaunchPlan.build({10, 0, 0, 4}, 9999, @confined)
      {prog, _args} = NodeLauncher.exec_from_plan(plan)

      assert String.starts_with?(prog, "/"),
             """
             `:peer` starts this program with `spawn_executable`, which does no
             PATH lookup. A bare name fails with :enoent before the tenant is
             ever created.

             Got: #{inspect(prog)}
             """
    end

    test "names the head of the plan, not a resolvable stand-in" do
      # Launching a different binary with the plan's arguments is the
      # substitution `LaunchDecisionsTest` exists to forbid.
      {:ok, plan} = LaunchPlan.build({10, 0, 0, 4}, 9999, @confined)
      {prog, args} = NodeLauncher.exec_from_plan(plan)

      assert [^prog | ^args] = plan.tenant_command
      assert Path.basename(prog) == "systemd-run"
    end
  end
end
