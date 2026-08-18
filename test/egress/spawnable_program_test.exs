defmodule ExSandbox.Egress.SpawnableProgramTest do
  @moduledoc """
  The program a policed launch execs must be spawnable by `:peer` (005 T060a).

  ## The defect this pins

  `LaunchPlan.build/3` puts `pasta` at the head of the tenant command, and
  `NodeLauncher.exec_from_plan/1` hands that head to `:peer` as the program to
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

  alias ExSandbox.Egress.{LaunchPlan, Netns}
  alias ExSandbox.Mechanism.Beam.NodeLauncher

  @confined ["systemd-run", "--scope", "bwrap", "--unshare-net", "--die-with-parent", "erl"]

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

    test "names pasta, so the fix did not swap the program for a resolvable one" do
      # ⚠️ The paired assertion. "Absolute path" alone would be satisfied by
      # `/usr/bin/systemd-run`, which is the exact substitution
      # `LaunchDecisionsTest` exists to forbid -- the tenant would launch with
      # pasta's arguments and no namespace at all, reaching everything.
      {:ok, plan} = LaunchPlan.build({10, 0, 0, 4}, 9999, @confined)
      {prog, _args} = NodeLauncher.exec_from_plan(plan)

      assert Path.basename(prog) == "pasta"
    end

    test "is a file that exists wherever pasta is installed" do
      # Skipped rather than failed off-Linux: `pasta` is a Linux binary and its
      # absence on a developer machine is a fact about the host, not a defect in
      # the plan. `pasta_path/0` falls back to a named path precisely so the
      # failure says where it looked.
      case System.find_executable("pasta") do
        nil ->
          assert Path.basename(hd(Netns.pasta_command("/tmp/p.pid", ["true"]))) == "pasta"

        found ->
          [head | _] = Netns.pasta_command("/tmp/p.pid", ["true"])
          assert head == found
          assert File.exists?(head)
      end
    end
  end
end
