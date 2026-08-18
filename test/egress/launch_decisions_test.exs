defmodule ExSandbox.Egress.LaunchDecisionsTest do
  @moduledoc """
  The launch path's egress decisions, tested where `launch/2` cannot run
  (005 T060a3b).

  ## Why these are separate functions rather than assertions about a launch

  `NodeLauncher.launch/2` runs on Linux and nowhere else: it needs `bwrap`,
  `systemd-run`, and now `ip netns`. Every decision it makes about egress --
  does this sandbox get a policy, which program gets exec'd, what happens when
  a step fails -- was therefore verifiable only on a host that could perform
  the whole launch.

  ⚠️ **That arrangement is what let the context-discard defect survive.** The
  allowlist was parsed correctly and then thrown away, and every test asserted
  on the parse. Measured here rather than argued: with the launch-failure
  release deleted, the entire 294-test host suite still passed, because not one
  test reaches that line.

  So the decisions are extracted and tested directly. What remains untestable
  off-Linux is whether `ip netns` works, which is a container question.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.LaunchPlan
  alias ExSandbox.Mechanism.Beam.NodeLauncher
  alias ExSandbox.Sandbox

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

  defp sandbox(context) do
    %Sandbox{
      id: "decisions-#{System.unique_integer([:positive])}",
      owner_ref: "owner",
      template_ref: "template",
      context: context
    }
  end

  describe "whether a sandbox gets a policy at all" do
    test "a resolved allowlist is carried to the launch path" do
      allowed = [{"api.example.com", 443}]
      assert NodeLauncher.egress_allowlist(sandbox(%{network_allowlist: allowed})) == allowed
    end

    test "no allowlist means no policy rather than an empty policy" do
      # ⚠️ The distinction is load-bearing. `[]` routes to the passthrough
      # clause, which leaves `--unshare-net` in place and publishes no
      # `:permitted` -- so the census reports the third outcome. Treating `[]`
      # as "a policy permitting nothing" would instead install a namespace,
      # claim the sandbox is policed, and deny everything: a full green suite
      # for a boundary that was never demonstrated.
      assert NodeLauncher.egress_allowlist(sandbox(%{})) == []
      assert NodeLauncher.egress_allowlist(sandbox(nil)) == []
    end

    test "a sandbox with no context at all is not policed" do
      bare = %Sandbox{id: "bare", owner_ref: "o", template_ref: "t"}
      assert NodeLauncher.egress_allowlist(bare) == []
    end
  end

  describe "which program is actually exec'd" do
    test "the plan's own head becomes the program, not the original one" do
      {:ok, plan} = LaunchPlan.build({10, 0, 0, 4}, 9999, @confined)

      {prog, _args} = NodeLauncher.exec_from_plan(plan)

      # ⚠️ The mistake this pins: keeping `systemd-run` as the program while
      # taking the plan's arguments. The command reads correctly in a log line
      # and execs the wrong binary -- and because the arguments still *contain*
      # every hardening flag, a test that greps the joined string for
      # `--unshare-net` or the scope name would pass.
      # ⚠️ Asserted as a RELATIONSHIP to the plan, never as a literal name, and
      # the history of this line is why. It first required the bare name
      # `"pasta"` -- which did not merely miss the `spawn_executable` defect,
      # it *pinned* it, since `:peer` does no `PATH` lookup and every policed
      # launch died with `:enoent`. It was then loosened to an absolute path
      # with basename `pasta`, which pinned the *wrapping* ordering just as
      # firmly: under the split (T060a4e) pasta is mid-chain and the head is
      # `systemd-run` once more.
      #
      # Both times the literal was correct when written and became the thing
      # blocking the fix. What must actually hold is that the program exec'd is
      # the head of the plan's own command -- true under every ordering, and
      # false for exactly the defect this test exists to catch.
      assert [^prog | _] = plan.pasta_command

      assert String.starts_with?(prog, "/"),
             "`:peer` spawns this program with `spawn_executable`, which does " <>
               "no PATH lookup; a bare name fails with :enoent (got #{inspect(prog)})"

      # The substitution the test forbids: taking the plan's arguments while
      # keeping a program the plan did not name.
      refute prog == "bwrap",
             "the plan's head must be exec'd, not an inner binary paired with " <>
               "the plan's arguments"
    end

    test "the confinement survives the rewrite" do
      {:ok, plan} = LaunchPlan.build({10, 0, 0, 4}, 9999, @confined)
      {prog, args} = NodeLauncher.exec_from_plan(plan)

      full = [prog | args]

      # The namespace is joined *and* the tenant is still confined. A rewrite
      # that dropped the bwrap half would police the network of a sandbox with
      # no filesystem or privilege confinement at all.
      #
      # ⚠️ Compared by BASENAME. Programs are resolved to absolute paths so
      # `:peer` can spawn them, and an equality test against the bare name fails
      # for a resolution that is correct -- which is how the last two of these
      # assertions came to pin a defect instead of catching one.
      basenames = Enum.map(full, &Path.basename/1)

      for required <- ["systemd-run", "setpriv", "pasta", "bwrap", "erlexec"] do
        assert required in basenames,
               "#{required} must survive the rewrite; got #{inspect(basenames)}"
      end

      # ⚠️ Presence is not enough, and this is the assertion the earlier version
      # lacked. All five binaries were present in the UNBOOTABLE ordering too --
      # what made it unbootable was `setpriv` landing *inside* pasta's namespace.
      # A test that only checks membership passes against the command that cannot
      # launch a tenant at all.
      order = fn name -> Enum.find_index(basenames, &(&1 == name)) end

      assert order.("systemd-run") < order.("setpriv"),
             "the scope must stay outermost or its caps are never applied"

      assert order.("setpriv") < order.("pasta"),
             "the drop must precede pasta or setresuid fails in an empty uid_map"

      assert order.("pasta") < order.("bwrap"),
             "the tenant must run inside pasta's namespace"

      refute "--unshare-net" in full,
             "`--unshare-net` must be removed, not supplemented: it would put " <>
               "the tenant in a fresh empty namespace while the policy sat on " <>
               "the configured one, and every denial check would still pass"
    end

    test "the pidfile is derived from the /30 the policy is keyed by" do
      {:ok, plan} = LaunchPlan.build({10, 0, 0, 8}, 9999, @confined)
      {_prog, args} = NodeLauncher.exec_from_plan(plan)

      # A pidfile named from anything but the source key can collide between
      # sandboxes, and two sandboxes sharing one would have the second overwrite
      # the first -- so the host would search the wrong process's children and
      # police the wrong namespace, or none.
      assert plan.pidfile == LaunchPlan.default_pidfile({10, 0, 0, 8})
      assert plan.pidfile in args
    end
  end
end
