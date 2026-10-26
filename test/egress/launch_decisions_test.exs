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
      # ⚠️ Asserted as a RELATIONSHIP to the plan, never as a literal name: a
      # literal pinned the wrong ordering twice before.
      assert [^prog | _] = plan.tenant_command

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

      for required <- ["systemd-run", "setpriv", "bwrap", "erlexec"] do
        assert required in basenames,
               "#{required} must survive the rewrite; got #{inspect(basenames)}"
      end

      order = fn name -> Enum.find_index(basenames, &(&1 == name)) end

      assert order.("systemd-run") < order.("setpriv"),
             "the scope must stay outermost or its caps are never applied"

      assert order.("setpriv") < order.("bwrap"),
             "the drop must precede bwrap"

      assert "--unshare-net" in full,
             "the tenant's namespace must hold only loopback (D6)"
    end
  end
end
