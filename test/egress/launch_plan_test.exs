defmodule ExSandbox.Egress.LaunchPlanTest do
  @moduledoc """
  The ordered steps that put a tenant process inside a policed namespace
  (005 T060a3).

  ## The wrong implementation this is written against

  One that lets the tenant keep running when the redirect failed to install. A
  sandbox that runs having skipped its redirect is unpoliced, while every
  denial check still passes -- because the checks probe destinations it cannot
  reach for unrelated reasons.

  ⚠️ The dangerous direction here is not "the tenant fails to start". It is
  "the tenant starts anyway".

  ## Why the order inverted

  The plan no longer configures a namespace before launch. It cannot: `pasta`
  creates the namespace *by starting the tenant in it*, so the policy is
  installed afterwards, against a running tenant's pid. See the module.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.LaunchPlan

  @key {10, 0, 0, 0}
  @port 18_080

  # ⚠️ Mirrors what `Hardening.Linux.compose/3` actually emits, `setpriv` group
  # included. The earlier fixture omitted it, and that omission is why the
  # unbootable ordering survived every one of these tests: a plan built from a
  # command with no privilege drop cannot exhibit the defect that only appears
  # when a drop lands inside pasta's namespace. `LaunchDecisionsTest` pins the
  # fixture against the real composer so it cannot drift back.
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

  describe "the plan's shape" do
    setup do
      {:ok, plan} = LaunchPlan.build(@key, @port, @confined)
      %{plan: plan}
    end

    test "the tenant launch no longer unshares the network", %{plan: plan} do
      # ⚠️ `--unshare-net` is a namespace with **no interfaces**. Keeping it
      # would put the tenant in a *fresh empty* namespace while `pasta`
      # configured a different one -- isolation restored silently, policy
      # discarded, and every denial check still green.
      refute "--unshare-net" in plan.tenant_command
      refute "--unshare-net" in plan.pasta_command
    end

    test "pasta runs the tenant rather than the tenant joining a namespace", %{plan: plan} do
      # The inversion. An earlier design had the tenant `ip netns exec` into a
      # pre-built namespace; `pasta` cannot attach to one made that way
      # (measured: `Failed to join network namespace: Permission denied`).
      pasta = Enum.find(plan.pasta_command, &(Path.basename(&1) == "pasta"))
      assert pasta, "the command must run the tenant under pasta"

      assert String.starts_with?(pasta, "/"),
             "must be a path :peer can spawn, not a bare name"

      tenant = plan.pasta_command |> Enum.drop_while(&(&1 != "--")) |> Enum.drop(1)
      assert List.last(tenant) == List.last(plan.tenant_command)
    end

    test "pasta is inserted AFTER the privilege drop, not wrapped around it", %{plan: plan} do
      # ⚠️ The whole of T060a4e. Wrapping the command in `pasta` puts `setpriv`
      # inside pasta's spawn-mode userns, whose `uid_map` is empty -- so
      # `setresuid` fails with EINVAL for any uid and the tenant never boots.
      # Measured; it is not a theoretical ordering preference.
      pasta_at = Enum.find_index(plan.pasta_command, &(Path.basename(&1) == "pasta"))
      setpriv_at = Enum.find_index(plan.pasta_command, &(&1 == "setpriv"))
      scope_at = Enum.find_index(plan.pasta_command, &(Path.basename(&1) == "systemd-run"))

      assert scope_at < setpriv_at,
             "systemd-run must stay outermost or the scope's caps are never applied"

      assert setpriv_at < pasta_at,
             "setpriv must run BEFORE pasta or setresuid fails inside an empty uid_map"
    end

    test "pasta's --runas names the same uid setpriv drops to", %{plan: plan} do
      # A mismatch here does not fail loudly: pasta would map a uid the tenant
      # never becomes, and the namespace comes up owned by nobody in particular.
      # ⚠️ `--runas 0` after a drop is measured to fail outright, and `--runas
      # 0:0` as root **hangs** rather than erroring -- a launch that never
      # returns is worse than one that fails.
      assert "--reuid=4242" in plan.pasta_command

      runas_value =
        plan.pasta_command
        |> Enum.drop_while(&(&1 != "--runas"))
        |> Enum.at(1)

      assert runas_value == "4242:4242"
    end

    test "a command with no privilege drop is refused rather than prefixed" do
      # ⚠️ Falling back to the wrapping shape would reintroduce the unbootable
      # ordering on exactly the hosts where the split failed -- silently. And a
      # command that never drops privilege launches its tenant as root, which is
      # worse than launching nothing.
      no_drop = ["/usr/bin/systemd-run", "--scope", "bwrap", "--unshare-net", "erlexec"]
      assert {:error, :no_privilege_drop} = LaunchPlan.build(@key, @port, no_drop)
    end

    test "the pidfile pasta writes is the one the plan names", %{plan: plan} do
      # The holder is found by searching this pid's children, so a plan whose
      # pidfile disagrees with pasta's would search the wrong process -- and
      # find nothing, which reads as an architectural refusal.
      assert plan.pidfile in plan.pasta_command
    end

    test "the redirect targets the pid it is given, not pasta's own", %{plan: plan} do
      # ⚠️ THE trap on this path. `pasta -P` records pasta's HOST-side pid; the
      # tenant runs in a child. `nsenter -t <pasta pid> -n nft ...` installs the
      # sandbox's redirect into the HOST namespace: it succeeds, warns about
      # nothing, and leaves the tenant unpoliced.
      for step <- LaunchPlan.redirect_steps(plan, 4242) do
        assert Enum.take(step, 4) == ["nsenter", "-t", "4242", "-n"]
      end
    end

    test "the redirect carries the acceptor's port", %{plan: plan} do
      steps = LaunchPlan.redirect_steps(plan, 4242)
      assert Enum.any?(steps, fn step -> ":#{@port}" in step end)
    end

    test "the holder pid cannot be omitted", %{plan: plan} do
      # ⚠️ Deliberately an argument rather than a struct field. The holder does
      # not exist when the plan is built -- running the plan is what creates the
      # namespace it names. A `nil` field would let redirect steps be composed
      # against nothing and quietly target the wrong namespace.
      refute Map.has_key?(plan, :holder_pid)
      assert_raise FunctionClauseError, fn -> LaunchPlan.redirect_steps(plan, nil) end
    end
  end

  describe "refusal" do
    test "a tenant command that never unshared the network is refused" do
      # ⚠️ Not a no-op. If the caller hands over a command with no
      # `--unshare-net`, the assumption this module is built on -- that it is
      # *replacing* an existing confinement -- is false, and silently returning
      # a plan would attach a policy to a launch that may confine nothing.
      assert {:error, :no_network_confinement} =
               LaunchPlan.build(@key, @port, ["bwrap", "erlexec"])
    end

    test "port zero is refused rather than redirected into the void" do
      # An acceptor that failed to bind reports port 0. Redirecting to it
      # produces a namespace whose traffic goes nowhere -- indistinguishable,
      # from inside, from a correctly denied destination.
      assert {:error, :no_pool_port} =
               LaunchPlan.build(@key, 0, ["bwrap", "--unshare-net", "erlexec"])
    end
  end
end
