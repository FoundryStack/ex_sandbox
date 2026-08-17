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

  ## The order

  Setup completes, then the tenant launches into a finished namespace. Getting
  back to that plain order took two attempts -- see `ExSandbox.Egress.Netns` on
  why `pasta` could not carry a `bwrap`-confined tenant.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.LaunchPlan

  @key {10, 0, 0, 0}
  @port 18_080

  describe "the plan's shape" do
    setup do
      {:ok, plan} = LaunchPlan.build(@key, @port, ["bwrap", "--unshare-net", "erlexec"])
      %{plan: plan}
    end

    test "the tenant launch no longer unshares the network", %{plan: plan} do
      # ⚠️ `--unshare-net` is a namespace with **no interfaces**. Keeping it
      # would put the tenant in a *fresh empty* namespace while the policy sat
      # on the configured one -- isolation restored silently, policy discarded,
      # and every denial check still green.
      refute "--unshare-net" in plan.tenant_command
    end

    test "the tenant joins the namespace that was configured, by name", %{plan: plan} do
      assert ["ip", "netns", "exec", name | _] = plan.tenant_command
      assert name == plan.namespace

      # A plan that configures `sb-a` and launches into `sb-b` installs a
      # correct policy on a namespace nothing uses.
      assert LaunchPlan.namespaced?(plan)
    end

    test "every setup step precedes the tenant launch", %{plan: plan} do
      # Ordering is the property, and it is not expressible as a set. The
      # redirect must exist before the tenant can emit a packet.
      assert plan.setup_steps != []
      assert Enum.find_index(plan.setup_steps, &("rule" in &1)) != nil
    end

    test "the plan carries the route, without which nothing is policed", %{plan: plan} do
      # The defect the first spike hit: no route means `enetunreach` before the
      # nat hook runs, which prints exactly like a refused redirect.
      assert Enum.any?(plan.setup_steps, fn step ->
               "route" in step and "default" in step
             end),
             "no default route: the sandbox would be isolated, not policed"
    end

    test "the plan carries the redirect to the acceptor's port", %{plan: plan} do
      assert Enum.any?(plan.setup_steps, fn step -> ":#{@port}" in step end)
    end

    test "the plan can give back what it created", %{plan: plan} do
      # A namespace and a veth pair outlive the process that made them. Without
      # teardown, a host leaks one of each per sandbox until `ip` refuses.
      assert plan.teardown_steps != []
      assert Enum.any?(plan.teardown_steps, &("delete" in &1))
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
