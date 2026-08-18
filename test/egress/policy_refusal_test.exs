defmodule ExSandbox.Egress.PolicyRefusalTest do
  @moduledoc """
  A host that cannot supply an egress binding must **refuse the launch**
  (005 T060a5).

  ## Why this is the branch worth testing

  `install_policy/3` has an obvious path (a binding is available, the command is
  rewritten) and a dangerous one (no binding is available). The dangerous path
  is dangerous precisely because its wrong implementation looks *safer* than the
  right one: falling back to `--unshare-net` produces a sandbox that reaches
  **nothing**, which is maximally restrictive and passes every denial check in
  the network conformance group.

  That is 005 T060a5's named false pass, and it is the same shape as the trap
  this whole feature exists to close: a boundary permitting nothing is
  indistinguishable from a correct one under a suite that only tests denial. The
  census would report the group as demonstrated for a host that never policed
  anything.

  ⚠️ These tests do not launch. `launch/2` runs on Linux and nowhere else, so a
  launch-dependent test could not check this rule on the host most development
  happens on -- which is the arrangement `LaunchDecisionsTest` records as having
  let the context-discard defect survive.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Mechanism.Beam.NodeLauncher

  @allowed [{"api.example.com", 443}]

  @exec {"/usr/bin/systemd-run",
         [
           "--scope",
           "--unit=sandbox-x.scope",
           "setpriv",
           "--reuid=4242",
           "--regid=4242",
           "--clear-groups",
           "--no-new-privs",
           "bwrap",
           "--unshare-net",
           "--die-with-parent",
           "erlexec"
         ]}

  describe "when the host cannot supply a binding" do
    test "the launch is refused rather than downgraded" do
      exhausted = fn _allowed -> {:error, :pool_exhausted} end

      assert {:error, :mechanism_error} =
               NodeLauncher.install_policy(@exec, @allowed, exhausted),
             "a host with no binding must refuse: launching anyway gives the " <>
               "tenant a sandbox whose allowlist is not enforced"
    end

    test "no command is returned to launch, so there is nothing to fall back to" do
      # ⚠️ The specific defect this forbids: returning `{:ok, exec, nil, nil}` --
      # the *unpoliced* passthrough shape, which is a legitimate return for a
      # sandbox with no allowlist at all. Reused here it would launch the tenant
      # under `--unshare-net` while the caller believes a policy was installed.
      #
      # It would also be entirely silent: the passthrough clause is correct code
      # reached from the wrong branch, so no error, no log, and every denial
      # check still green.
      for reason <- [:pool_exhausted, {:still_registered, {10, 0, 0, 0}}, :nope] do
        result = NodeLauncher.install_policy(@exec, @allowed, fn _ -> {:error, reason} end)

        refute match?({:ok, _, _, _}, result),
               "a #{inspect(reason)} refusal produced a launchable command: #{inspect(result)}"
      end
    end

    test "the refusal does not depend on which allowlist was asked for" do
      # The binding is what is missing, not the policy -- so an allowlist that
      # would have been perfectly valid must not rescue the launch.
      for allowed <- [@allowed, [{"a.example.com", 80}, {"b.example.com", 443}]] do
        assert {:error, :mechanism_error} =
                 NodeLauncher.install_policy(@exec, allowed, fn _ -> {:error, :pool_exhausted} end)
      end
    end
  end

  describe "when the host can supply a binding" do
    test "a policed command is built, so the refusal above is not vacuous" do
      # ⚠️ Without this, every assertion above passes against an
      # `install_policy/3` that refuses unconditionally -- which would be a
      # sandbox nobody can launch, tested green.
      #
      # Uses the real `Binding.acquire/1` against the real supervised allocator:
      # a stubbed success would only prove the `with` chain forwards a tuple.
      case NodeLauncher.install_policy(@exec, @allowed) do
        {:ok, {prog, args}, binding, plan} ->
          assert is_binary(prog)
          assert is_list(args)
          refute is_nil(binding), "a policed launch must carry a binding to release"
          refute is_nil(plan)

          refute "--unshare-net" in [prog | args],
                 "the policed command must drop --unshare-net, or the tenant " <>
                   "sits in an empty namespace while the policy names another"

          on_exit(fn -> ExSandbox.Egress.Binding.release(binding) end)

        {:error, reason} ->
          flunk(
            "the real allocator refused a binding (#{inspect(reason)}), so the " <>
              "refusal tests above prove nothing -- they would pass against an " <>
              "install_policy/3 that never succeeds"
          )
      end
    end
  end
end
