defmodule ExSandbox.Hardening.BuildCommandTest do
  @moduledoc """
  The launch command implements an environment **allowlist** (005 T009,
  research R3, FR-004).

  ## Why `env -i` and not `:peer`'s `env` option

  Research R3 measured this rather than reasoning about it: a child spawned
  with `{env, [{"GRANTED", "yes"}]}` saw **76** variables, including
  `PLATFORM_SECRET`. `:peer`'s `env` merges with the inherited environment
  instead of replacing it, so using it produces a sandbox that receives
  everything the platform had plus the grant.

  `env -i` clears the environment first. It is the only construction here that
  implements FR-004's "receives only what is explicitly granted".

  ## Testing on a host where hardening is unavailable

  `build_command/2` refuses on this Darwin host, so the assertions below exercise
  the composition through the module's internals rather than its public
  refusal. That is a deliberate trade: the alternative is testing nothing about
  the command shape until Linux CI, and the `env -i` construction is exactly the
  part worth catching early — it is one word, easily dropped, and its absence
  produces a sandbox that works perfectly while leaking every platform secret.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Hardening.Linux

  defp sandbox(overrides \\ %{}) do
    defaults = %ExSandbox.Sandbox{
      id: "sb-#{System.unique_integer([:positive])}",
      owner_ref: "owner-1",
      template_ref: "tpl",
      memory_limit_mb: 256,
      cpu_limit: 500,
      disk_quota_mb: 1024
    }

    Map.merge(defaults, overrides)
  end

  # The composition is only reachable when every capability is present, which
  # this host does not satisfy. Rather than skip, the shape is asserted against
  # the same private construction the public function calls.
  defp built_args(sandbox, granted_env) do
    {:ok, {_cmd, args}} = Linux.compose_for_inspection(sandbox, granted_env)
    args
  end

  describe "the environment allowlist (FR-004)" do
    test "the command clears the environment with `env -i`" do
      args = built_args(sandbox(), [{"GRANTED", "yes"}])

      env_index = Enum.find_index(args, &(&1 == "env"))
      assert env_index, "the command does not invoke `env` at all"

      assert Enum.at(args, env_index + 1) == "-i",
             """
             `env` is invoked without `-i`, so the sandbox inherits the platform's
             environment. Research R3 measured 76 inherited variables including
             PLATFORM_SECRET under exactly this mistake.
             """
    end

    test "granted pairs are passed through" do
      args = built_args(sandbox(), [{"GRANTED", "yes"}, {"LANG", "C.UTF-8"}])

      assert "GRANTED=yes" in args
      assert "LANG=C.UTF-8" in args
    end

    test "BINDIR is always present" do
      # Without it the runtime cannot locate `erlexec` and the node never boots
      # (peer.erl:1214-1221). A fully empty environment is not a valid sandbox.
      args = built_args(sandbox(), [])

      assert Enum.any?(args, &String.starts_with?(&1, "BINDIR=")),
             "BINDIR is absent; the sandbox runtime cannot boot"
    end
  end

  describe "platform secrets are rejected, not passed through" do
    test "a platform-shaped key is refused" do
      for key <- ~w(DATABASE_URL SECRET_KEY_BASE AXONN_API_KEY RELEASE_COOKIE MY_PASSWORD) do
        assert {:error, {:forbidden_env, [^key]}} =
                 Linux.build_command(sandbox(), [{key, "value"}]),
               "#{key} was accepted into granted_env"
      end
    end

    test "rejection is by shape, not by exact name" do
      # `AXONN_DATABASE_URL` and `REPLICA_DATABASE_URL` are the same mistake as
      # `DATABASE_URL`. Matching exact names would let a rename defeat the check.
      assert {:error, {:forbidden_env, _}} =
               Linux.build_command(sandbox(), [{"REPLICA_DATABASE_URL", "x"}])
    end

    test "an ordinary variable is not refused" do
      # The negative control: without it, a check that refused everything would
      # pass every test above while making the sandbox unbootable.
      refute match?(
               {:error, {:forbidden_env, _}},
               Linux.build_command(sandbox(), [{"LANG", "C.UTF-8"}])
             )
    end
  end

  describe "the layers the contract composes" do
    test "resource caps, privilege drop, and confinement are all present" do
      args = built_args(sandbox(), [])

      assert Enum.any?(args, &String.starts_with?(&1, "MemoryMax=")), "no memory cap (FR-008)"
      assert Enum.any?(args, &String.starts_with?(&1, "CPUQuota=")), "no CPU cap (FR-008)"
      assert "setpriv" in args, "no privilege separation (FR-007)"
      assert "--clear-groups" in args, "groups are not cleared (FR-007)"
      assert "--unshare-net" in args, "no network restriction (FR-011)"
      assert "--ro-bind" in args, "no filesystem confinement (FR-010)"
    end

    test "swap is capped alongside memory" do
      # Without this the cap bounds RSS rather than consumption: a sandbox at
      # its limit swaps instead of being killed, and can still exhaust host IO.
      args = built_args(sandbox(), [])
      assert "MemorySwapMax=0" in args
    end
  end

  describe "invalid limits" do
    test "a missing limit is refused rather than defaulted" do
      # Defaulting would launch a sandbox under a cap nobody chose, and the
      # caller could not distinguish that from a cap they set.
      assert {:error, :invalid_limits} =
               validate_only(sandbox(%{memory_limit_mb: nil}))
    end
  end

  defp validate_only(sandbox) do
    # Reaches the limits check directly: on this host `build_command/2` refuses
    # for unavailability first, which would mask the case under test.
    Linux.validate_limits_for_inspection(sandbox)
  end
end
