defmodule ExSandbox.Mechanism.Beam.IsolationEnvTest do
  @moduledoc """
  A sandbox cannot read the platform's environment (005 T028, `FR-004`, R3).

  ## Why this test is the direct test of R3

  `:peer`'s `env` option is **additive**: it adds variables to what the origin
  already has rather than replacing them. Setting `env: []` therefore grants
  nothing *and clears nothing* — a sandbox launched that way inherits
  `DATABASE_URL` and `SECRET_KEY_BASE` in full.

  `env -i`, inside the hardening command, is what actually clears it. That makes
  this test the one that distinguishes the two, and a failure here means the
  hardening wrapper was dropped and `:peer`'s option was trusted.
  """
  use ExUnit.Case, async: false

  @moduletag :isolation

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  # Set on the *origin* before launching. If confinement works these never reach
  # the sandbox; if `env -i` were dropped they would arrive verbatim, because
  # that is precisely what inheritance means.
  @platform_secrets %{
    "DATABASE_URL" => "postgres://platform:hunter2@localhost:5434/axonn_dev",
    "SECRET_KEY_BASE" => "sk_test_" <> String.duplicate("z", 48),
    "SANDBOX_CREDENTIAL_KEY" => Base.encode64(:crypto.strong_rand_bytes(32))
  }

  setup do
    previous = for {k, _} <- @platform_secrets, into: %{}, do: {k, System.get_env(k)}
    for {k, v} <- @platform_secrets, do: System.put_env(k, v)

    on_exit(fn ->
      for {k, v} <- previous do
        if v, do: System.put_env(k, v), else: System.delete_env(k)
      end
    end)

    :ok
  end

  defp sandbox do
    %Sandbox{
      id: "env-#{System.unique_integer([:positive])}",
      owner_ref: "owner-env",
      template_ref: "conformance-template",
      cpu_limit: 500,
      memory_limit_mb: 128,
      disk_quota_mb: 256
    }
  end

  test "tenant code cannot read any platform secret from its environment" do
    sb = sandbox()
    assert {:ok, provisioned} = Beam.provision(sb)
    on_exit(fn -> Beam.destroy(provisioned) end)

    node = String.to_atom(provisioned.mechanism_ref)

    # The sandbox reports its *entire* environment. Asking it for specific keys
    # would only prove those keys are absent; the whole environment is what
    # shows nothing else leaked either.
    environment = :erpc.call(node, :os, :getenv, [], 10_000)
    rendered = Enum.map_join(environment, "\n", &to_string/1)

    for {key, value} <- @platform_secrets do
      refute rendered =~ key,
             "sandbox inherited the platform variable #{key} -- `env -i` was not applied (R3)"

      refute rendered =~ value,
             "sandbox inherited the VALUE of #{key}; the secret itself crossed the boundary"
    end
  end

  test "the sandbox's environment is empty apart from what the launch grants" do
    sb = sandbox()
    assert {:ok, provisioned} = Beam.provision(sb)
    on_exit(fn -> Beam.destroy(provisioned) end)

    node = String.to_atom(provisioned.mechanism_ref)
    environment = :erpc.call(node, :os, :getenv, [], 10_000)

    # Asserted as a bound rather than exact equality: the ERTS startup adds a
    # handful of its own (`HOME`, `PATH`, `ROOTDIR`) and pinning the exact set
    # would make this test fail on an OTP upgrade for reasons unrelated to
    # isolation. A platform environment would be dozens of entries.
    assert length(environment) < 15,
           "sandbox environment has #{length(environment)} entries, which looks inherited: " <>
             inspect(environment)
  end
end
