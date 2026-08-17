defmodule ExSandbox.Mechanism.Beam.VerifyContractTest do
  @moduledoc """
  `verify_or_terminate/1` must accept what `verify_applied/1` actually returns.

  These two agreed on the failure shape and disagreed on the success shape, and
  nothing noticed: the pid being verified was `bwrap`'s outer supervisor, so the
  answer was always `{:error, :not_applied}` and the success clause was never
  executed. Every fake in the suite returned an error too. The first launch that
  genuinely verified its confinement crashed on the match.

  `verify_applied/1` is **not** part of the `ExSandbox.Hardening` behaviour, so
  there is no callback spec to catch a divergence here. Until it is, this test is
  the contract.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Mechanism.Beam.NodeLauncher

  defmodule VerifiesWithMap do
    @moduledoc false
    def available?, do: true
    def capabilities, do: %{}
    def build_command(_sandbox, _env), do: {:ok, {"/bin/true", []}}

    # The real Linux shape, from a measured run.
    def verify_applied(_os_pid) do
      {:ok,
       %{
         uid: 117_068,
         cgroup: "/docker/abc/system.slice/run-p497.scope",
         memory_limit_mb: 256,
         cpu_quota: 50.0,
         mount_confined: true,
         netns_separated: true,
         disk_quota_mb: :filesystem_enforced
       }}
    end
  end

  defmodule VerifiesWithBareOk do
    @moduledoc false
    def available?, do: true
    def capabilities, do: %{}
    def build_command(_sandbox, _env), do: {:ok, {"/bin/true", []}}
    def verify_applied(_os_pid), do: :ok
  end

  defp with_hardening(module, fun) do
    previous = Application.get_env(:ex_sandbox, :hardening_module)
    Application.put_env(:ex_sandbox, :hardening_module, module)

    try do
      fun.()
    after
      if previous do
        Application.put_env(:ex_sandbox, :hardening_module, previous)
      else
        Application.delete_env(:ex_sandbox, :hardening_module)
      end
    end
  end

  test "an {:ok, applied} map is a verified launch, not a crash" do
    with_hardening(VerifiesWithMap, fn ->
      # `peer` is never touched on the success path. If this clause regresses to
      # matching only `:ok`, the call raises CaseClauseError instead.
      assert :ok =
               NodeLauncher.verify_or_terminate(%{
                 os_pid: 1,
                 node: :"sandbox-test@host",
                 peer: :unused_on_success
               })
    end)
  end

  test "a bare :ok is still accepted, so existing fakes stay valid" do
    with_hardening(VerifiesWithBareOk, fn ->
      assert :ok =
               NodeLauncher.verify_or_terminate(%{
                 os_pid: 1,
                 node: :"sandbox-test@host",
                 peer: :unused_on_success
               })
    end)
  end
end
