defmodule ExSandbox.Mechanism.Beam.LaunchRefusalTest do
  @moduledoc """
  The launcher refuses when the host cannot confine (005 T020, R9).

  ## Runs everywhere, deliberately

  Every other test of this mechanism is Linux-gated, which leaves the *refusal*
  path — the one that protects misconfigured hosts — untested on the machine
  where most of this code is written. That is backwards: refusing correctly is
  the behaviour a developer is most likely to break and least likely to notice.

  These tests substitute the hardening module, so they assert the launcher's own
  decision rather than the host's capabilities, and run on Darwin and Linux
  alike.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  defmodule UnavailableHardening do
    @moduledoc false
    def available?, do: false
    def capabilities, do: %{setpriv: false, bwrap: false, cgroup_v2: false}
    def build_command(_sandbox, _env), do: {:error, :hardening_unavailable}
    def verify_applied(_os_pid), do: {:error, :not_applied}
  end

  defmodule LyingHardening do
    @moduledoc false
    # Probes green and builds a command, but confinement does not actually
    # apply -- the R9b shape, and the reason `verify_applied/1` exists.
    def available?, do: true
    def capabilities, do: %{setpriv: true, bwrap: true, cgroup_v2: true}
    # A command that boots a REAL node. `/bin/sh -c "exit 0"` would fail the
    # boot first, so `verify_applied/1` would never be reached and this test
    # would pass whether or not the launcher checks it -- verified by mutation.
    def build_command(_sandbox, _env) do
      {:ok, {:os.find_executable(~c"erl") |> to_string(), []}}
    end

    def verify_applied(_os_pid), do: {:error, :not_applied}
  end

  setup context do
    previous = Application.get_env(:ex_sandbox, :hardening_module)
    Application.put_env(:ex_sandbox, :hardening_module, context[:hardening])

    on_exit(fn ->
      if previous do
        Application.put_env(:ex_sandbox, :hardening_module, previous)
      else
        Application.delete_env(:ex_sandbox, :hardening_module)
      end
    end)

    :ok
  end

  defp sandbox do
    %Sandbox{
      id: "refuse-#{System.unique_integer([:positive])}",
      owner_ref: "owner-refuse",
      template_ref: "conformance-template",
      cpu_limit: 500,
      memory_limit_mb: 128,
      disk_quota_mb: 256
    }
  end

  @tag hardening: UnavailableHardening
  test "provisioning is refused when hardening is unavailable" do
    assert {:error, :mechanism_error} = Beam.provision(sandbox()),
           "a sandbox was provisioned on a host that cannot confine it (Principle II)"
  end

  @tag hardening: UnavailableHardening
  test "the refusal leaves no launched node behind" do
    assert {:error, _} = Beam.provision(sandbox())
    assert {:ok, []} = Beam.list_running()
  end

  describe "the verification gate itself" do
    # Tested directly rather than through `provision/1`. On a non-Linux host the
    # launch fails before this gate is reached, so a provision-level test passes
    # whether or not the gate exists -- confirmed by mutation, where deleting
    # the check left every test green. This exercises the gate on any host.
    setup do
      previous = Application.get_env(:ex_sandbox, :hardening_module)
      Application.put_env(:ex_sandbox, :hardening_module, LyingHardening)

      on_exit(fn ->
        if previous,
          do: Application.put_env(:ex_sandbox, :hardening_module, previous),
          else: Application.delete_env(:ex_sandbox, :hardening_module)
      end)

      :ok
    end

    test "terminates the node and reports an error when confinement did not apply" do
      peer = spawn(fn -> Process.sleep(:infinity) end)
      launched = %{os_pid: 1, node: :"unverified@127.0.0.1", peer: peer}

      assert {:error, :mechanism_error} =
               ExSandbox.Mechanism.Beam.NodeLauncher.verify_or_terminate(launched),
             """
             a node whose hardening did not apply was accepted.

             It is running, and everything above this layer now believes it is
             confined -- the one outcome worse than a failed launch.
             """

      refute Process.alive?(peer),
             "the unverified node was reported as an error but left running"
    end
  end

  @tag hardening: LyingHardening
  test "a node that launches but fails verification is refused, not returned" do
    # The dangerous case: hardening claimed to be available, the command built,
    # the process started -- and confinement did not apply. Returning `:ok` here
    # would report a contained sandbox that is running unconfined.
    assert {:error, :mechanism_error} = Beam.provision(sandbox()),
           """
           provision succeeded despite verify_applied/1 reporting :not_applied.

           This is the R9b failure shape: a cap requested, silently lost, and
           reported as enforced.
           """

    assert {:ok, []} = Beam.list_running(),
           "a node that failed verification was left running"
  end
end
