defmodule ExSandbox.Mechanism.DockerLifecycleTest do
  @moduledoc """
  The lifecycle callbacks against a real daemon.

  ⚠️ Every test here is tagged `:docker` and is therefore **absent** on a host
  with no container runtime -- see `ExSandbox.Mechanism.DockerTagTest` for why
  an absent group is safer than a green one, and for the canary that makes a
  missed exclusion fail rather than pass.

  ⚠️ `async: false`. `list_running/0` filters on a label rather than on a
  sandbox id, so two of these running concurrently would see each other's
  containers -- and the test that asserts "only mine" would fail for a reason
  that has nothing to do with the filter it is checking.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Mechanism.Docker
  alias ExSandbox.Sandbox

  @moduletag :docker

  setup do
    sandbox = %Sandbox{
      id: "docker-lifecycle-#{System.unique_integer([:positive])}",
      owner_ref: "test",
      template_ref: Docker.default_image()
    }

    # Registered before provisioning rather than after: a test that fails
    # between `docker create` and its own cleanup would otherwise leave a
    # container behind on the developer's machine, and the next run's
    # `list_running/0` assertions would inherit it.
    on_exit(fn -> destroy_by_label(sandbox.id) end)

    {:ok, sandbox: sandbox}
  end

  defp destroy_by_label(id) do
    {output, 0} =
      System.cmd("docker", ["ps", "-aq", "--filter", "label=ex_sandbox.sandbox_id=#{id}"],
        stderr_to_stdout: true
      )

    for ref <- String.split(output, "\n", trim: true) do
      System.cmd("docker", ["rm", "--force", ref], stderr_to_stdout: true)
    end
  end

  describe "provision/1 and destroy/1" do
    test "provision returns the container id as mechanism_ref", %{sandbox: sandbox} do
      assert {:ok, provisioned} = Docker.provision(sandbox)
      assert is_binary(provisioned.mechanism_ref)

      assert Regex.match?(~r/^[0-9a-f]{12,64}$/, provisioned.mechanism_ref),
             "mechanism_ref must be the container id, not the command's whole output: " <>
               inspect(provisioned.mechanism_ref)

      # Created, not started: `provision/1` creates resources without running
      # them, and a mechanism that starts here makes `start/1` unobservable.
      assert {:ok, :provisioned} = Docker.status(provisioned)
    end

    test "destroy is idempotent", %{sandbox: sandbox} do
      {:ok, provisioned} = Docker.provision(sandbox)

      assert :ok = Docker.destroy(provisioned)

      assert :ok = Docker.destroy(provisioned),
             "a second destroy must return :ok -- `003-FR-013`: a crash-recovery sweep " <>
               "destroys whatever the record holds, and half of it is already gone"

      assert {:ok, :absent} = Docker.status(provisioned)
    end

    test "destroying a sandbox that was never provisioned is :ok", %{sandbox: sandbox} do
      assert :ok = Docker.destroy(sandbox)
    end
  end

  describe "start/1 and stop/1" do
    test "a stopped sandbox is still present", %{sandbox: sandbox} do
      {:ok, provisioned} = Docker.provision(sandbox)

      assert {:ok, started} = Docker.start(provisioned)
      assert {:ok, :running} = Docker.status(started)

      assert {:ok, stopped} = Docker.stop(started)

      # ⚠️ `stop/1` "leaves its resources intact". The distinction from
      # `destroy/1` is the whole callback: a stop that removes the container
      # makes a restart impossible and turns a pause into data loss.
      assert {:ok, :stopped} = Docker.status(stopped)
      refute match?({:ok, :absent}, Docker.status(stopped))

      assert {:ok, restarted} = Docker.start(stopped)
      assert {:ok, :running} = Docker.status(restarted)
    end

    test "starting or stopping an unprovisioned sandbox refuses", %{sandbox: sandbox} do
      assert {:error, :not_provisioned} = Docker.start(sandbox)
      assert {:error, :not_provisioned} = Docker.stop(sandbox)
    end
  end

  describe "status/1" do
    test "each state a test can reach maps to one status atom", %{sandbox: sandbox} do
      # ⚠️ `:starting` and `:stopping` are deliberately absent from this list.
      # Docker's `restarting` and `removing` are transient by definition, and a
      # test that raced to observe one would fail intermittently for a reason
      # unrelated to the mapping -- so they are mapped in code and not claimed
      # as verified here.
      {:ok, provisioned} = Docker.provision(sandbox)
      assert {:ok, :provisioned} = Docker.status(provisioned)

      {:ok, started} = Docker.start(provisioned)
      assert {:ok, :running} = Docker.status(started)

      {_output, 0} =
        System.cmd("docker", ["pause", started.mechanism_ref], stderr_to_stdout: true)

      # A paused container is not running and its resources are intact, which is
      # what `:stopped` means to a caller. The status type has no `:paused`, and
      # inventing one is a breaking change to every mechanism; reporting
      # `:running` would be worse -- a caller would exec into it and hang.
      assert {:ok, :stopped} = Docker.status(started)

      {_output, 0} =
        System.cmd("docker", ["unpause", started.mechanism_ref], stderr_to_stdout: true)

      {:ok, stopped} = Docker.stop(started)
      assert {:ok, :stopped} = Docker.status(stopped)

      :ok = Docker.destroy(stopped)
      assert {:ok, :absent} = Docker.status(stopped)
    end

    test "an unreachable daemon is :unknown, never :absent", %{sandbox: sandbox} do
      {:ok, provisioned} = Docker.provision(sandbox)

      # ⚠️ The sandbox genuinely exists throughout this test. Pointing the client
      # at a dead socket removes our ability to *see* it, which is precisely the
      # case `003-FR-024` keeps distinct: read as `:absent`, a caller destroys
      # the record of a container that is still running.
      previous = System.get_env("DOCKER_HOST")
      System.put_env("DOCKER_HOST", "unix:///tmp/ex-sandbox-no-such-daemon.sock")

      try do
        assert {:ok, :unknown} = Docker.status(provisioned)
      after
        if previous,
          do: System.put_env("DOCKER_HOST", previous),
          else: System.delete_env("DOCKER_HOST")
      end

      assert {:ok, :provisioned} = Docker.status(provisioned),
             "the daemon is reachable again, so the sandbox must be visible again"
    end
  end

  describe "list_running/0" do
    test "returns this mechanism's running containers and nothing else", %{sandbox: sandbox} do
      {:ok, provisioned} = Docker.provision(sandbox)
      {:ok, started} = Docker.start(provisioned)

      # An unlabelled container, started the same way any other tool on this
      # machine might have started one. `list_running/0` adopting it would mean
      # a reconciliation sweep later destroys somebody else's work.
      {stranger, 0} =
        System.cmd("docker", ["run", "-d", Docker.default_image(), "tail", "-f", "/dev/null"],
          stderr_to_stdout: true
        )

      stranger = String.trim(stranger)
      on_exit(fn -> System.cmd("docker", ["rm", "--force", stranger], stderr_to_stdout: true) end)

      assert {:ok, running} = Docker.list_running()

      assert Enum.any?(running, &String.starts_with?(started.mechanism_ref, &1)),
             "the sandbox's own ref is missing from #{inspect(running)}"

      refute Enum.any?(running, &String.starts_with?(stranger, &1)),
             "an unlabelled container was claimed by this mechanism"
    end
  end

  describe "usage/1" do
    test "reports CPU and memory, and no disk figure", %{sandbox: sandbox} do
      {:ok, provisioned} = Docker.provision(sandbox)
      {:ok, started} = Docker.start(provisioned)

      assert {:ok, usage} = Docker.usage(started)

      assert Map.has_key?(usage, :cpu_millicores)
      assert Map.has_key?(usage, :memory_mb)

      # ⚠️ D4. `--storage-opt size` is accepted and ignored on overlayfs, so
      # nothing bounds this sandbox's disk use. A figure reported beside a quota
      # that does not hold invites a caller to act on it as though something
      # would stop the growth it measures.
      refute Map.has_key?(usage, :disk_mb)
    end
  end
end
