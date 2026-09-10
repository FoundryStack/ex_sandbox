defmodule ExSandbox.GettingStartedDocTest do
  @moduledoc """
  `docs/getting-started.md`, executed.

  Every code block in that tutorial is run here in the order it is written, and
  every `#=>` comment is asserted. A tutorial is the one document a reader
  copies verbatim, so an example that does not run is worse than no example --
  and the only way to know it runs is to run it.

  ⚠️ It has already earned that. Writing it against a real daemon is what
  surfaced `docker exec` reporting "executable file not found" on **stdout**
  with an exit status of 126, which the mechanism was classifying as a command
  that ran and failed. See `ExSandbox.Mechanism.DockerExecuteTest`.

  ⚠️ Tagged `:docker`, so it is **absent** rather than green on a host with no
  container runtime -- see `ExSandbox.Mechanism.DockerTagTest`. The capability
  and refusal steps are asserted in a shape that holds on any host, because the
  tutorial's own point is that the answer differs by host.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Capability
  alias ExSandbox.Mechanism.Docker
  alias ExSandbox.Sandbox

  @moduletag :docker

  setup do
    id = "getting-started-#{System.unique_integer([:positive])}"
    on_exit(fn -> destroy_by_label(id) end)
    {:ok, id: id}
  end

  describe "step 2 -- ask the host what it can do" do
    test "every known capability is reported, with a name and a boolean" do
      reports = ExSandbox.capabilities()

      assert length(reports) == 9

      for %Capability{} = report <- reports do
        assert is_atom(report.name)
        assert is_boolean(report.available?)
      end

      names = Enum.map(reports, & &1.name)

      # The nine the tutorial prints, in the order it prints them.
      assert names == [
               :resource_limits,
               :filesystem_confinement,
               :privilege_separation,
               :network_restriction,
               :disk_quota,
               :process_separation,
               :memory_cap,
               :cpu_cap,
               :time_budget
             ]
    end

    test "an unavailable capability says what is missing, not merely that something is" do
      unavailable = Enum.reject(ExSandbox.capabilities(), & &1.available?)

      for report <- unavailable do
        assert is_binary(report.detail) and report.detail != "",
               "#{report.name} reports unavailable with no detail; the tutorial promises one"
      end
    end
  end

  describe "step 3 -- watch it refuse" do
    @tag :tmp_dir
    test "a mechanism whose required capabilities are missing refuses, and names them", %{id: id} do
      # ⚠️ Asserted conditionally on purpose. On a fully capable Linux host the
      # BEAM mechanism does NOT refuse -- and the tutorial says so, because the
      # refusal is a fact about the host rather than about the library. Pinning
      # the refusal unconditionally would fail on the one host where everything
      # works.
      sandbox = %Sandbox{id: id, owner_ref: "tenant-42", template_ref: "alpine:3"}

      case ExSandbox.provision(ExSandbox.Mechanism.Beam, sandbox) do
        {:error, {:capability_unavailable, missing}} ->
          assert missing != []
          assert Enum.all?(missing, &match?(%Capability{available?: false}, &1))

        {:ok, provisioned} ->
          ExSandbox.destroy(ExSandbox.Mechanism.Beam, provisioned)
      end
    end
  end

  describe "steps 4 to 7 -- the lifecycle the tutorial walks" do
    test "provision creates without starting, and assigns an opaque handle", %{id: id} do
      {:ok, provisioned} = ExSandbox.provision(Docker, tutorial_sandbox(id))

      assert is_binary(provisioned.mechanism_ref)
      assert {:ok, :provisioned} = ExSandbox.status(Docker, provisioned)

      :ok = ExSandbox.destroy(Docker, provisioned)
    end

    test "the whole walk, in the order the tutorial writes it", %{id: id} do
      {:ok, provisioned} = ExSandbox.provision(Docker, tutorial_sandbox(id))
      {:ok, running} = ExSandbox.start(Docker, provisioned)

      assert {:ok, :running} = ExSandbox.status(Docker, running)

      # Step 5, the successful run.
      assert {:ok, completion} =
               ExSandbox.execute(Docker, running, {"sh", ["-c", "echo hello from $(hostname)"]})

      assert completion.exit_status == 0
      assert completion.stdout =~ "hello from"
      assert completion.stderr == ""
      refute completion.truncated?

      # Step 5, the three returns.
      assert {:ok, %{exit_status: 3}} =
               ExSandbox.execute(Docker, running, {"sh", ["-c", "exit 3"]})

      assert {:error, {:could_not_run, reason}} =
               ExSandbox.execute(Docker, running, {"no-such-binary", []})

      assert reason =~ "executable file not found"

      # Step 5, streaming output.
      parent = self()

      {:ok, _} =
        ExSandbox.execute(Docker, running, {"sh", ["-c", "echo one; echo two"]},
          on_output: fn chunk -> send(parent, {:chunk, chunk}) end
        )

      assert_received {:chunk, {:stdout, _}}

      # Step 6.
      assert {:ok, usage} = ExSandbox.usage(Docker, running)
      assert is_integer(usage.memory_mb)
      assert is_integer(usage.cpu_millicores)

      assert {:ok, refs} = ExSandbox.list_running(Docker)
      assert running.mechanism_ref in refs

      # Step 5's aside: a sandbox naming no service_port is given no address.
      assert {:ok, nil} = ExSandbox.address(Docker, running)

      # Step 7.
      {:ok, stopped} = ExSandbox.stop(Docker, running)
      assert {:ok, :stopped} = ExSandbox.status(Docker, stopped)

      assert :ok = ExSandbox.destroy(Docker, stopped)
      assert {:ok, :absent} = ExSandbox.status(Docker, stopped)

      # And the sentence about idempotence, which a recovery sweep depends on.
      assert :ok = ExSandbox.destroy(Docker, stopped)
    end
  end

  defp tutorial_sandbox(id) do
    %Sandbox{
      id: id,
      owner_ref: "tenant-42",
      template_ref: "alpine:3",
      memory_limit_mb: 256,
      cpu_limit: 500
    }
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
end
