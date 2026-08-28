defmodule ExSandbox.Mechanism.DockerExecuteTest do
  @moduledoc """
  `execute/3` against a real daemon, and the two caps it runs under.

  ⚠️ The cap tests **breach the cap and watch it hold**. A test that asserted
  `--memory` was passed to `docker` would have verified nothing: `005` R9b
  measured `taskpolicy -m` being accepted and silently lost across an exec,
  allocating 300 MB under a nominal 100 MB cap and exiting 0, and D4 measured
  `--storage-opt size` being accepted and ignored on this very host. A flag
  reaching the command line is not evidence that a limit exists.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Mechanism.Docker
  alias ExSandbox.Sandbox

  @moduletag :docker

  # Long enough that a quarter-core cap is unmistakable against an uncapped run,
  # short enough that two of them do not dominate the suite.
  @spin_seconds 3

  defp sandbox(overrides \\ []) do
    struct!(
      %Sandbox{
        id: "docker-exec-#{System.unique_integer([:positive])}",
        owner_ref: "test",
        template_ref: Docker.default_image()
      },
      overrides
    )
  end

  defp running(overrides \\ []) do
    {:ok, provisioned} = Docker.provision(sandbox(overrides))
    {:ok, started} = Docker.start(provisioned)
    on_exit(fn -> Docker.destroy(started) end)
    started
  end

  describe "the three returns are three different facts" do
    test "a command that succeeds returns its output" do
      assert {:ok, completion} = Docker.execute(running(), {"echo", ["hello"]}, [])

      assert completion.exit_status == 0
      assert String.trim(completion.stdout) == "hello"
      assert completion.stderr == ""
      refute completion.truncated?
    end

    test "a non-zero exit is a result, not an error" do
      assert {:ok, completion} =
               Docker.execute(running(), {"sh", ["-c", "echo out; echo err >&2; exit 3"]}, [])

      # ⚠️ `{:ok, _}` with status 3. The command ran; what it decided is its own
      # business. Mapping this to `{:error, _}` collapses "did not run" into
      # "ran and failed", which `008-FR-016` keeps apart.
      assert completion.exit_status == 3
      assert String.trim(completion.stdout) == "out"
      assert String.trim(completion.stderr) == "err"
    end

    test "stdout and stderr stay separate" do
      assert {:ok, completion} =
               Docker.execute(running(), {"sh", ["-c", "echo one; echo two >&2"]}, [])

      assert String.trim(completion.stdout) == "one"
      assert String.trim(completion.stderr) == "two"
    end

    test "a destroyed sandbox could not run the command, and says so" do
      started = running()
      :ok = Docker.destroy(started)

      assert {:error, {:could_not_run, reason}} = Docker.execute(started, {"echo", ["hi"]}, [])

      assert is_binary(reason) and reason =~ "No such container",
             "the refusal must carry the daemon's own reason: #{inspect(reason)}"
    end

    test "a sandbox that was never provisioned could not run the command" do
      assert {:error, {:could_not_run, :not_provisioned}} =
               Docker.execute(sandbox(), {"echo", ["hi"]}, [])
    end
  end

  describe "output capture" do
    test "a single line longer than 256 bytes arrives uncorrupted" do
      # ⚠️ 256 is not arbitrary: `015` R17 measured `MuonTrap`'s `:logger_fun`
      # corrupting output past a 256-byte line buffer. This mechanism reads byte
      # ranges and never frames lines, and this test is what keeps it that way.
      line = String.duplicate("abcdefghij", 200)

      assert {:ok, completion} =
               Docker.execute(running(), {"sh", ["-c", "printf %s '#{line}'"]}, [])

      assert completion.stdout == line
      assert byte_size(completion.stdout) == 2000
    end

    test "on_output receives chunks, and the chunks reassemble into the capture" do
      line = String.duplicate("z", 5000)
      parent = self()

      assert {:ok, completion} =
               Docker.execute(running(), {"sh", ["-c", "printf %s '#{line}'; echo e >&2"]},
                 on_output: fn chunk -> send(parent, {:chunk, chunk}) end
               )

      chunks = collect_chunks()

      assert chunks != [], "no chunk was delivered to the sink"

      assert chunks
             |> Enum.filter(&match?({:stdout, _}, &1))
             |> Enum.map_join("", &elem(&1, 1)) == completion.stdout

      assert chunks
             |> Enum.filter(&match?({:stderr, _}, &1))
             |> Enum.map_join("", &elem(&1, 1)) == completion.stderr
    end

    test "output past the capture limit is truncated and says it was" do
      assert {:ok, completion} =
               Docker.execute(
                 running(),
                 {"sh", ["-c", "printf %s $(head -c 4000 /dev/zero | tr '\\0' 'x')"]},
                 limit_bytes: 100
               )

      assert byte_size(completion.stdout) == 100

      assert completion.truncated?,
             "a silently cut log is how a real error disappears from a diagnosis"
    end
  end

  describe "the memory cap, breached" do
    test "an allocation past --memory is stopped by the kernel" do
      capped = running(memory_limit_mb: 64)

      # `tail /dev/zero` reads without bound and buffers what it reads. Under a
      # 64 MB cap the cgroup OOM killer takes it; without one it would run until
      # the host gave out.
      result = Docker.execute(capped, {"tail", ["/dev/zero"]}, timeout: 30_000)

      assert {:error, {:limit_exceeded, :memory}} = result,
             """
             A 64 MB-capped sandbox was asked to allocate without bound and the run \
             was not attributed to the cap: #{inspect(result)}.

             Remove `--memory` from `limit_args/1` and this test must go red. If it \
             stays green with the flag gone, it is measuring something other than the cap.
             """

      # The cap stopped the process, not the sandbox. A memory limit that takes
      # the container with it is a limit that costs the caller its workspace.
      assert {:ok, :running} = Docker.status(capped)
      assert {:ok, %{exit_status: 0}} = Docker.execute(capped, {"true", []}, [])
    end

    test "the same allocation under no cap is not attributed to one" do
      # ⚠️ The control. Without it, an implementation that returned
      # `:limit_exceeded` for every 137 would pass the test above while
      # attributing an operator's `kill -9` to a memory cap.
      uncapped = running()

      {:ok, %{exit_status: status}} =
        Docker.execute(uncapped, {"sh", ["-c", "kill -9 $$"]}, timeout: 30_000)

      assert status == 137,
             "a SIGKILL from something other than the cgroup must arrive as its own status"
    end
  end

  describe "the CPU cap, throttled" do
    test "a busy loop under --cpus consumes materially less CPU than uncapped" do
      capped = running(cpu_limit: 250)
      uncapped = running()

      capped_usec = spin_and_measure(capped)
      uncapped_usec = spin_and_measure(uncapped)

      window_usec = @spin_seconds * 1_000_000

      assert capped_usec < uncapped_usec / 2,
             """
             A 250-millicore sandbox burned #{capped_usec}µs of CPU in a \
             #{@spin_seconds}s window; an uncapped one on the same host burned \
             #{uncapped_usec}µs. The cap is not throttling.

             Remove `--cpus` from `limit_args/1` and this test must go red.
             """

      assert capped_usec < window_usec * 0.4,
             "250 millicores is a quarter of one core: #{capped_usec}µs in a " <>
               "#{window_usec}µs window is more than that quarter allows"
    end
  end

  # The cgroup's own accounting, read from inside the container. A wall-clock
  # measurement would report the same elapsed time for both runs -- the window is
  # fixed -- and an iteration counter would measure busybox rather than the cap.
  defp spin_and_measure(sandbox) do
    before = cpu_usage_usec(sandbox)

    script =
      "end=$(( $(date +%s) + #{@spin_seconds} )); " <>
        "for i in 1 2; do ( while [ $(date +%s) -lt $end ]; do :; done ) & done; wait"

    {:ok, %{exit_status: 0}} =
      Docker.execute(sandbox, {"sh", ["-c", script]}, timeout: (@spin_seconds + 20) * 1000)

    cpu_usage_usec(sandbox) - before
  end

  defp cpu_usage_usec(sandbox) do
    {:ok, %{exit_status: 0, stdout: stdout}} =
      Docker.execute(sandbox, {"cat", ["/sys/fs/cgroup/cpu.stat"]}, [])

    [_all, usec] = Regex.run(~r/usage_usec\s+(\d+)/, stdout)
    String.to_integer(usec)
  end

  defp collect_chunks(acc \\ []) do
    receive do
      {:chunk, chunk} -> collect_chunks([chunk | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end
