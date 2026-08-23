defmodule ExSandbox.Mechanism.Beam.ExecCaptureTest do
  @moduledoc """
  What `execute/3` actually captures, measured rather than described
  (008 T002).

  ## Why this runs the sandbox-side expression on the host

  The runner is Erlang source that `ExSandbox.Mechanism.Beam` parses here and
  `:erl_eval` evaluates **on the sandbox node**. On a host that cannot confine —
  every darwin developer machine — no sandbox can be provisioned at all, so the
  whole capture contract would be untestable until someone ran the container
  suite, which is where two earlier probes shipped broken from
  (`probe_exprs/3` twice). `connect_probe_verdict_test.exs` set the precedent:
  evaluate the same expressions in this VM against real processes, so the thing
  that ships is the thing that was measured.

  What this therefore does **not** establish: that the command ran under
  confinement. That is `ExSandbox.Conformance.Execution`'s job and it needs a
  host that can confine. Capture and confinement are separate claims and this
  file makes only the first.

  ## The defect being measured against

  `015` research R17 measured `MuonTrap`'s `:logger_fun` **corrupting lines past
  a 256-byte buffer**. A capture that reframes bytes into lines silently mangles
  anything longer than its buffer, and a build log is exactly where long lines
  live. So the assertions below are about bytes: a long line comes back
  byte-identical, and where bytes are dropped the result says so.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Mechanism.Beam.Exec

  setup do
    dir = Path.join(System.tmp_dir!(), "ex-sandbox-exec-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    %{dir: dir}
  end

  defp run(dir, cmd, args, opts \\ []) do
    cmd
    |> Exec.runner_exprs(args, Keyword.put(opts, :stderr_dir, dir))
    |> :erl_eval.exprs([])
    |> Exec.decode()
  end

  describe "the completion result" do
    test "carries the command's own exit status, not a synthesised one", %{dir: dir} do
      # 42 rather than 0 or 1: a runner that reported success for everything and
      # a runner that reported failure for everything would each pass one of
      # those, and neither would have carried the command's answer.
      assert {:ok, %{exit_status: 42}} = run(dir, "/bin/sh", ["-c", "exit 42"])
    end

    test "separates stdout from stderr", %{dir: dir} do
      assert {:ok, result} =
               run(dir, "/bin/sh", ["-c", "printf OUT; printf ERR 1>&2"])

      assert result.stdout == "OUT"
      assert result.stderr == "ERR"
    end

    test "passes arguments as argv, so shell metacharacters are data", %{dir: dir} do
      # If arguments were interpolated into shell text this would run `id` and
      # create a file. They are passed as separate argv entries and expanded
      # with `"$@"`, so there is nothing to escape and nothing to get wrong.
      hostile = "; $(id) `id` && echo pwned"

      assert {:ok, result} = run(dir, "/bin/echo", [hostile])

      # Byte-for-byte what was passed in, plus echo's newline. Nothing was
      # substituted, nothing was split on `;`, and nothing ran.
      assert result.stdout == hostile <> "\n"

      # `id`'s output would start with `uid=`. Its absence is the evidence that
      # the substitutions were data rather than commands.
      refute result.stdout =~ "uid="
    end

    test "gives the command EOF on stdin rather than leaving it blocked", %{dir: dir} do
      # `015` R14's lesson from `MuonTrap.Daemon`, in the form it takes here: a
      # command that reads stdin and never sees EOF blocks until a wall-clock
      # limit kills it, and "this command needs no input" becomes a limit
      # breach. `cat` with no redirect would hang forever.
      assert {:ok, %{exit_status: 0, stdout: ""}} = run(dir, "/bin/cat", [])
    end
  end

  describe "truncation (008 data-model property 3)" do
    test "a line far past any line buffer survives byte-identically", %{dir: dir} do
      # 100 KB in one line, ~390x `015` R17's 256-byte buffer. Measured on this
      # host, the port delivered it as six chunks of 29696, 29696, 9216, 24576,
      # 6144 and 672 bytes -- irregular, unrelated to any line boundary, and
      # reassembling to the original exactly. That irregularity is the point: a
      # capture that framed lines would have to buffer, and a buffer is what
      # corrupts.
      line = String.duplicate("x", 100_000)

      assert {:ok, result} = run(dir, "/bin/sh", ["-c", ~s(printf %s "$1"), "sh", line])
      assert result.stdout == line
      refute result.truncated?
    end

    test "output past the limit is cut at the limit and declared", %{dir: dir} do
      line = String.duplicate("x", 100_000)

      assert {:ok, result} =
               run(dir, "/bin/sh", ["-c", ~s(printf %s "$1"), "sh", line], limit_bytes: 1_000)

      assert byte_size(result.stdout) == 1_000
      assert result.stdout == binary_part(line, 0, 1_000)

      assert result.truncated?,
             "bytes were dropped and the result did not say so. Silent truncation " <>
               "of a build log is how a real error disappears from a diagnosis."
    end

    test "stderr is truncated and declared on the same terms as stdout", %{dir: dir} do
      assert {:ok, result} =
               run(
                 dir,
                 "/bin/sh",
                 ["-c", ~s(printf %s "$1" 1>&2), "sh", String.duplicate("e", 5_000)],
                 limit_bytes: 100
               )

      assert byte_size(result.stderr) == 100
      assert result.truncated?
    end

    test "the command still completes after the limit is reached", %{dir: dir} do
      # The runner keeps draining rather than closing the port. Closing early
      # would leave the child writing into a broken pipe, and the exit status
      # this seam reports would become the seam's doing rather than the
      # command's.
      assert {:ok, result} =
               run(
                 dir,
                 "/bin/sh",
                 ["-c", "printf %s \"$1\"; exit 7", "sh", String.duplicate("y", 50_000)],
                 limit_bytes: 10
               )

      assert result.exit_status == 7
      assert result.truncated?
    end
  end

  describe "could_not_run is a distinct outcome, never an exit status (008 FR-016)" do
    test "a binary that is not there is could_not_run", %{dir: dir} do
      # ⚠️ This is the case a shell would answer with exit 127, and 127 is an
      # exit status a real command may legitimately return. The command is
      # therefore resolved against the very PATH it would run with, *before*
      # anything is spawned, so "not there" and "ran and exited 127" cannot be
      # confused. `008-FR-026` turns on that: an unperformed check must not
      # spend a refinement iteration.
      assert {:could_not_run, {:executable_not_found, _}} =
               run(dir, "/no/such/binary", [])
    end

    test "a name that exists but is not executable is could_not_run", %{dir: dir} do
      path = Path.join(dir, "not-executable")
      File.write!(path, "data\n")
      File.chmod!(path, 0o644)

      assert {:could_not_run, {:executable_not_found, _}} = run(dir, path, [])
    end

    test "stderr that cannot be captured stops the command running at all", %{dir: dir} do
      # The alternative -- run anyway and let stderr fall through to the node's
      # own stderr -- loses the stream silently, and a caller reading an empty
      # `stderr` cannot tell "the command said nothing" from "we dropped what it
      # said". Refusing to run is the honest direction.
      _ = dir

      assert {:could_not_run, {:stderr_capture_unavailable, _dir, _reason}} =
               run("/no/such/directory", "/bin/echo", ["x"])
    end
  end

  describe "the environment the command runs with" do
    test "names PATH explicitly, because the sandbox inherits none", %{dir: dir} do
      # `env -i` with an ERTS-only allowlist (005 FR-004) leaves a child with no
      # PATH at all, so a bare command name fails :enoent -- which reads exactly
      # like the sandbox refusing the operation. That ambiguity is what this
      # seam exists to remove.
      assert {"PATH", path} = List.keyfind(Exec.default_env(), "PATH", 0)
      assert path =~ "/usr/bin"

      assert {:ok, %{stdout: "ok\n"}} = run(dir, "sh", ["-c", "echo ok"])
    end

    test "a caller's environment reaches the command", %{dir: dir} do
      env = Exec.default_env() ++ [{"EX_SANDBOX_TEST_VALUE", "carried"}]

      assert {:ok, %{stdout: "carried\n"}} =
               run(dir, "/bin/sh", ["-c", "echo \"$EX_SANDBOX_TEST_VALUE\""], env: env)
    end
  end

  describe "the capture leaves nothing behind" do
    test "the stderr spill file is removed after the command", %{dir: dir} do
      assert {:ok, _} = run(dir, "/bin/sh", ["-c", "printf big 1>&2"])

      assert File.ls!(dir) == [],
             "the stderr spill file was left in the sandbox's storage. One per " <>
               "command would fill a tenant's disk quota with the seam's own bookkeeping."
    end
  end
end
