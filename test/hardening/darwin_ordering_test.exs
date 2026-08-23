defmodule ExSandbox.Hardening.DarwinOrderingTest do
  @moduledoc """
  The `005` R9b composition trap, kept reproducible (014 T017, `SC-003`).

  ## What this file guards, and why a structural assertion is not enough

  `taskpolicy -m` applies to its **immediate child** and is silently lost across
  an intervening `exec`. R9b measured it:

      taskpolicy -m 100 sandbox-exec -f p.sb ./hog 300   # exits 0, 300 MB allocated

  A limiter present in the process tree, named in configuration, invoked with
  correct arguments — and enforcing nothing. Every check short of breaching the
  cap reports that composition as working, which is why `FR-014a` exists.

  So this file asserts the trap **live**, on this host, in the same run as the
  fix. The misordered composition is built here and required to exit 0 having
  allocated 300 MB; the backend's own composition is required to kill the same
  binary at 137. The two are then required to *differ*.

  That last assertion is the one that fails if `ExSandbox.Hardening.Darwin` ever
  inverts its order: an inverted backend produces the trap's own outcome, both
  sides exit 0, and "these two orders give different answers" stops being true.
  A structural assertion on the emitted argv is carried too (it localises the
  break to one line), but it is the *behavioural* pair that makes the guard
  impossible to satisfy by accident.

  ## Verified red

  Inverting `apply/3` to emit `taskpolicy -m N sandbox-exec -f p.sb <target>`
  turns "the backend's composition stops the same breach" into
  `{:exit_status, 0}` with `allocated 300 MB OK`, and turns the differ-assertion
  red as well. Recorded in the `014` T017 commit message.
  """

  use ExUnit.Case, async: false

  # ⚠️ Required. `test_helper.exs` excludes `:darwin_hardening` off Darwin, and
  # that exclusion only reaches a module that tags itself. Untagged, everything
  # below runs on Linux CI and fails against `sandbox-exec` and `taskpolicy`,
  # which do not exist there — a mechanism defect is what those failures would
  # look like.
  @moduletag :darwin_hardening

  # The hog is fast (well under a second for 300 MB), but a misordered run that
  # is NOT stopped has to finish, and CI machines page.
  @moduletag timeout: 120_000

  alias ExSandbox.Hardening.Darwin

  # The nominal cap both compositions are given. 100 MB is R9b's own number.
  @cap_mb 100

  # Three times the cap: large enough that a working cap must fire, small enough
  # that the unstopped control finishes promptly.
  @hog_mb 300

  setup_all do
    unless match?({:unix, :darwin}, :os.type()) do
      raise """
      ExSandbox.Hardening.DarwinOrderingTest ran on #{inspect(:os.type())}.

      `taskpolicy` and `sandbox-exec` do not exist here, so neither composition
      means anything. Refusing rather than skipping quietly — `005` R9 records
      three isolation tests that passed against a mechanism that never ran.
      Exclude the `:darwin_hardening` tag (014 T003) instead.
      """
    end

    dir =
      Path.join(
        System.tmp_dir!(),
        "ex_sandbox_darwin_ordering_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)

    hog = Path.join(dir, "hog")
    src = Path.join(__DIR__, "../support/darwin_fixtures/hog.c") |> Path.expand()

    # `-O0` for the reason `DarwinTest` records: an optimiser is entitled to
    # delete work whose result is unused, and a hog that allocates nothing turns
    # a breach test into a program that exits 0.
    case System.cmd("cc", ["-O0", "-o", hog, src], stderr_to_stdout: true) do
      {_out, 0} -> :ok
      {out, status} -> raise "cc failed for #{src} (status #{status}):\n#{out}"
    end

    {:ok, dir: dir, hog: hog}
  end

  describe "the misordered composition (005 R9b's trap)" do
    test "taskpolicy outermost allocates 300 MB under a 100 MB cap and exits 0", ctx do
      %{status: status, output: output} = run_misordered(ctx)

      assert status == 0,
             """
             `taskpolicy -m #{@cap_mb} sandbox-exec -f p.sb hog #{@hog_mb}` exited \
             #{status} rather than 0 on this host.

             This test is the *control*: it establishes that the misordering really \
             does fail open here, which is the only thing that makes the backend's \
             137 below evidence of anything. If macOS has started enforcing the cap \
             across the intervening exec, this file's premise has changed and the \
             backend's ordering rule needs re-deriving rather than this assertion \
             relaxing.

             Output tail:
             #{tail(output)}
             """

      assert output =~ "allocated #{@hog_mb} MB OK",
             "the hog did not reach #{@hog_mb} MB, so it was stopped by something — " <>
               "but not by exiting non-zero. Output tail:\n#{tail(output)}"
    end
  end

  describe "the backend's own composition" do
    test "sandbox-exec outermost, taskpolicy immediate parent, kills the same hog at 137", ctx do
      %{status: status, output: output} = run_backend(ctx)

      assert status == 137,
             "the backend's composition exited #{status}; expected 137 (128 + SIGKILL). " <>
               "Output tail:\n#{tail(output)}"

      # ⚠️ The half that makes 137 mean "stopped at the cap" rather than "never
      # ran". `005` R9 recorded three tests passing against a mechanism that
      # never started, because a program that dies instantly allocates nothing.
      assert output =~ "mb 50\n",
             "the hog never reached 50 MB, so nothing establishes it was stopped BY the " <>
               "cap rather than never running. Output tail:\n#{tail(output)}"

      refute output =~ "allocated #{@hog_mb} MB OK"
    end

    test "the two orders give different answers — inverting the backend breaks this", ctx do
      misordered = run_misordered(ctx)
      backend = run_backend(ctx)

      # ⚠️ THE regression assertion. Same binary, same nominal cap, same host,
      # in the same run; the only variable is where `taskpolicy` sits. A backend
      # that inverted its order would produce the trap's own outcome and these
      # two would agree — which is precisely the state `FR-014a` forbids being
      # reported as an enforced cap.
      refute misordered.status == backend.status,
             """
             Both compositions exited #{backend.status}.

             The misordered form (`taskpolicy` outermost) and the backend's form \
             (`sandbox-exec` outermost, `taskpolicy` as the target's immediate \
             parent) must not agree: if they do, either the backend has inverted \
             its order and lost the cap, or this host has stopped losing it and \
             the control is no longer a control.

             misordered: exit #{misordered.status}
             backend:    exit #{backend.status}
             """

      assert {misordered.status, backend.status} == {0, 137}
    end

    test "the emitted argv places sandbox-exec outermost and taskpolicy last", ctx do
      assert {:ok, {cmd, argv}} =
               Darwin.build_command({ctx.hog, [to_string(@hog_mb)]}, limits())

      # Outermost: what the caller actually spawns.
      assert Path.basename(cmd) == "sandbox-exec",
             "the outermost process is #{inspect(cmd)}. `taskpolicy` out here is R9b's " <>
               "trap: its limit does not survive the exec into `sandbox-exec`"

      assert ["-f", profile, "/bin/sh", "-c", script, target | rest] = argv
      assert String.ends_with?(profile, ".sb")
      assert rest == [to_string(@hog_mb)]
      assert String.ends_with?(target, "hog")

      # Innermost: `taskpolicy` is the last thing named before the target's argv
      # placeholders, so nothing execs between it and the target.
      assert String.ends_with?(script, ~s|taskpolicy -m #{@cap_mb} "$0" "$@"|),
             "the shell script is #{inspect(script)}. Anything between `taskpolicy` and " <>
               "`\"$0\"` is an intervening exec, which is exactly what drops the cap"

      # And `sandbox-exec` is not *inside* the script — that would be the
      # inversion expressed a second way.
      refute script =~ "sandbox-exec"

      assert Darwin.release(%{args: argv}) == :ok
    end
  end

  # -- Harness --------------------------------------------------------------

  defp limits, do: %{memory_mb: @cap_mb, cpu_millicores: 1000, wall_clock_seconds: 30}

  # The backend's composition, run exactly as a caller must: `spec.cmd` with
  # `spec.args`, never the command that was asked about.
  defp run_backend(ctx) do
    assert {:ok, spec} = Darwin.apply({ctx.hog, [to_string(@hog_mb)]}, limits())

    try do
      {output, status} =
        System.cmd(spec.cmd, spec.args, cd: spec.cd, stderr_to_stdout: true, env: [])

      %{status: status, output: output}
    after
      Darwin.release(spec)
    end
  end

  # R9b's misordered form, built here rather than obtained from the backend —
  # the backend cannot produce it, and the point is to run the shape it refuses
  # to emit.
  #
  # ⚠️ The profile is rendered by `Darwin.render_profile/2`, not hand-written, so
  # the control differs from the backend in **one** variable: process order. A
  # hand-rolled profile could differ in a second way and this file would not say
  # which one produced the result.
  defp run_misordered(ctx) do
    workdir = Path.join(ctx.dir, "wd-#{System.unique_integer([:positive])}")
    File.mkdir_p!(workdir)

    profile = Path.join(ctx.dir, "misordered-#{System.unique_integer([:positive])}.sb")
    File.write!(profile, Darwin.render_profile(workdir, System.user_home!()))

    {output, status} =
      System.cmd(
        taskpolicy_path(),
        [
          "-m",
          to_string(@cap_mb),
          sandbox_exec_path(),
          "-f",
          profile,
          ctx.hog,
          to_string(@hog_mb)
        ],
        cd: workdir,
        stderr_to_stdout: true,
        env: []
      )

    %{status: status, output: output}
  end

  defp taskpolicy_path, do: System.find_executable("taskpolicy") || "/usr/sbin/taskpolicy"
  defp sandbox_exec_path, do: System.find_executable("sandbox-exec") || "/usr/bin/sandbox-exec"

  defp tail(output) do
    output |> String.split("\n") |> Enum.take(-5) |> Enum.join("\n")
  end
end
