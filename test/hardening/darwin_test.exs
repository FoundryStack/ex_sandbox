defmodule ExSandbox.Hardening.DarwinTest do
  @moduledoc """
  Adversarial verification of `ExSandbox.Hardening.Darwin` (014 T007 – T010).

  ## Every cap here is established by BREACHING it

  Not one assertion below checks that a wrapper was invoked, and that is the
  whole design. `005` R9b measured `taskpolicy -m 100 sandbox-exec … ./hog 300`
  allocating 300 MB under a nominal 100 MB cap and exiting 0 — a limiter present
  in the process tree, named in configuration, invoked with correct arguments,
  and silently not applied. Every check short of *trigger a breach and watch it
  stop* reported that composition as working.

  ## ⚠️ And every breach assertion carries something able to contradict it

  `005` R9 (research.md:211) recorded three isolation tests passing against a
  mechanism that never ran: a program that dies instantly allocates nothing, and
  the suite read that as the cap holding. `{:error, :undef}` satisfies "the
  sandbox could not do this" exactly as convincingly as a real boundary.

  So:

    * the memory test asserts the hog **got to 100 MB** before dying, which an
      instant failure cannot do;
    * the CPU test uses a spinner that does **not** call `setrlimit` on itself
      (the spike's does — `014` T002 Finding 1) and carries an **uncapped
      control** that is required to still be running when the harness kills it;
    * the idle test requires *no* exit status, which no cap breach can produce;
    * all four outcomes are asserted mutually distinct in one test, so a
      mechanism that collapsed them into one answer fails here even if each
      individual number still looked right.

  ## ⚠️ These tests are the only thing standing between the shell and the tenant

  The Darwin composition routes the target through `/bin/sh -c`, which
  `ExSandbox.Hardening.Linux` never does. `injection` below is not a nicety: it
  is the test that decides whether the backend's own command line is a hole.
  """

  use ExUnit.Case, async: false

  # ⚠️ Depends on `014` T003 adding `:darwin_hardening` to the excluded tags on
  # non-Darwin hosts. Until that lands this module still guards itself — every
  # test needs `sandbox-exec` and `taskpolicy`, which exist nowhere else, and
  # `setup_all` refuses rather than letting them report a Darwin guarantee from
  # a host that has none.
  @moduletag :darwin_hardening

  # The CPU test spends its budget on purpose and its control spends more.
  @moduletag timeout: 180_000

  alias ExSandbox.Hardening.Darwin

  # Above every measured outcome (the slowest is the 300 MB hog at well under a
  # second) and far below the control's budget, so a harness timeout here means
  # the cap did not fire rather than that the machine was slow.
  @breach_budget_ms 30_000

  setup_all do
    unless match?({:unix, :darwin}, :os.type()) do
      raise """
      ExSandbox.Hardening.DarwinTest ran on #{inspect(:os.type())}.

      Nothing here is meaningful off Darwin — `sandbox-exec` and `taskpolicy` do
      not exist. Refusing rather than skipping quietly: a silently absent suite
      is how `005` R9's three tests came to pass against a mechanism that never
      ran. Exclude the `:darwin_hardening` tag (014 T003) instead.
      """
    end

    dir =
      Path.join(
        System.tmp_dir!(),
        "ex_sandbox_darwin_fixtures_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)

    source_dir = Path.join(__DIR__, "../support/darwin_fixtures") |> Path.expand()

    bins =
      Map.new(~w(hog spin_nolimit crash argv_echo), fn name ->
        out = Path.join(dir, name)
        src = Path.join(source_dir, name <> ".c")

        # `-O0`: at higher levels the compiler is entitled to delete
        # `spin_nolimit`'s loop (its result is unused) and to elide `crash`'s
        # null store as undefined behaviour. Either would turn a breach test
        # into a program that exits 0 immediately — the failure this file exists
        # to make impossible.
        case System.cmd("cc", ["-O0", "-o", out, src], stderr_to_stdout: true) do
          {_out, 0} ->
            {name, out}

          {out_text, status} ->
            raise "cc failed for #{src} (status #{status}):\n#{out_text}"
        end
      end)

    {:ok, bins: bins}
  end

  # -- The harness ----------------------------------------------------------

  # Launches the spec the way a caller must: `spec.cmd` with `spec.args`, never
  # the command that was asked about. Enforces the wall-clock budget itself,
  # because nothing in a launch spec can kill a process later (see the Darwin
  # moduledoc) — this stands in for the supervisor.
  defp run(command, limits, opts \\ []) do
    budget_ms = Keyword.get(opts, :budget_ms, @breach_budget_ms)
    assert {:ok, spec} = Darwin.apply(command, limits, Keyword.delete(opts, :budget_ms))

    on_exit(fn -> Darwin.release(spec) end)

    port =
      Port.open({:spawn_executable, spec.cmd}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        args: spec.args,
        cd: spec.cd
      ])

    collect(port, budget_ms, [])
  end

  defp collect(port, budget_ms, acc) do
    receive do
      {^port, {:data, chunk}} ->
        collect(port, budget_ms, [chunk | acc])

      {^port, {:exit_status, status}} ->
        %{outcome: {:exit_status, status}, output: acc |> Enum.reverse() |> IO.iodata_to_binary()}
    after
      budget_ms ->
        os_pid = with info when is_list(info) <- Port.info(port), do: info[:os_pid]
        Port.close(port)

        # ⚠️ The captured pid and nothing else. `sandbox-exec`, `/bin/sh` and
        # `taskpolicy` all `exec`, so this single pid IS the target — which is
        # also why a pattern-matching kill would be both unnecessary and unsafe.
        if os_pid, do: System.cmd("/bin/kill", ["-KILL", to_string(os_pid)])

        %{
          outcome: {:wall_clock_timeout, os_pid},
          output: acc |> Enum.reverse() |> IO.iodata_to_binary()
        }
    end
  end

  # -- T007: memory ---------------------------------------------------------

  describe "memory cap (T007)" do
    test "a 300 MB allocation under a 150 MB cap is killed AFTER allocating", %{bins: bins} do
      result =
        run({bins["hog"], ["300"]}, %{
          memory_mb: 150,
          cpu_millicores: 1000,
          wall_clock_seconds: 30
        })

      assert result.outcome == {:exit_status, 137}

      # ⚠️ The half that makes the exit status mean something. A program that
      # fails to start, is denied its own binary, or dies in dyld also produces a
      # non-zero status — and `005` R9 recorded exactly that reading as a cap
      # holding. 100 MB of touched pages is not something an instant failure
      # reaches.
      assert result.output =~ "mb 100\n",
             "the hog never reached 100 MB, so nothing establishes it was stopped BY the cap " <>
               "rather than never running. Output:\n#{result.output}"

      # And it did not finish. Without this, a cap set so high that the hog
      # completed would still show `mb 100`.
      refute result.output =~ "allocated 300 MB OK"
    end

    test "the same hog inside the cap completes — the control", %{bins: bins} do
      result =
        run({bins["hog"], ["50"]}, %{
          memory_mb: 150,
          cpu_millicores: 1000,
          wall_clock_seconds: 30
        })

      assert result.outcome == {:exit_status, 0}
      assert result.output =~ "allocated 50 MB OK"
    end
  end

  # -- T008: CPU ------------------------------------------------------------

  describe "cpu cap (T008, amended by T002 Finding 1)" do
    test "a spinner that never limits itself is killed with SIGXCPU", %{bins: bins} do
      result =
        run({bins["spin_nolimit"], []}, %{
          memory_mb: 150,
          cpu_millicores: 1000,
          wall_clock_seconds: 2
        })

      assert result.outcome == {:exit_status, 152},
             "expected 152 (128 + SIGXCPU); got #{inspect(result.outcome)}"

      assert result.output =~ "spinning",
             "the spinner never announced itself, so it may have died before spinning at all"
    end

    test "the SAME spinner with no CPU cap runs until the harness kills it", %{bins: bins} do
      # ⚠️ This is the control that makes the test above capable of failing.
      # Written against the spike's `spin.c` — which calls `setrlimit(RLIMIT_CPU,
      # 2)` on itself — this control would ALSO exit 152, and the assertion
      # would pass whether or not the backend imposed anything (T002 Finding 1).
      # It runs forever here because this binary asks for nothing, which is what
      # tenant code will do.
      #
      # ⚠️ The budget is 600 s rather than absent, and that is T019's floor
      # rather than a weakening of this control. `FR-014b` now makes a launch
      # with no `:wall_clock_seconds` a refusal, so "no budget at all" is not a
      # spec this backend will build. A 600 s CPU ceiling observed for 6 wall-
      # seconds is the same control: the spinner cannot reach it, so anything
      # that stops it in that window is the binary limiting itself — which is
      # exactly what this test exists to rule out. Only the ceiling differs
      # between this and the capped case above, so the difference in outcome is
      # attributable to the ceiling and nothing else.
      result =
        run({bins["spin_nolimit"], []}, %{memory_mb: 150, wall_clock_seconds: 600},
          budget_ms: 6_000
        )

      assert match?({:wall_clock_timeout, _}, result.outcome),
             "the uncapped spinner terminated on its own with #{inspect(result.outcome)}. " <>
               "It must not: if it does, the capped case's 152 is the binary limiting itself " <>
               "and says nothing about the platform"

      assert result.output =~ "spinning"
    end

    test "a CPU cap with no wall-clock budget is refused, not defaulted", %{bins: bins} do
      assert {:error, {:cannot_enforce, :cpu_cap, detail}} =
               Darwin.apply({bins["spin_nolimit"], []}, %{memory_mb: 150, cpu_millicores: 1000})

      assert detail =~ "wall_clock_seconds"
    end
  end

  # -- T009: idle hang ------------------------------------------------------

  describe "idle hang (T009)" do
    test "an idle sleep produces NO exit status and is killed by its OS pid", %{bins: _bins} do
      result =
        run(
          {"/bin/sleep", ["60"]},
          %{memory_mb: 150, cpu_millicores: 1000, wall_clock_seconds: 2},
          budget_ms: 2_000
        )

      assert {:wall_clock_timeout, os_pid} = result.outcome
      assert is_integer(os_pid) and os_pid > 0

      # ⚠️ The distinguishing property, and the reason this is its own outcome
      # rather than a status number. An idle process consumes no CPU, so
      # `ulimit -t` never fires; it allocates nothing, so `taskpolicy` never
      # fires; it does not crash. Nothing but a supervisor watching the clock
      # ends it, and a supervisor's kill leaves no exit status behind.
      refute match?({:exit_status, _}, result.outcome)

      # And it really was killed: the pid must be gone.
      Process.sleep(200)
      assert {_, 1} = System.cmd("/bin/kill", ["-0", to_string(os_pid)], stderr_to_stdout: true)
    end
  end

  # -- T010: crash and success ---------------------------------------------

  describe "crash and success (T010)" do
    test "an ordinary segfault exits 139", %{bins: bins} do
      result =
        run({bins["crash"], []}, %{memory_mb: 150, cpu_millicores: 1000, wall_clock_seconds: 30})

      assert result.outcome == {:exit_status, 139}
      assert result.output =~ "crashing"
    end

    test "a program inside every cap exits 0", %{bins: bins} do
      result =
        run({bins["hog"], ["10"]}, %{memory_mb: 150, cpu_millicores: 1000, wall_clock_seconds: 30})

      assert result.outcome == {:exit_status, 0}
      assert result.output =~ "allocated 10 MB OK"
    end

    test "all four outcomes are mutually distinguishable (SC-002, FR-016)", %{bins: bins} do
      caps = %{memory_mb: 150, cpu_millicores: 1000, wall_clock_seconds: 30}

      outcomes = %{
        memory: run({bins["hog"], ["300"]}, caps).outcome,
        cpu:
          run({bins["spin_nolimit"], []}, %{
            memory_mb: 150,
            cpu_millicores: 1000,
            wall_clock_seconds: 2
          }).outcome,
        idle:
          run({"/bin/sleep", ["60"]}, %{memory_mb: 150, wall_clock_seconds: 2}, budget_ms: 2_000).outcome,
        crash: run({bins["crash"], []}, caps).outcome,
        success: run({bins["hog"], ["10"]}, caps).outcome
      }

      # The idle pid varies, so compare its shape rather than its value.
      normalised =
        Map.new(outcomes, fn
          {key, {:wall_clock_timeout, _pid}} -> {key, :wall_clock_timeout}
          {key, other} -> {key, other}
        end)

      assert normalised == %{
               memory: {:exit_status, 137},
               cpu: {:exit_status, 152},
               idle: :wall_clock_timeout,
               crash: {:exit_status, 139},
               success: {:exit_status, 0}
             }

      assert normalised |> Map.values() |> Enum.uniq() |> length() == 5,
             "two outcomes collapsed into one answer: #{inspect(normalised)}"
    end
  end

  # -- The shell injection surface -----------------------------------------

  describe "the intervening /bin/sh is not an injection surface" do
    test "shell metacharacters in arguments arrive as literal bytes", %{bins: bins} do
      workdir =
        Path.join(System.tmp_dir!(), "darwin_injection_#{System.unique_integer([:positive])}")

      File.mkdir_p!(workdir)
      on_exit(fn -> File.rm_rf(workdir) end)

      # ⚠️ The side effects are aimed inside a directory handed to the backend as
      # its `:workdir`, so the generated profile PERMITS writing there. That is
      # load-bearing: aimed anywhere else, `(deny file-write*)` would absorb an
      # injection that really happened, and this test would report an argv
      # discipline that is not there. Verified by breaking it — with the target
      # and arguments interpolated into the `-c` script, `PWNED_*` files appear.
      payloads = [
        "harmless",
        "; touch #{workdir}/PWNED_SEMI",
        "$(touch #{workdir}/PWNED_SUBST)",
        "`touch #{workdir}/PWNED_TICK`",
        "&& touch #{workdir}/PWNED_AND",
        "| touch #{workdir}/PWNED_PIPE",
        "> #{workdir}/PWNED_REDIR",
        "$$ $(id)",
        "\n touch #{workdir}/PWNED_NEWLINE",
        "'\"'\"'quoted\" and \\backslashed"
      ]

      result =
        run(
          {bins["argv_echo"], payloads},
          %{memory_mb: 150, cpu_millicores: 1000, wall_clock_seconds: 30},
          workdir: workdir
        )

      assert result.outcome == {:exit_status, 0}

      # argv[0] is the target, so argc is one more than the payload count. A
      # shell that split any argument would raise this number.
      assert result.output =~ "argc=#{length(payloads) + 1}\n"

      for {payload, index} <- Enum.with_index(payloads, 1) do
        assert result.output =~ "argv[#{index}]=#{payload}",
               "argv[#{index}] did not arrive literally.\nExpected: #{inspect(payload)}\n" <>
                 "Got:\n#{result.output}"
      end

      # The bytes arriving intact is one half; nothing having *happened* is the
      # other. A shell that expanded `$(…)` at argv-construction time would leave
      # the argument looking clean and the file sitting here.
      leftovers = workdir |> File.ls!() |> Enum.filter(&String.starts_with?(&1, "PWNED"))

      assert leftovers == [],
             "the intervening shell executed injected commands: #{inspect(leftovers)}"
    end

    test "a target path containing shell metacharacters is never parsed as script", %{
      bins: bins
    } do
      workdir =
        Path.join(System.tmp_dir!(), "darwin_injection_cmd_#{System.unique_integer([:positive])}")

      File.mkdir_p!(workdir)
      on_exit(fn -> File.rm_rf(workdir) end)

      # Not a real program: a path shaped like one command followed by another.
      # If it reached the parser, `touch` would run and the launch would look
      # like a success.
      result =
        run(
          {"#{bins["argv_echo"]} ; touch #{workdir}/PWNED_CMD", []},
          %{memory_mb: 150, cpu_millicores: 1000, wall_clock_seconds: 30},
          workdir: workdir
        )

      # The exec fails, because there is no file by that name. That is the
      # correct outcome: the operating system's own error, not a substituted one.
      assert match?({:exit_status, status} when status != 0, result.outcome)
      refute File.exists?(Path.join(workdir, "PWNED_CMD"))
    end

    test "the emitted argv puts the target after the -c script, never inside it", %{bins: bins} do
      assert {:ok, {cmd, argv}} =
               Darwin.build_command({bins["hog"], ["300"]}, %{
                 memory_mb: 150,
                 cpu_millicores: 1000,
                 wall_clock_seconds: 2
               })

      assert Path.basename(cmd) == "sandbox-exec"

      # ⚠️ Structural, not incidental. `sandbox-exec` outermost, then the shell,
      # then `taskpolicy` as the immediate parent of the target — the ordering
      # R9b measured failing open when inverted.
      assert ["-f", profile, "/bin/sh", "-c", script | rest] = argv
      assert String.ends_with?(profile, ".sb")

      # ⚠️ Symlink-RESOLVED, and deliberately so. The profile's path rules are
      # evaluated by the kernel against resolved paths (`/var` is a symlink to
      # `/private/var` on macOS), so the grant and the exec must name the same
      # file or the profile silently governs a path nobody runs.
      assert rest == [ExSandbox.Hardening.Confinement.resolve_executable(bins["hog"]), "300"]
      assert String.starts_with?(hd(rest), "/")

      # The target and its argument are absent from the parsed text entirely.
      refute script =~ Path.basename(bins["hog"])
      refute script =~ "300"
      assert script == ~s|ulimit -t 2; exec /usr/sbin/taskpolicy -m 150 "$0" "$@"|

      # `build_command/3` hands back only `{cmd, argv}`, so the profile path
      # inside argv is the whole handle — and it has to be enough.
      assert Darwin.release(%{args: argv}) == :ok
      refute File.exists?(profile)
    end
  end

  # -- Refusals -------------------------------------------------------------

  describe "refusal rather than a spec with the cap missing (T014)" do
    test "a disk quota is refused, naming the capability" do
      assert {:error, {:cannot_enforce, :disk_quota, detail}} =
               Darwin.apply({"/bin/echo", []}, %{memory_mb: 150, disk_mb: 100})

      assert detail =~ "disk"
    end

    test "a refused launch creates no profile and no workdir" do
      before = profile_dir_entries()

      assert {:error, {:cannot_enforce, :disk_quota, _}} =
               Darwin.apply({"/bin/echo", []}, %{memory_mb: 150, disk_mb: 100})

      assert {:error, {:cannot_enforce, :cpu_cap, _}} =
               Darwin.apply({"/bin/echo", []}, %{memory_mb: 150, cpu_millicores: 500})

      assert profile_dir_entries() == before,
             "a rejected launch left files behind that nothing will ever call release/1 for"
    end

    test "required_capabilities/0 does not claim disk quota" do
      caps = Darwin.required_capabilities()

      assert :memory_cap in caps
      assert :cpu_cap in caps
      assert :process_separation in caps
      assert :time_budget in caps

      refute :disk_quota in caps,
             "a capability this backend refuses outright must not be listed as one it requires"
    end
  end

  # -- T019: the wall-clock floor -------------------------------------------

  describe "the wall-clock floor (T019, FR-014b, SC-006c)" do
    # ⚠️ `SC-006c` is verified one way only: **disable the budget and observe
    # the deployment refuse the run.** Not "observe it fail" — a run that failed
    # for any other reason (a missing binary, a denied profile, a crash) would
    # satisfy a looser assertion while leaving the floor exactly as absent as it
    # was. So every test below asserts on the refusal *specifically*: the error
    # tuple, the capability it names, and — in the last one — that the target's
    # side effect never happened while the identical launch *with* a budget
    # produces it.

    test "a launch with no wall-clock budget is refused, naming :time_budget" do
      assert {:error, {:cannot_enforce, :time_budget, detail}} =
               Darwin.apply({"/bin/echo", ["hi"]}, %{memory_mb: 150})

      assert detail =~ "wall-clock budget"

      # ⚠️ The capability name matters as much as the refusal. `:cpu_cap` here
      # would send a caller to configure a CPU limit, which is not the hole:
      # an idle process breaches no CPU cap and is exactly what has no
      # terminating condition without a budget.
      refute detail =~ "millicore CPU cap was requested"
    end

    test "a budget of zero is refused for the same reason an absent one is" do
      # "Disabled" is the state `SC-006c` names, and `0` is how a caller
      # disables it without deleting the key. It leaves the identical hole.
      for disabled <- [0, -1, nil, "30", 30.0] do
        limits = %{memory_mb: 150, wall_clock_seconds: disabled}

        assert {:error, {:cannot_enforce, :time_budget, _}} =
                 Darwin.apply({"/bin/echo", ["hi"]}, limits),
               "a :wall_clock_seconds of #{inspect(disabled)} was accepted; " <>
                 "it enforces nothing, so it must refuse"
      end
    end

    test "the refusal reaches build_command/3 too, not only apply/3" do
      # Both are entry points a caller can reach. A floor enforced in one of
      # them is a floor with a door next to it.
      assert {:error, {:cannot_enforce, :time_budget, _}} =
               Darwin.build_command({"/bin/echo", ["hi"]}, %{memory_mb: 150})
    end

    test "the refusal happens before anything is written to disk" do
      before = profile_dir_entries()

      assert {:error, {:cannot_enforce, :time_budget, _}} =
               Darwin.apply({"/bin/echo", ["hi"]}, %{memory_mb: 150})

      assert profile_dir_entries() == before,
             "a rejected launch left a profile behind that nothing will ever call " <>
               "release/1 for — one leak per refused run"
    end

    test "the run does not happen: no spec, no side effect — and the control shows it could" do
      workdir =
        Path.join(System.tmp_dir!(), "darwin_floor_#{System.unique_integer([:positive])}")

      File.mkdir_p!(workdir)
      on_exit(fn -> File.rm_rf(workdir) end)

      marker = Path.join(workdir, "IT_RAN")

      # `touch` inside the workdir is PERMITTED by the generated profile, so if
      # anything launches, the marker appears. Aimed anywhere else,
      # `(deny file-write*)` would absorb the side effect and this test would
      # report a refusal that never happened.
      attempt = fn limits ->
        case Darwin.apply({"/usr/bin/touch", [marker]}, limits, workdir: workdir) do
          {:ok, spec} ->
            try do
              {_out, status} =
                System.cmd(spec.cmd, spec.args, cd: spec.cd, stderr_to_stdout: true, env: [])

              {:launched, status}
            after
              Darwin.release(spec)
            end

          {:error, reason} ->
            {:refused, reason}
        end
      end

      assert {:refused, {:cannot_enforce, :time_budget, _}} = attempt.(%{memory_mb: 150})

      refute File.exists?(marker),
             "the target ran despite the budget being disabled — FR-014b's floor is not " <>
               "a warning, it is a refusal"

      # ⚠️ The control. Without it, a backend that refused *every* launch would
      # pass everything above while enforcing nothing at all.
      assert {:launched, 0} = attempt.(%{memory_mb: 150, wall_clock_seconds: 5})

      assert File.exists?(marker),
             "the identical launch WITH a budget did not run either, so the refusal above " <>
               "says nothing about the budget"
    end
  end

  # -- Profile --------------------------------------------------------------

  describe "profile generation (T013)" do
    test "starts from (allow default), denies network and writes, permits the workdir" do
      profile = Darwin.render_profile("/private/tmp/wd", "/Users/nobody")

      assert profile =~ "(version 1)"
      assert profile =~ "(allow default)"

      # ⚠️ Line-wise, ignoring `;` comments. The profile *names* `(deny default)`
      # in a comment to record why it is not used, and a naive `refute =~` would
      # be satisfied by deleting that explanation — turning the measured reason
      # into the thing the test forbids.
      rules =
        profile
        |> String.split("\n")
        |> Enum.reject(&String.starts_with?(String.trim(&1), ";"))

      refute Enum.any?(rules, &(&1 =~ "(deny default)"))
      assert profile =~ "(deny network*)"
      assert profile =~ "(deny file-write*)"
      assert profile =~ ~s|(allow file-write* (subpath "/private/tmp/wd")|
      assert profile =~ ~s|(deny file-read* (subpath "/Users/nobody/Documents")|
      assert profile =~ ~s|(subpath "/Users/nobody/.ssh")|

      # Rule order is load-bearing: later rules win in SBPL, so a workdir grant
      # placed before the blanket deny would be overridden and the sandbox could
      # write nowhere.
      {deny_index, _} = :binary.match(profile, "(deny file-write*)")
      {allow_index, _} = :binary.match(profile, "(allow file-write*")
      assert deny_index < allow_index
    end

    test "a workdir containing SBPL string syntax cannot escape the string literal" do
      profile =
        Darwin.render_profile(~S|/tmp/a") (allow file-write* (subpath "/|, "/Users/nobody")

      # The quote is escaped, so the injected text stays inside one string.
      assert profile =~ ~S|\"|
      refute profile =~ ~S|(subpath "/tmp/a") (allow|
    end
  end

  # -- Release --------------------------------------------------------------

  describe "release/1 (T012)" do
    test "removes the generated profile and is idempotent" do
      assert {:ok, spec} =
               Darwin.apply({"/bin/echo", ["hi"]}, %{memory_mb: 64, wall_clock_seconds: 5})

      ["-f", profile | _] = spec.args

      assert File.exists?(profile)
      assert Darwin.release(spec) == :ok
      refute File.exists?(profile)

      # Twice, three times, on a handle whose file is already gone.
      assert Darwin.release(spec) == :ok
      assert Darwin.release(spec) == :ok
      assert Darwin.release(profile) == :ok
      assert Darwin.release(nil) == :ok
    end

    test "reclaims the workdir it invented, and leaves one the caller supplied" do
      before = profile_dir_entries()

      assert {:ok, spec} =
               Darwin.apply({"/bin/echo", ["hi"]}, %{memory_mb: 64, wall_clock_seconds: 5})

      assert File.dir?(spec.cd)
      assert Darwin.release(spec) == :ok

      assert profile_dir_entries() == before,
             "release/1 left the profile or the workdir it generated behind"

      # A caller-supplied workdir is not this module's to reclaim, however it
      # ends up empty.
      mine = Path.join(System.tmp_dir!(), "caller_workdir_#{System.unique_integer([:positive])}")
      File.mkdir_p!(mine)
      on_exit(fn -> File.rm_rf(mine) end)

      assert {:ok, spec} =
               Darwin.apply({"/bin/echo", ["hi"]}, %{memory_mb: 64, wall_clock_seconds: 5},
                 workdir: mine
               )

      assert Darwin.release(spec) == :ok
      assert File.dir?(mine)
    end

    test "leaves a generated workdir alone once it holds tenant output" do
      assert {:ok, spec} =
               Darwin.apply({"/bin/echo", ["hi"]}, %{memory_mb: 64, wall_clock_seconds: 5})

      File.write!(Path.join(spec.cd, "tenant-output.txt"), "keep me")
      on_exit(fn -> File.rm_rf(spec.cd) end)

      assert Darwin.release(spec) == :ok

      assert File.exists?(Path.join(spec.cd, "tenant-output.txt")),
             "release/1 destroyed a tenant's output; it must reclaim only an EMPTY workdir"
    end

    test "refuses to unlink a path outside its own profile directory" do
      outsider = Path.join(System.tmp_dir!(), "not_ours_#{System.unique_integer([:positive])}.sb")
      File.write!(outsider, "(version 1)")
      on_exit(fn -> File.rm(outsider) end)

      assert Darwin.release(%{args: ["-f", outsider, "/bin/sh"]}) == :ok

      assert File.exists?(outsider),
             "release/1 unlinked a path it did not generate — an arbitrary-delete primitive " <>
               "reachable from the launch path"
    end
  end

  # -- Host probe -----------------------------------------------------------

  describe "available?/0" do
    test "reports true on a Darwin host with both facilities, by running the composition" do
      assert Darwin.available?()
      assert %{memory_cap: true, cpu_cap: true, process_separation: true} = Darwin.capabilities()
    end
  end

  defp profile_dir_entries do
    case File.ls(Darwin.profile_dir()) do
      {:ok, entries} -> Enum.sort(entries)
      {:error, _} -> []
    end
  end
end
