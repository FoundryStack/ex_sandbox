defmodule ExSandbox.Hardening.DarwinCapabilityTest do
  @moduledoc """
  The report is checked against the host by **attempting what it says is
  prevented** (014 T016, T018; `SC-006`, `SC-006a`).

  ## Why the quantifier is structural

  `SC-006` says *for every capability reported enforced*. A file that happened
  to breach three of four would satisfy every assertion in it while leaving the
  fourth claimed and unverified — which is the same defect as a cap that is
  configured and silently not applied, moved one layer out.

  So `@attempts` below is compared against `Hardening.Darwin.capabilities/0`
  itself: a capability that starts reporting `true` with no breach attempt here
  fails this file, before it fails anything else. That comparison is the first
  test in the file for that reason.

  ## ⚠️ `:cpu_cap` is a TOTAL, and this file says so rather than pretending

  Phase 3 Finding D: the backend derives `ulimit -t` as
  `ceil(wall_clock_seconds × cpu_millicores ÷ 1000)`. `ulimit -t` is a ceiling
  on **CPU-seconds consumed**; `cpu_millicores` names a **rate**. A process
  nominally capped at 100 millicores over a 60 s budget receives 6 CPU-seconds
  and is free to burn them flat out in 6 wall-seconds — it is never throttled
  to 10% of a core.

  The operation attempted here is therefore *exceeding a CPU-second total*,
  which is the operation actually prevented. A rate-breach attempt would be a
  check that cannot fail, the shape T008 was already amended for. The rate is
  covered too, in the opposite direction: `the rate is NOT enforced` measures
  the gap and requires it to still be there, so that a future rate mechanism
  turns that test red instead of leaving a stale claim behind.

  ## `SC-006a`: a degraded host must not collapse to a summary level

  This host reports `:disk_quota`, `:network_restriction`,
  `:privilege_separation` and the coarse `:resource_limits` unavailable while
  reporting three per-capability names available. The tests at the bottom
  require the report to keep saying exactly that — distinct verdicts, distinct
  reasons, and a run that still happens.
  """

  use ExUnit.Case, async: false

  # ⚠️ Required. `test_helper.exs` excludes `:darwin_hardening` off Darwin, and
  # the exclusion only reaches a module that tags itself. Untagged, every test
  # below runs on Linux CI against `sandbox-exec` and `taskpolicy`, which are
  # not there.
  @moduletag :darwin_hardening

  # The CPU-total attempt spends its ceiling on purpose, twice.
  @moduletag timeout: 240_000

  alias ExSandbox.Capability
  alias ExSandbox.Hardening.Darwin

  # ⚠️ One entry per capability `Hardening.Darwin.capabilities/0` can report
  # enforced, naming the operation this file attempts for it. The first test
  # requires this map's keys to cover everything reported `true`.
  @attempts %{
    memory_cap: "allocate 300 MB under a 150 MB cap",
    cpu_cap: "consume more CPU-seconds than the derived `ulimit -t` ceiling",
    process_separation: "execute inside the platform's own OS process",
    filesystem_confinement: "write outside the workdir, and read a denied subpath"
  }

  @breach_budget_ms 60_000

  setup_all do
    unless match?({:unix, :darwin}, :os.type()) do
      raise """
      ExSandbox.Hardening.DarwinCapabilityTest ran on #{inspect(:os.type())}.

      Every attempt below breaches a macOS mechanism. Refusing rather than
      skipping quietly — `005` R9 records three isolation tests that passed
      against a mechanism that never ran. Exclude the `:darwin_hardening` tag
      (014 T003) instead.
      """
    end

    dir =
      Path.join(System.tmp_dir!(), "ex_sandbox_darwin_caps_#{System.unique_integer([:positive])}")

    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)

    source_dir = Path.join(__DIR__, "../support/darwin_fixtures") |> Path.expand()

    bins =
      Map.new(~w(hog spin_nolimit crash), fn name ->
        out = Path.join(dir, name)
        src = Path.join(source_dir, name <> ".c")

        # `-O0`: an optimiser is entitled to delete a loop whose result is
        # unused and to elide a null store as undefined behaviour. Either turns
        # a breach attempt into a program that exits 0 immediately.
        case System.cmd("cc", ["-O0", "-o", out, src], stderr_to_stdout: true) do
          {_out, 0} -> {name, out}
          {text, status} -> raise "cc failed for #{src} (status #{status}):\n#{text}"
        end
      end)

    {:ok, bins: bins, dir: dir}
  end

  # -- SC-006's quantifier --------------------------------------------------

  describe "every capability reported enforced is attempted here (SC-006)" do
    test "the set of breach attempts covers everything capabilities/0 reports true" do
      enforced =
        Darwin.capabilities()
        |> Enum.filter(fn {_name, present?} -> present? end)
        |> Enum.map(&elem(&1, 0))
        |> MapSet.new()

      attempted = @attempts |> Map.keys() |> MapSet.new()

      unattempted = MapSet.difference(enforced, attempted) |> MapSet.to_list() |> Enum.sort()

      assert unattempted == [],
             """
             `Hardening.Darwin.capabilities/0` reports #{inspect(unattempted)} enforced, \
             and nothing in this file attempts the operation #{if length(unattempted) == 1,
               do: "it claims",
               else: "they claim"} to prevent.

             `SC-006` is a quantifier over the whole reported set, not over the subset \
             somebody remembered to test. A claimed-and-unverified capability is the same \
             defect as a cap that is configured and silently not applied -- one layer out.

             Add the attempt to `@attempts` and write it, or stop reporting the capability.
             """

      # The other direction, kept loose on purpose: an attempt for a capability
      # this host cannot construct is not a defect (a host without `taskpolicy`
      # reports `:memory_cap` false), but an attempt for a name the backend does
      # not answer at all is a stale entry.
      unknown =
        MapSet.difference(attempted, Darwin.capabilities() |> Map.keys() |> MapSet.new())

      assert MapSet.to_list(unknown) == [],
             "this file attempts #{inspect(MapSet.to_list(unknown))}, which " <>
               "`capabilities/0` does not report on at all"
    end
  end

  # -- :memory_cap ----------------------------------------------------------

  describe ":memory_cap — the attempt is to exceed the cap" do
    @tag :capability_attempt
    test "300 MB under a 150 MB cap is stopped, and had really started", ctx do
      assert Darwin.capabilities()[:memory_cap],
             "this host does not report :memory_cap enforced, so there is nothing to verify " <>
               "-- and this test would otherwise pass vacuously"

      result = run({ctx.bins["hog"], ["300"]}, caps(), budget_ms: @breach_budget_ms)

      assert result.outcome == {:exit_status, 137},
             "the allocation was not stopped: #{inspect(result.outcome)}"

      # ⚠️ The half that makes 137 mean "stopped by the cap". A program that
      # never ran also exits non-zero, and `005` R9 recorded exactly that being
      # read as a cap holding.
      assert result.output =~ "mb 100\n",
             "the hog never reached 100 MB, so nothing distinguishes the cap from a " <>
               "failure to start. Output:\n#{tail(result.output)}"

      refute result.output =~ "allocated 300 MB OK"
    end
  end

  # -- :cpu_cap -------------------------------------------------------------

  describe ":cpu_cap — the attempt is to exceed a CPU-second TOTAL" do
    @tag :capability_attempt
    test "a spinner that never limits itself exceeds the derived ceiling and is killed", ctx do
      assert Darwin.capabilities()[:cpu_cap]

      # 1000 millicores over a 2 s budget derives a 2 CPU-second ceiling.
      result =
        run(
          {ctx.bins["spin_nolimit"], []},
          %{memory_mb: 150, cpu_millicores: 1000, wall_clock_seconds: 2},
          budget_ms: 30_000
        )

      assert result.outcome == {:exit_status, 152},
             "expected 152 (128 + SIGXCPU); got #{inspect(result.outcome)}"

      assert result.output =~ "spinning",
             "the spinner never announced itself, so it may have died before spinning"
    end

    @tag :capability_attempt
    test "the same spinner under a ceiling it cannot reach is NOT killed — the control", ctx do
      # ⚠️ Without this, the 152 above could be the binary limiting itself
      # (`005` R9b's `spin.c` does exactly that, T002 Finding 1) and the
      # assertion would pass whether or not the platform imposed anything.
      result =
        run(
          {ctx.bins["spin_nolimit"], []},
          %{memory_mb: 150, cpu_millicores: 1000, wall_clock_seconds: 600},
          budget_ms: 6_000
        )

      assert match?({:wall_clock_timeout, _}, result.outcome),
             "the spinner terminated on its own with #{inspect(result.outcome)} under a " <>
               "600 CPU-second ceiling it cannot have reached in 6 wall-seconds. If it " <>
               "stops here, the capped case says nothing about the platform"
    end

    @tag :capability_attempt
    test "the RATE is not enforced, and :cpu_cap must not be read as claiming it", ctx do
      # ⚠️ Phase 3 Finding D, measured rather than argued.
      #
      # 100 millicores over a 60 s budget derives ceil(60 × 100 ÷ 1000) = 6
      # CPU-seconds. If `:cpu_cap` meant a *rate*, this process would be held to
      # 10% of a core and would take ~60 wall-seconds to spend those 6
      # CPU-seconds. It does not: it runs flat out and dies at ~6 wall-seconds.
      #
      # This test exists so the gap cannot go stale. A future rate mechanism
      # turns it red, which is a demand to update the claim rather than a
      # silently obsolete one.
      started = System.monotonic_time(:millisecond)

      result =
        run(
          {ctx.bins["spin_nolimit"], []},
          %{memory_mb: 150, cpu_millicores: 100, wall_clock_seconds: 60},
          budget_ms: 90_000
        )

      elapsed = System.monotonic_time(:millisecond) - started

      assert result.outcome == {:exit_status, 152},
             "the CPU-second TOTAL was not enforced either: #{inspect(result.outcome)}"

      assert elapsed < 25_000,
             """
             the spinner took #{elapsed} ms to exhaust a 6 CPU-second ceiling.

             That is what a RATE cap of 100 millicores would look like (~60 s), and this \
             host does not have one -- so either macOS has grown a rate mechanism this \
             backend is now using, or the derivation changed. Either way `:cpu_cap`'s \
             meaning has moved and the report has to move with it.
             """

      assert elapsed > 3_000,
             "the spinner died in #{elapsed} ms, well under the 6 CPU-seconds it was " <>
               "given; it was stopped by something other than the ceiling"
    end
  end

  # -- :process_separation --------------------------------------------------

  describe ":process_separation — the attempt is to run inside the platform" do
    @tag :capability_attempt
    test "the target executes as its own OS process, not this VM's" do
      assert Darwin.capabilities()[:process_separation]

      # The target reports the process it is actually running in. `$$` is
      # resolved by the inner shell at runtime; every layer of the composition
      # `exec`s, so this is the pid the platform spawned.
      result = run({"/bin/sh", ["-c", "echo $$"]}, caps())

      assert result.outcome == {:exit_status, 0}

      target_pid = result.output |> String.trim() |> String.to_integer()
      platform_pid = String.to_integer(System.pid())

      refute target_pid == platform_pid,
             """
             the target reported pid #{target_pid}, which is this BEAM's own.

             `:process_separation` claims generated code does not execute in the \
             platform's process. If those pids ever agree, it does -- and every other \
             guarantee in this file is being measured inside the thing it is meant to \
             protect.
             """

      # And it really was a live, separate process that has since ended.
      assert target_pid > 0

      assert {_, 1} =
               System.cmd("/bin/kill", ["-0", to_string(target_pid)], stderr_to_stdout: true)
    end

    @tag :capability_attempt
    test "a hard crash in the target does not reach the platform process", ctx do
      result = run({ctx.bins["crash"], []}, caps())

      assert result.outcome == {:exit_status, 139}
      assert result.output =~ "crashing"

      # The platform is still there — asserted against the OS rather than
      # against the fact that this line is executing, which would be true
      # whatever happened.
      assert {_, 0} = System.cmd("/bin/kill", ["-0", System.pid()], stderr_to_stdout: true)
    end
  end

  # -- :filesystem_confinement ---------------------------------------------

  describe ":filesystem_confinement — the attempt is to write out and read in" do
    @tag :capability_attempt
    test "a write outside the workdir fails, and the same write inside it succeeds", ctx do
      assert Darwin.capabilities()[:filesystem_confinement]

      workdir = fresh_dir(ctx, "wd")
      outside = fresh_dir(ctx, "outside")

      denied = Path.join(outside, "ESCAPED")
      permitted = Path.join(workdir, "allowed")

      escape = run({"/usr/bin/touch", [denied]}, caps(), workdir: workdir)

      assert match?({:exit_status, status} when status != 0, escape.outcome),
             "touching #{denied} succeeded from inside the sandbox: #{inspect(escape.outcome)}"

      refute File.exists?(denied),
             "the write outside the workdir landed; `(deny file-write*)` did not hold"

      # ⚠️ The control. A profile that denied *everything* — which is what a
      # broken workdir grant produces, and what R30 measured as `134` on every
      # case including the control — would pass the assertion above while
      # confining nothing meaningfully.
      inside = run({"/usr/bin/touch", [permitted]}, caps(), workdir: workdir)

      assert inside.outcome == {:exit_status, 0},
             "the permitted write also failed (#{inspect(inside.outcome)}), so the denial " <>
               "above measures a broken profile rather than a boundary"

      assert File.exists?(permitted)
    end

    @tag :capability_attempt
    test "a read of a denied subpath fails, and a read beside it succeeds", ctx do
      workdir = fresh_dir(ctx, "wd-read")
      home = fresh_dir(ctx, "home")

      # The profile denies `file-read*` under `<home>/Documents` and
      # `<home>/.ssh`. Built here rather than aimed at the real home directory,
      # so the test is deterministic on a host where neither exists.
      File.mkdir_p!(Path.join(home, "Documents"))
      File.write!(Path.join([home, "Documents", "secret.txt"]), "denied")
      File.write!(Path.join(home, "public.txt"), "permitted")

      opts = [workdir: workdir, home: home]

      denied =
        run({"/bin/cat", [Path.join([home, "Documents", "secret.txt"])]}, caps(), opts)

      assert match?({:exit_status, status} when status != 0, denied.outcome),
             "the denied subpath was read: #{inspect(denied.outcome)}"

      refute denied.output =~ "denied",
             "the file's contents came back despite the deny rule:\n#{tail(denied.output)}"

      permitted = run({"/bin/cat", [Path.join(home, "public.txt")]}, caps(), opts)

      assert permitted.outcome == {:exit_status, 0},
             "the readable file beside it also failed, so the denial above is not a " <>
               "boundary — it is a sandbox that cannot read anything"

      assert permitted.output =~ "permitted"
    end
  end

  # -- T018: the degraded host ---------------------------------------------

  describe "a degraded host still runs and still reports per capability (T018, SC-006a)" do
    test "capabilities reported unavailable do not stop the deployment running" do
      # This host reports several capabilities unavailable. `SC-006a` requires
      # that it still runs; a deployment that refused to start on such a host
      # fails the criterion just as a silently downgraded report does.
      unavailable =
        Capability.check_all()
        |> Enum.reject(& &1.available?)
        |> Enum.map(& &1.name)

      assert unavailable != [],
             "no capability is unavailable on this host, so this test verifies nothing " <>
               "about a degraded one. `SC-006a` is checked by RUNNING on such a host, " <>
               "not by simulating it — if macOS has grown all of these, say so " <>
               "deliberately rather than deleting the test"

      assert :disk_quota in unavailable
      assert :network_restriction in unavailable

      result = run({"/bin/echo", ["still running"]}, caps())

      assert result.outcome == {:exit_status, 0},
             "the deployment did not run on a host with #{inspect(unavailable)} " <>
               "unavailable: #{inspect(result.outcome)}"

      assert result.output =~ "still running"
    end

    test "the report does NOT collapse to a single summary level" do
      report = Capability.check_all()
      verdicts = report |> Enum.map(& &1.available?) |> Enum.uniq()

      assert length(verdicts) == 2,
             """
             every capability reports #{inspect(hd(verdicts))} on this host.

             `SC-006a` fails on a report that downgrades to one summary answer. This host \
             enforces some caps and not others, and the report has to be able to say so.

             #{format(report)}
             """

      # ⚠️ The sharpest form of the same property, and the one `FR-013a` was
      # written for. The COARSE name and its per-capability decomposition
      # disagree here, deliberately: there is no cgroup v2 scope on macOS, so
      # `:resource_limits` is unavailable, while the memory and CPU caps are
      # separately enforced by a different mechanism and reported so.
      #
      # A report that collapsed the decomposition into its summary would have to
      # lie in one direction or the other. That it does not is the whole of
      # `014-FR-013a`.
      refute Capability.check(:resource_limits).available?

      for name <- [:memory_cap, :cpu_cap, :process_separation] do
        assert Capability.check(name).available?,
               "#{inspect(name)} follows `:resource_limits` down on macOS, which is the " <>
                 "collapse `FR-013a` exists to prevent"
      end
    end

    test "each unavailable capability names its OWN cause, not a shared summary" do
      unavailable = Capability.check_all() |> Enum.reject(& &1.available?)

      for report <- unavailable do
        assert is_binary(report.detail) and report.detail != "",
               "#{inspect(report.name)} is unavailable with no detail; `FR-016` requires " <>
                 "saying why"
      end

      details = Enum.map(unavailable, & &1.detail)

      assert length(Enum.uniq(details)) == length(details),
             """
             two capabilities share a detail string, so the report is explaining them \
             with one sentence:

             #{format(unavailable)}

             A shared reason is a summary level wearing per-capability clothes. The \
             remedy differs per capability, which is why `FR-016` asks for four \
             distinguishable outcomes and not one.
             """
    end

    test "the backend's own map is per capability too, not one boolean" do
      caps = Darwin.capabilities()

      assert map_size(caps) > 1
      assert Enum.all?(Map.values(caps), &is_boolean/1)

      # `available?/0` is the summary, and it is DERIVED from the map rather
      # than being the only thing on offer. A backend that exposed only the
      # summary could not feed a per-capability report at all.
      assert Darwin.available?() == Enum.all?(Map.values(caps))
    end
  end

  # -- Harness --------------------------------------------------------------

  defp caps, do: %{memory_mb: 150, cpu_millicores: 1000, wall_clock_seconds: 30}

  # Launches the spec the way a caller must: `spec.cmd` with `spec.args`, never
  # the command that was asked about. Enforces the wall-clock budget itself,
  # standing in for the supervisor — nothing in a launch spec can kill a process
  # later.
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

        # Every layer `exec`s, so this single pid IS the target.
        if os_pid, do: System.cmd("/bin/kill", ["-KILL", to_string(os_pid)])

        %{
          outcome: {:wall_clock_timeout, os_pid},
          output: acc |> Enum.reverse() |> IO.iodata_to_binary()
        }
    end
  end

  defp fresh_dir(ctx, prefix) do
    dir = Path.join(ctx.dir, "#{prefix}-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    dir
  end

  defp format(reports) do
    Enum.map_join(reports, "\n", fn r ->
      "  #{inspect(r.name)}: #{r.available?} — #{String.slice(r.detail || "", 0, 90)}"
    end)
  end

  defp tail(output), do: output |> String.split("\n") |> Enum.take(-5) |> Enum.join("\n")
end
