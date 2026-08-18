defmodule ExSandbox.Conformance.CensusTest do
  @moduledoc """
  Behavioural tests for the census (`012-FR-016a`).

  ## Why these are not grep assertions

  `ExSandbox.ConformanceExclusionsTest` reads the census's *source* to assert it
  cannot become an exclusion, and that is the right tool for "this code must not
  exist". It is the wrong tool for "this code must behave", and both defects
  these tests pin were invisible to it:

    * a module whose `setup_all` raised reported `failed=0`, because ExUnit
      marks those tests `{:invalid, module}` rather than `{:failed, _}` and the
      catch-all discarded them;
    * a run in which every test was filtered out reported `failed=0` too.

  Both produced a **green exit code for a suite that demonstrated nothing** --
  the artefact `FR-012b` and `SC-008` exist to prevent, reached through the
  reporting layer rather than through the mechanism. Grep saw well-formed code
  in both cases. Only running it showed the hole.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Conformance.Census

  # Drives the formatter directly. The alternative -- booting a nested ExUnit --
  # cannot run inside a suite that is already running, and shelling out to `mix
  # run` would make a unit test depend on compiling the whole app.
  # ⚠️ The destination is injected into the formatter's state, **never** set via
  # `System.put_env/2`. An earlier version of this helper set and then deleted
  # `EX_SANDBOX_CENSUS_PATH` around each call, which is OS-process-global: it
  # wiped the destination the real run had been started with, so the census went
  # unwritten for the entire suite and the container reported "the suite did not
  # report" after passing 177 checks. A test that silences the reporter it is
  # testing is worse than no test, and `async: true` makes the race real.
  defp census(events) do
    path =
      Path.join(
        System.tmp_dir!(),
        "census-#{System.unique_integer([:positive])}.txt"
      )

    {:ok, state} = Census.init([])
    state = %{state | path: path}

    state =
      Enum.reduce(events, state, fn event, acc ->
        {:noreply, next} = Census.handle_cast(event, acc)
        next
      end)

    {:noreply, _} = Census.handle_cast({:suite_finished, %{}}, state)

    on_exit(fn -> File.rm(path) end)

    report = File.read!(path)

    counts =
      ~r/^(\w+)=(\d+)$/m
      |> Regex.scan(report)
      |> Map.new(fn [_, k, v] -> {k, String.to_integer(v)} end)

    {counts, report}
  end

  defp test_finished(state, name \\ :"test a check") do
    {:test_finished, %ExUnit.Test{module: SomeMechanismTest, name: name, state: state}}
  end

  defp unavailable_failure do
    marker =
      ExSandbox.Conformance.Group.not_demonstrated(%ExSandbox.Conformance.CapabilityUnavailable{
        capability: :credential_probe,
        detail: "no data store on this host"
      })

    {:error, %ExUnit.AssertionError{message: marker}, []}
  end

  defp real_failure do
    {:error, %ExUnit.AssertionError{message: "tenant code was not contained"}, []}
  end

  describe "an isolation test that could not launch is the third outcome, not a defect" do
    # ⚠️ The regression this pins was measured, not imagined: with
    # `network_restriction` honestly reporting `false`, the container census
    # read `passed=330 unavailable=0 failed=19`. All nineteen were
    # `@tag :isolation` tests whose guarantees had not stopped holding -- there
    # was simply no sandbox to demonstrate them in, because the mechanism
    # correctly refused to launch one.
    #
    # `IsolationLaunch` already raised a *distinct exception type* for exactly
    # this case, and that was not enough: the census classifies by the marker
    # string, so a distinct type with an unmarked message counts as a defect.
    # The type made the cause legible to a human reading the log and invisible
    # to the counter that gates the exit code.
    test "the raise from provision_or_skip carries the census marker" do
      # Raised for real rather than hand-built. A test asserting on a string it
      # constructed itself would keep passing if `raise_skip/1` stopped framing
      # its message -- which is precisely the defect being pinned.
      error =
        assert_raise ExSandbox.Test.IsolationLaunch.Unavailable, fn ->
          ExSandbox.Test.IsolationLaunch.provision_or_skip(
            ExSandbox.Test.IsolationLaunch.RefusingMechanism,
            %ExSandbox.Sandbox{id: "probe", owner_ref: "t", template_ref: "x"}
          )
        end

      {counts, report} = census([test_finished({:failed, [{:error, error, []}]})])

      assert counts["unavailable"] == 1,
             "a test that could not launch must count as the third outcome, got:\n#{report}"

      assert counts["failed"] == 0,
             "a host limitation must not be reported as a breached guarantee, got:\n#{report}"
    end

    test "a genuine isolation failure is still counted as a defect" do
      # The mirror case, and the one that makes the test above mean something.
      # A classifier that called *everything* from these tests unavailable would
      # satisfy the assertion above and destroy the suite -- the fail-open shape
      # this whole census exists to prevent.
      {counts, report} = census([test_finished({:failed, [real_failure()]})])

      assert counts["failed"] == 1,
             "a real breach must still be a failure, got:\n#{report}"

      assert counts["unavailable"] == 0
    end
  end

  describe "the reporter cannot be silenced by the suite it reports on" do
    test "the destination is captured at init, not read at write time" do
      # The regression this pins, measured in the isolation container: reading
      # `EX_SANDBOX_CENSUS_PATH` at `suite_finished` let any test that touched
      # that variable erase the run's destination. The census went unwritten,
      # the runner correctly refused to call an unreported run a pass, and a
      # suite that had just passed 177 checks reported as a failure.
      System.put_env("EX_SANDBOX_CENSUS_PATH", "/dev/null/definitely-not-writable")
      {:ok, state} = Census.init([])
      System.delete_env("EX_SANDBOX_CENSUS_PATH")

      assert state.path == "/dev/null/definitely-not-writable",
             "init/1 must capture the destination into state"

      # Deleting the variable after init must not affect the write.
      path = Path.join(System.tmp_dir!(), "census-init-#{System.unique_integer([:positive])}.txt")
      on_exit(fn -> File.rm(path) end)

      {:noreply, _} =
        Census.handle_cast({:suite_finished, %{}}, %{state | path: path, passed: 1})

      assert File.exists?(path),
             "the census must write to the destination captured at init even after " <>
               "the environment variable is gone"
    end
  end

  describe "the three outcomes are counted apart (FR-016a)" do
    test "a pass, a third outcome, and a defect land in different buckets" do
      {counts, report} =
        census([
          test_finished(nil, :"test passes"),
          test_finished({:failed, [unavailable_failure()]}, :"test unavailable"),
          test_finished({:failed, [real_failure()]}, :"test defect")
        ])

      assert counts["passed"] == 1
      assert counts["unavailable"] == 1
      assert counts["failed"] == 1
      assert report =~ "UNAVAILABLE"
      assert report =~ "FAILED"
    end

    test "an unrecognised failure counts as a defect, never as unavailable" do
      # The safety direction: if the marker ever stops matching, the census must
      # over-report defects so someone investigates -- not convert real
      # violations into "unavailable" and hand back a green exit.
      {counts, _} = census([test_finished({:failed, [real_failure()]})])

      assert counts["failed"] == 1
      assert counts["unavailable"] == 0
    end

    test "a check that is both unavailable and failed counts as a defect" do
      # `Enum.all?`, not `Enum.any?`. A check that reported a missing capability
      # *and* blew an assertion has a defect in it, and the stricter reading is
      # the one that cannot hide it.
      {counts, _} =
        census([test_finished({:failed, [unavailable_failure(), real_failure()]})])

      assert counts["failed"] == 1
      assert counts["unavailable"] == 0
    end
  end

  describe "a suite that demonstrated nothing is never a pass (FR-012b)" do
    test "a module whose setup_all raised counts as a defect" do
      # ⚠️ The regression this pins. ExUnit marks these `{:invalid, module}`,
      # not `{:failed, _}`. An earlier census let them reach its catch-all and
      # vanish: `failed=0`, exit 0, for a run where no check executed.
      {counts, report} =
        census([test_finished({:invalid, %ExUnit.TestModule{name: SomeMechanismTest}})])

      assert counts["invalid"] == 1

      assert counts["failed"] == 1,
             "an invalid module must be counted on the `failed` line -- a consumer " <>
               "gating on `failed=` would otherwise read a crashed setup_all as clean"

      assert report =~ "INVALID (setup_all failed)"
    end

    test "a run where every test was filtered out reports ran=0" do
      # The other route to a green exit for a suite that verified nothing: a
      # mistyped `--include`, a stale tag filter, a suite that failed to load.
      # `failed=0` is true and meaningless; `ran=0` is what the runner gates on.
      {counts, _} = census([])

      assert counts["ran"] == 0
      assert counts["failed"] == 0
    end

    test "ran counts every outcome, not only passes" do
      {counts, _} =
        census([
          test_finished(nil, :"test a"),
          test_finished({:failed, [unavailable_failure()]}, :"test b"),
          test_finished({:failed, [real_failure()]}, :"test c"),
          test_finished({:invalid, %ExUnit.TestModule{name: SomeMechanismTest}}, :"test d")
        ])

      assert counts["ran"] == 4
    end

    test "skipped and excluded tests are not counted as demonstrated" do
      # They are ExUnit's own bookkeeping, resolved before the run, and are not
      # the suite's third outcome. Counting them as `passed` would let a fully
      # skipped suite look demonstrated.
      {counts, _} =
        census([
          test_finished({:skipped, "not today"}, :"test a"),
          test_finished({:excluded, "filtered"}, :"test b")
        ])

      assert counts["passed"] == 0
      assert counts["unavailable"] == 0
      assert counts["failed"] == 0
    end
  end
end
