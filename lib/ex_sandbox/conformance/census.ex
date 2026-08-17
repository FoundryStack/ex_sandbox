defmodule ExSandbox.Conformance.Census do
  @moduledoc """
  Separates the suite's third outcome from failure **in the exit status**
  (`012-FR-016a`).

  ## The gap this closes

  `FR-016` is about reporting, and the suite already reports well: an
  undemonstrable check prints `NOT DEMONSTRATED (host capability unavailable)`
  and says what would turn it into a pass. What it could not do is make that
  distinction reach a *machine*.

  ExUnit has two outcomes. `ExSandbox.Conformance.Group` turns the third into a
  failure — deliberately, because the alternative is reporting an
  undemonstrated guarantee as green (`FR-012b`), and because ExUnit's skip tag
  resolves before the test runs while `ExSandbox.Capability` answers only at
  runtime. That decision is correct and this module does not revisit it.

  Its consequence is what needed fixing. `mix test` exits non-zero for a
  mechanism defect and non-zero for a host that cannot demonstrate six
  credentials checks, and nothing downstream can tell the two apart. The
  isolation container therefore exited 2 on every green run, so
  `--exit-code-from isolation` carried no information: a genuine containment
  regression would have looked exactly like the six third outcomes that are
  supposed to be there.

  ## What it does, and what it deliberately does not

  It is an `ExUnit` formatter, which means it *observes*. It receives each
  finished test, classifies the failures the suite already decided on, and
  writes a census to `EX_SANDBOX_CENSUS_PATH`. It sets no verdict, rescues
  nothing, and changes no test's outcome — `mix test` still exits non-zero, and
  every third outcome is still printed in full by the default formatter running
  alongside it.

  The caller decides what to do with the census. `docker/run-isolation-tests.sh`
  treats "failures, all of them third outcomes" as a pass and anything else as a
  failure; that policy lives in the caller because it is a caller's judgement,
  not a property of the contract.

  ## Why matching on the message is sound here

  Classification keys on the marker string in
  `ExSandbox.Conformance.Group.not_demonstrated/1`, which is the single place
  the framing is produced — `check/2` and `guarded_setup/1` both route through
  it precisely so they cannot drift. `ExSandbox.ConformanceExclusionsTest`
  asserts the marker still matches, so a reworded message fails a test rather
  than silently reclassifying every third outcome as a defect.

  ⚠️ The failure direction matters and is chosen: an unrecognised message counts
  as a **defect**, never as a third outcome. If this module's matching ever
  breaks, the suite over-reports failures and someone investigates. The opposite
  default would quietly convert real violations into "unavailable" and hand back
  a green exit code, which is the precise artefact this suite exists to prevent.
  """

  use GenServer

  @marker "NOT DEMONSTRATED (host capability unavailable)"

  @doc false
  # ⚠️ The destination is read **once, at init**, and carried in state -- never
  # read again at `suite_finished`.
  #
  # `System.get_env/1` is OS-process-global, and a suite is entitled to change
  # it: this module's own tests set and clear `EX_SANDBOX_CENSUS_PATH` while
  # exercising the formatter. Reading it at write time meant any such test
  # erased the real destination for the whole run, so the census silently went
  # unwritten and the runner reported "the suite did not report" for a suite
  # that had just passed 177 checks. Measured in the isolation container, and
  # reproduced on the host immediately after.
  #
  # Capturing at init makes the formatter independent of anything the suite does
  # to its environment while running, which is the only way a reporter of last
  # resort can be trusted.
  def init(_opts) do
    {:ok,
     %{
       unavailable: [],
       failed: [],
       passed: 0,
       invalid: [],
       path: System.get_env("EX_SANDBOX_CENSUS_PATH")
     }}
  end

  @doc false
  def handle_cast({:test_finished, %ExUnit.Test{state: {:failed, failures}} = test}, state) do
    name = name(test)

    if third_outcome?(failures) do
      {:noreply, %{state | unavailable: [name | state.unavailable]}}
    else
      {:noreply, %{state | failed: [name | state.failed]}}
    end
  end

  def handle_cast({:test_finished, %ExUnit.Test{state: nil} = _test}, state) do
    {:noreply, %{state | passed: state.passed + 1}}
  end

  # ⚠️ `{:invalid, _}` is a **defect**, and counting it was not optional.
  #
  # ExUnit marks every test in a module `{:invalid, module}` -- not `{:failed,
  # _}` -- when its `setup_all` raises. An earlier version of this module let
  # those reach the catch-all below and vanish, so a module whose setup crashed
  # reported `failed=0` and the runner exited **0** for a suite in which not one
  # check ran. Measured, not theorised: a `setup_all` raising produced
  # `passed=0 unavailable=0 failed=0` and a green exit.
  #
  # That is the precise artefact this whole suite exists to prevent, arriving
  # through the reporting layer instead of through the mechanism.
  def handle_cast({:test_finished, %ExUnit.Test{state: {:invalid, _module}} = test}, state) do
    {:noreply, %{state | invalid: [name(test) | state.invalid]}}
  end

  # Skipped and excluded tests are ExUnit's own bookkeeping -- a consumer's tag
  # filter, resolved before the run -- and are not the suite's third outcome.
  # Counting them as unavailable would blur the distinction this module exists
  # to draw. They are still totalled, because "nothing ran" has to be visible.
  def handle_cast({:test_finished, _test}, state), do: {:noreply, state}

  def handle_cast({:suite_finished, _times}, state) do
    write_census(state)
    {:noreply, state}
  end

  def handle_cast(_event, state), do: {:noreply, state}

  defp name(test), do: "#{inspect(test.module)}.#{test.name}"

  # A test carries a list of failures. It counts as a third outcome only when
  # *every* one is -- a check that reported an unavailable capability and also
  # failed an assertion is a defect, and the stricter reading is the safe one.
  defp third_outcome?(failures) do
    failures != [] and
      Enum.all?(failures, fn
        {_kind, reason, _stack} -> message_of(reason) =~ @marker
        _ -> false
      end)
  end

  defp message_of(%{message: message}) when is_binary(message), do: message
  defp message_of(reason) when is_exception(reason), do: Exception.message(reason)
  defp message_of(reason), do: inspect(reason)

  defp write_census(state) do
    case state.path do
      nil ->
        :ok

      path ->
        # `invalid` is reported on the `failed` line as well as its own. A
        # consumer reading only `failed=` must not conclude "no defects" from a
        # run whose modules never started -- the count that gates an exit code
        # has to include every way the suite failed to demonstrate something.
        report = """
        passed=#{state.passed}
        unavailable=#{length(state.unavailable)}
        failed=#{length(state.failed) + length(state.invalid)}
        invalid=#{length(state.invalid)}
        ran=#{state.passed + length(state.unavailable) + length(state.failed) + length(state.invalid)}
        #{Enum.map_join(Enum.sort(state.unavailable), "\n", &"UNAVAILABLE #{&1}")}
        #{Enum.map_join(Enum.sort(state.failed), "\n", &"FAILED #{&1}")}
        #{Enum.map_join(Enum.sort(state.invalid), "\n", &"INVALID (setup_all failed) #{&1}")}
        """

        File.write!(path, report)
    end
  end
end
