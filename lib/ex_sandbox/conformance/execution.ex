defmodule ExSandbox.Conformance.Execution do
  @moduledoc """
  Conformance group: running a command inside a sandbox (008 T005).

  ## Every limit check breaches, and nothing here inspects configuration

  `003-FR-012a` is the rule and `005` R9b is the reason:

      taskpolicy -m 100 sandbox-exec -f profile.sb ./hog 300

  allocates 300 MB under a nominal 100 MB cap and **exits 0**. The limiter was
  invoked, with the right flag and the right number, and the cap is silently
  lost across the intervening `exec`. So a check that asserted `execute/3`
  passed the cap along, or that the launch names it, or that the command exited
  cleanly, would certify that composition as conformant.

  Each check here therefore *runs a hostile command through the seam* and
  requires the mechanism to show it was stopped. An attempt that neither
  completed its hostile act nor was visibly stopped is the third outcome —
  `host capability unavailable` — never a pass (`FR-012b`).

  ## The check that is not about a limit at all

  `execute/3` against a **destroyed** sandbox must answer
  `{:error, {:could_not_run, _}}`. A mechanism that answers with a non-zero exit
  status instead has converted an *unperformed* check into a *failed* one, and
  `008-FR-026` says a failed check spends a refinement iteration that an
  unperformed one must not. That defect is invisible from every layer above:
  both shapes are "the verification did not pass", and only here can the two be
  told apart — which is why the check lives in the conformance suite rather than
  in `008`'s own tests.

  ## Separation and truncation are checked by producing them, not by reading a doc

  A command writes a known string to `stderr` and a different one to `stdout`,
  and the check requires each to arrive in its own field. `015` R17 measured
  `MuonTrap`'s `:logger_fun` corrupting lines past a 256-byte buffer, so the
  long-line check emits a single line an order of magnitude past that and
  requires it back byte-identically: a mechanism whose capture reframes output
  into lines fails here rather than in someone's build log.
  """

  # A single line far past `015` R17's 256-byte buffer. Long enough that no
  # plausible line buffer accommodates it, short enough to compare cheaply.
  @long_line_bytes 4096

  @doc "Emits the execution checks into the calling test module."
  defmacro tests do
    quote do
      require ExSandbox.Conformance.Group
      import ExSandbox.Conformance.Group, only: [check: 2]

      describe "execution (008 FR-002, FR-016; 003 FR-012a)" do
        # Selects this group for `mix test --only conformance:execution`.
        @describetag conformance: :execution

        check "a command runs inside the sandbox and reports its own exit status" do
          ExSandbox.Conformance.Execution.assert_runs(@mechanism)
        end

        check "stdout and stderr arrive separately" do
          ExSandbox.Conformance.Execution.assert_streams_separated(@mechanism)
        end

        check "a line far longer than any buffer comes back byte-identical" do
          ExSandbox.Conformance.Execution.assert_long_line_intact(@mechanism)
        end

        check "output past the capture limit is reported as truncated, not silently dropped" do
          ExSandbox.Conformance.Execution.assert_truncation_declared(@mechanism)
        end

        check "a destroyed sandbox answers could_not_run, never an exit status" do
          ExSandbox.Conformance.Execution.assert_could_not_run_when_destroyed(@mechanism)
        end

        check "a command allocating past the memory cap is stopped" do
          demonstrate_breach(:resource_limits, "003-FR-004", fn ->
            ExSandbox.Conformance.Execution.breach(
              @mechanism,
              build_sandbox(memory_limit_mb: 64),
              ExSandbox.Conformance.ResourceLimits.memory_hog_command(192),
              :memory
            )
          end)
        end

        check "a command spinning past the CPU cap is throttled or stopped" do
          demonstrate_breach(:resource_limits, "003-FR-004", fn ->
            ExSandbox.Conformance.Execution.breach(
              @mechanism,
              build_sandbox(cpu_limit: 100),
              ExSandbox.Conformance.ResourceLimits.cpu_hog_command(),
              :cpu
            )
          end)
        end

        check "a command blocking past the time budget is stopped" do
          demonstrate_breach(:resource_limits, "003-FR-004", fn ->
            ExSandbox.Conformance.Execution.breach(
              @mechanism,
              build_sandbox(context: %{timeout_ms: 2_000}),
              ExSandbox.Conformance.ResourceLimits.sleep_command(60),
              :time
            )
          end)
        end

        check "a could-not-run result is never classified as a stopped breach" do
          # T034b's shape applied to this group, and a self-check on the one
          # place the fail-open mistake would live. `:could_not_run` means the
          # command never ran; scoring it as a cap taking effect would report
          # every mechanism conformant on every limit without executing a byte.
          result =
            ExSandbox.Conformance.Execution.classify(
              {:error, {:could_not_run, :unknown_sandbox}},
              :memory,
              64,
              nil
            )

          # Asserted positively -- `{:inconclusive, _}` rather than "not
          # `{:stopped, _}`" -- because the negative form is a claim the
          # compiler can discharge statically here, and a check the compiler can
          # discharge is a check that stops measuring the day someone edits
          # `classify/4`.
          assert_guarantee(
            match?({:inconclusive, _}, result),
            "012-FR-012b",
            "an attempt that could not run was not classified as inconclusive. " <>
              "Anything else -- `{:stopped, _}` above all -- reports a cap as " <>
              "demonstrated by an attempt that never happened. Got " <> inspect(result)
          )
        end

        check "a completed breach is never classified as stopped" do
          # The other half, and the R9b shape exactly: the command ran, exited
          # 0, and printed its completion marker. A group that let this read as
          # `:stopped` would certify a cap that does not exist.
          result =
            ExSandbox.Conformance.Execution.classify(
              {:ok,
               %{
                 exit_status: 0,
                 stdout: "ALLOCATED-PAST-CAP\n",
                 stderr: "",
                 truncated?: false
               }},
              :memory,
              64,
              nil
            )

          assert_guarantee(
            match?({:breached, _}, result),
            "012-FR-012a",
            "a hostile command that ran to completion and printed its own " <>
              "completion marker was not classified as a breach. Got " <> inspect(result)
          )
        end
      end
    end
  end

  import ExSandbox.Conformance.Helpers

  alias ExSandbox.Conformance.Helpers

  @doc false
  def long_line_bytes, do: @long_line_bytes

  @doc """
  Runs a trivial command and requires the mechanism to report the command's own
  exit status.

  ⚠️ The status asserted is **not** zero. A mechanism that mapped every failure
  onto a non-zero exit would pass a zero-status check, and a mechanism that
  mapped every non-zero status onto an error would pass it too. Asking for a
  specific, unusual, non-zero status is what distinguishes "the command ran and
  this is its answer" from either.
  """
  def assert_runs(mechanism) do
    with_sandbox(mechanism, fn mechanism, sandbox ->
      case ExSandbox.execute(mechanism, sandbox, {"/bin/sh", ["-c", "exit 42"]}) do
        {:ok, %{exit_status: 42}} ->
          :ok

        {:ok, other} ->
          guarantee_failure("008-FR-002", """
          The command ran but its exit status did not survive the seam.

          Asked for `exit 42`, got #{inspect(other)}. A caller cannot tell a
          failing check from a passing one if the status is synthesised.
          """)

        other ->
          undemonstrable(
            "a trivial command could not be run inside this sandbox: #{inspect(other)}"
          )
      end
    end)
  end

  @doc """
  Requires `stdout` and `stderr` to be attributable, by producing both.
  """
  def assert_streams_separated(mechanism) do
    with_sandbox(mechanism, fn mechanism, sandbox ->
      command = {"/bin/sh", ["-c", "printf OUT-MARKER; printf ERR-MARKER 1>&2"]}

      case ExSandbox.execute(mechanism, sandbox, command) do
        {:ok, %{stdout: out, stderr: err}} ->
          assert_guarantee(
            out =~ "OUT-MARKER" and not (out =~ "ERR-MARKER"),
            "008-FR-002",
            "stderr leaked into stdout, so a failure cannot be attributed to a " <>
              "stream. stdout was #{inspect(out)}"
          )

          assert_guarantee(
            err =~ "ERR-MARKER",
            "008-FR-002",
            "stderr was not captured at all; it was #{inspect(err)}. A mechanism " <>
              "that discards stderr reports a build failure with no diagnosis."
          )

        other ->
          undemonstrable("the two-stream command could not be run: #{inspect(other)}")
      end
    end)
  end

  @doc """
  Requires a single line past any plausible buffer to survive intact
  (`015` R17).
  """
  def assert_long_line_intact(mechanism) do
    with_sandbox(mechanism, fn mechanism, sandbox ->
      line = String.duplicate("A", @long_line_bytes)
      command = {"/bin/sh", ["-c", ~s(printf %s "$1"), "sh", line]}

      case ExSandbox.execute(mechanism, sandbox, command) do
        {:ok, %{stdout: out, truncated?: false}} ->
          assert_guarantee(
            out == line,
            "008-FR-002",
            """
            A #{@long_line_bytes}-byte line did not survive capture intact.

            Got #{byte_size(out)} bytes. `015` R17 measured exactly this defect in
            `MuonTrap`'s `:logger_fun`, where a line past a 256-byte buffer comes
            back corrupted. A capture that reframes output into lines loses the
            content of any line longer than its buffer, and the loss is silent.
            """
          )

        {:ok, %{truncated?: true}} ->
          undemonstrable(
            "the mechanism's capture limit is below #{@long_line_bytes} bytes, so " <>
              "this check cannot distinguish a line buffer from a byte limit"
          )

        other ->
          undemonstrable("the long-line command could not be run: #{inspect(other)}")
      end
    end)
  end

  @doc """
  Requires truncation to be **declared**, by producing more output than the
  mechanism will keep.

  ⚠️ The assertion is not "output was truncated" — a mechanism with a generous
  limit legitimately truncates nothing. It is that `truncated?` and the bytes
  returned agree: if bytes were dropped the flag says so. Silent truncation of a
  build log is how a real error disappears from a diagnosis.
  """
  def assert_truncation_declared(mechanism) do
    with_sandbox(mechanism, fn mechanism, sandbox ->
      # Ten megabytes, which is past any defensible default and cheap to make.
      command =
        {"/bin/sh", ["-c", "i=0; while [ $i -lt 10240 ]; do printf %1024d 1; i=$((i+1)); done"]}

      case ExSandbox.execute(mechanism, sandbox, command) do
        {:ok, %{stdout: out, truncated?: truncated?}} ->
          produced = 10_240 * 1024

          assert_guarantee(
            byte_size(out) >= produced or truncated?,
            "008-FR-002",
            """
            The command produced #{produced} bytes on stdout, #{byte_size(out)} came
            back, and `truncated?` was false.

            Output was dropped and the caller is not told. A build log missing its
            tail reads exactly like a build log that ended there.
            """
          )

        other ->
          undemonstrable("the high-volume command could not be run: #{inspect(other)}")
      end
    end)
  end

  @doc """
  Runs a command, destroys the sandbox, and runs the same command again.

  The whole of `008-FR-016`/`FR-026` rests on the second answer being
  `{:error, {:could_not_run, _}}` rather than a non-zero exit status — and on
  the first one succeeding, without which the second proves nothing.
  """
  def assert_could_not_run_when_destroyed(mechanism) do
    sandbox = Helpers.build_sandbox()
    provisioned = Helpers.provision_or_report(mechanism, sandbox)

    started =
      case ExSandbox.start(mechanism, provisioned) do
        {:ok, started} -> started
        other -> undemonstrable("the sandbox could not be started: #{inspect(other)}")
      end

    # ⚠️ The live half first, and it is not ceremony. Without it a mechanism
    # that answers `:could_not_run` to *everything* -- one that cannot execute
    # at all -- passes this check while having demonstrated nothing about
    # destruction. Establishing that the same command succeeds while the sandbox
    # is alive is what makes the refusal afterwards attributable to the destroy.
    case ExSandbox.execute(mechanism, started, {"/bin/sh", ["-c", "exit 0"]}) do
      {:ok, _} ->
        :ok

      other ->
        ExSandbox.destroy(mechanism, started)

        undemonstrable(
          "the same command did not run while the sandbox was alive (#{inspect(other)}), " <>
            "so a refusal after destroying it says nothing about the destroy"
        )
    end

    :ok = ExSandbox.destroy(mechanism, started)

    case ExSandbox.execute(mechanism, started, {"/bin/sh", ["-c", "exit 0"]}) do
      {:error, {:could_not_run, _reason}} ->
        :ok

      {:ok, completion} ->
        guarantee_failure("008-FR-016", """
        A destroyed sandbox answered a command with a completion, not with
        `{:error, {:could_not_run, _}}`.

        Got #{inspect(completion)}.

        This is the defect no layer above can see. `:could_not_run` means the
        check was never performed, and `008-FR-026` says such an attempt does not
        count against the refinement bound. An exit status -- of any value,
        including zero -- says it *was* performed, so the run spends an iteration
        on a check that never happened, and a zero says it PASSED.
        """)

      {:error, {:limit_exceeded, capability}} ->
        guarantee_failure("008-FR-016", """
        A destroyed sandbox reported `{:limit_exceeded, #{inspect(capability)}}`.

        Nothing ran, so no limit was exceeded. Attributing the failure to a cap
        sends an operator to raise a limit that was never reached.
        """)

      other ->
        guarantee_failure("008-FR-016", """
        A destroyed sandbox answered #{inspect(other)}, which is neither of the
        two shapes `execute/3` may return here.
        """)
    end
  end

  @doc """
  Runs one hostile command through `execute/3` and classifies what happened.

  Returns `{:stopped, evidence}`, `{:breached, evidence}` or an inconclusive
  value that `ExSandbox.Conformance.Helpers.demonstrate_breach/3` routes to the
  third outcome.
  """
  def breach(mechanism, sandbox, command, dimension) do
    case ExSandbox.provision(mechanism, sandbox) do
      {:ok, provisioned} ->
        run_breach(mechanism, provisioned, command, dimension, sandbox)

      {:error, {:capability_unavailable, [missing | _]}} ->
        Helpers.capability_unavailable(missing.name, missing.detail)

      other ->
        {:could_not_provision, other}
    end
  end

  defp run_breach(mechanism, provisioned, command, dimension, requested) do
    {:ok, started} = ExSandbox.start(mechanism, provisioned)

    try do
      mechanism
      |> ExSandbox.execute(started, {"/bin/sh", ["-c", command]})
      |> classify(dimension, cap_for(requested, dimension), {mechanism, started})
    after
      ExSandbox.destroy(mechanism, started)
    end
  end

  @doc """
  Decides whether a breach through `execute/3` was stopped, succeeded, or showed
  nothing.

  Public because the group self-checks it in both directions: this is the single
  place a fail-open would live, so it is exercised directly rather than only
  through a live mechanism.
  """
  @spec classify(term(), :memory | :cpu | :time, term(), {module(), term()} | nil) ::
          {:stopped, String.t()} | {:breached, String.t()} | {:inconclusive, String.t()}
  def classify({:ok, completion}, dimension, cap, live) do
    output = completion.stdout <> completion.stderr

    cond do
      String.contains?(output, completion_marker(dimension)) ->
        # The hostile act ran to completion. Note that the mechanism may have
        # been invoked perfectly -- that is precisely `005` R9b.
        {:breached,
         "the #{dimension} breach ran to completion under a nominal cap of " <>
           "#{inspect(cap)} and exited #{completion.exit_status}; output contained " <>
           inspect(completion_marker(dimension))}

      String.contains?(output, throttle_marker()) ->
        # Positive evidence, not an absence. A CPU cap throttles rather than
        # kills, so there is no error to recognise -- the process simply does not
        # finish fixed work within a deadline it reports missing itself.
        {:stopped,
         "the #{dimension} breach did not finish its fixed workload within its " <>
           "deadline under a cap of #{inspect(cap)}: output contained " <>
           inspect(throttle_marker())}

      killed_by_signal?(completion.exit_status) and cap_declared?(live, dimension) ->
        {:stopped,
         "the #{dimension} breach was killed (exit #{completion.exit_status}) without " <>
           "reaching its completion marker, under a declared cap of #{inspect(cap)}"}

      true ->
        # It did not complete and did not visibly hit the cap. Not evidence: it
        # could have died of anything.
        {:inconclusive,
         "the #{dimension} breach neither completed nor reported being stopped " <>
           "(exit #{completion.exit_status}). Output: " <>
           inspect(String.slice(output, 0, 400))}
    end
  end

  def classify({:error, {:limit_exceeded, _capability}} = reason, dimension, cap, _live) do
    {:stopped,
     "the #{dimension} breach was stopped under a cap of #{inspect(cap)}: " <> inspect(reason)}
  end

  # ⚠️ `:could_not_run` is deliberately NOT a pass. It means the command never
  # ran, and a cap that stopped nothing because nothing started has demonstrated
  # nothing at all.
  def classify({:error, {:could_not_run, reason}}, dimension, _cap, _live) do
    {:inconclusive,
     "the #{dimension} breach could not be run at all, so the cap was not " <>
       "exercised: " <> inspect(reason)}
  end

  def classify(other, dimension, _cap, _live) do
    {:inconclusive, "the #{dimension} breach returned #{inspect(other)}"}
  end

  # 128 + signal. A SIGKILL inside a sandbox running nothing but this command is
  # the kernel's OOM killer or the mechanism's own stop; either way the hostile
  # act did not finish. Paired with `cap_declared?/2` so a crash in a sandbox
  # with no cap at all cannot read as a cap holding.
  defp killed_by_signal?(status) when is_integer(status), do: status > 128
  defp killed_by_signal?(_status), do: false

  defp cap_declared?(nil, _dimension), do: false

  defp cap_declared?({_mechanism, sandbox}, dimension),
    do: not is_nil(cap_for(sandbox, dimension))

  defp cap_for(sandbox, :memory), do: Map.get(sandbox, :memory_limit_mb)
  defp cap_for(sandbox, :cpu), do: Map.get(sandbox, :cpu_limit)
  defp cap_for(%{context: %{timeout_ms: ms}}, :time), do: ms
  defp cap_for(_sandbox, :time), do: nil

  defp completion_marker(:memory), do: "ALLOCATED-PAST-CAP"
  defp completion_marker(:cpu), do: "SPUN-PAST-CAP"
  defp completion_marker(:time), do: "SLEPT-PAST-BUDGET"

  defp throttle_marker, do: "THROTTLED-BY-CAP"

  # Provisions, starts, runs `body`, and always destroys. A host that cannot
  # confine reports the third outcome from `provision_or_report/2` rather than
  # failing a mechanism for correctly refusing to run unconfined.
  defp with_sandbox(mechanism, body) do
    provisioned = Helpers.provision_or_report(mechanism, Helpers.build_sandbox())

    started =
      case ExSandbox.start(mechanism, provisioned) do
        {:ok, started} -> started
        other -> undemonstrable("the sandbox could not be started: #{inspect(other)}")
      end

    try do
      body.(mechanism, started)
    after
      ExSandbox.destroy(mechanism, started)
    end
  end

  # The third outcome, reached only from a runtime fact about this host or this
  # mechanism's own refusal -- never from anything a consumer supplies.
  defp undemonstrable(detail), do: Helpers.capability_unavailable(:process_execution, detail)
end
