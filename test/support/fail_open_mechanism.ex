defmodule ExSandbox.FailOpenMechanism do
  @moduledoc """
  A mechanism that configures a resource cap without the cap taking effect
  (012 T029a, research R7a).

  This is the `005` R9b composition in fixture form. It is **not** a strawman:

    * it accepts the sandbox's `memory_limit_mb`
    * it records that it applied that cap, with the right number
    * it launches the workload with the limiter in the command line
    * the workload allocates three times the cap and exits 0

  Every observable signal short of the allocation itself says the cap is in
  place. `taskpolicy -m 100 sandbox-exec … ./hog 300` behaves exactly this way
  on macOS, because the cap is silently lost across the intervening `exec`.

  `ExSandbox.ConformanceFailOpenTest` requires that the conformance suite
  **fails** this mechanism. A suite that checked `applied_caps/0` — the
  invocation record this fixture faithfully maintains — would pass it, which is
  precisely the defect the meta-test exists to catch.
  """
  @behaviour ExSandbox.Mechanism

  @impl true
  def required_capabilities, do: []

  @impl true
  def provision(sandbox) do
    # The cap is "applied" here, correctly, with the right value. Everything
    # about this call is right except its effect.
    record_applied_cap(sandbox.id, sandbox.memory_limit_mb)

    {:ok, %{sandbox | mechanism_ref: "fail-open-" <> sandbox.id, context: runner(sandbox)}}
  end

  @impl true
  def start(sandbox), do: {:ok, sandbox}

  @impl true
  def stop(sandbox), do: {:ok, sandbox}

  @impl true
  def destroy(_sandbox), do: :ok

  @impl true
  def status(_sandbox), do: {:ok, :running}

  @impl true
  def list_running, do: {:ok, []}

  @impl true
  def usage(_sandbox), do: {:ok, %{memory_mb: 0}}

  # The R9b composition at the execution seam: the hostile command runs to
  # completion and exits 0 under a cap this mechanism faithfully recorded
  # applying. `ExSandbox.Conformance.Execution` must fail this, and
  # `ExSandbox.ConformanceFailOpenTest` is what requires that it does.
  @impl true
  def execute(_sandbox, {_cmd, args}, _opts \\ []) do
    command = Enum.join(args, " ")

    marker =
      cond do
        String.contains?(command, "ALLOCATED-PAST-CAP") -> "ALLOCATED-PAST-CAP\n"
        String.contains?(command, "SPUN-PAST-CAP") -> "SPUN-PAST-CAP\n"
        String.contains?(command, "SLEPT-PAST-BUDGET") -> "SLEPT-PAST-BUDGET\n"
        true -> ""
      end

    {:ok, %{exit_status: 0, stdout: marker, stderr: "", truncated?: false}}
  end

  @doc """
  The caps this mechanism believes it applied.

  Exposed so the meta-test can assert the *record is honest* — the fixture
  really did configure the cap — which is what makes its failure a statement
  about enforcement rather than about configuration.
  """
  def applied_caps, do: Process.get(:fail_open_applied_caps, [])

  defp record_applied_cap(id, mb) do
    Process.put(:fail_open_applied_caps, [{id, mb} | applied_caps()])
  end

  # A runner that always lets the hostile command run to completion. The cap
  # named in `provision/1` has no bearing on anything here -- which is the
  # whole point.
  defp runner(_sandbox) do
    %{
      exec: fn command ->
        cond do
          String.contains?(command, "ALLOCATED-PAST-CAP") -> {:ok, "ALLOCATED-PAST-CAP\n"}
          String.contains?(command, "SPUN-PAST-CAP") -> {:ok, "SPUN-PAST-CAP\n"}
          String.contains?(command, "SLEPT-PAST-BUDGET") -> {:ok, "SLEPT-PAST-BUDGET\n"}
          true -> {:ok, ""}
        end
      end
    }
  end
end
