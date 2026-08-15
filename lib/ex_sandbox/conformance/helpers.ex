defmodule ExSandbox.Conformance.Helpers do
  @moduledoc """
  The shared vocabulary of the conformance suite (012 T033, T034, T034b).

  Three things live here rather than in the individual groups, because all three
  are places where a plausible-looking implementation quietly stops measuring
  anything:

    * `guarantee_failure/2` — every failure names the `003` requirement it
      violated, not merely the assertion that tripped (T033).
    * `capability_unavailable/2` — the third outcome, distinct from pass and
      fail (T034).
    * `demonstrate_breach/3` — the rule that a cap which cannot be *shown*
      stopping something is unavailable, never satisfied (T034b).
  """

  @doc """
  Raises a failure naming the violated `003` requirement.

  `SC-004` asks that a third-party mechanism author can act on a failure. An
  `ExUnit` assertion message tells them a comparison failed; it does not tell
  them *which guarantee of the sandbox contract they have not met*, and those
  are the terms in which the fix is expressed.
  """
  @spec guarantee_failure(String.t(), String.t()) :: no_return()
  def guarantee_failure(requirement, detail) do
    raise ExUnit.AssertionError,
      message: """
      Sandbox contract violation: #{requirement}

      #{detail}

      This is a violation of the guarantee named above, not a suite defect. See
      `ExSandbox.Conformance` — the suite is authoritative for the capability.
      """
  end

  @doc """
  Asserts `condition`, naming `requirement` if it does not hold.
  """
  @spec assert_guarantee(term(), String.t(), String.t()) :: :ok
  def assert_guarantee(condition, requirement, detail) do
    if condition, do: :ok, else: guarantee_failure(requirement, detail)
  end

  @doc """
  The third outcome: this host cannot provide what the check needs (T034).

  Not a pass and not a failure. Reported through `ExUnit`'s skip mechanism so it
  shows up in the run rather than vanishing, and phrased so it cannot be mistaken
  for a green result.

  **Not requestable by the consumer.** Every call site derives its argument from
  `ExSandbox.Capability` at runtime. If a configuration option could reach here,
  it would be an exclusion wearing another name and `FR-011` would be violated.
  """
  @spec capability_unavailable(ExSandbox.Capability.name(), String.t() | nil) :: no_return()
  def capability_unavailable(capability, detail) do
    raise ExSandbox.Conformance.CapabilityUnavailable,
      capability: capability,
      detail: detail
  end

  @doc """
  Reports whether `capability` is available, as `ExSandbox.Capability` sees it.
  """
  @spec host_capability(ExSandbox.Capability.name()) :: ExSandbox.Capability.t()
  def host_capability(capability), do: ExSandbox.Capability.check(capability)

  @doc """
  Runs `attempt` — which must *breach* a cap — and requires the breach be stopped.

  This is `FR-012a` and `FR-012b` in one function, and the shape matters more
  than it looks:

    * `attempt` returns `{:breached, evidence}` if the hostile act **succeeded**,
      or `{:stopped, evidence}` if the mechanism prevented it.
    * `{:breached, _}` fails, naming `requirement`.
    * `{:stopped, _}` passes.
    * Anything else — including the attempt erroring for an unrelated reason —
      routes to **capability unavailable**, never to a pass (`FR-012b`).

  That last clause is the whole point. `005` R9b's composition configures a
  100 MB cap and lets a process allocate 300 MB while exiting 0. A check that
  treated "we could not tell" as satisfied would report it conformant.
  """
  @spec demonstrate_breach(
          ExSandbox.Capability.name(),
          String.t(),
          (-> {:breached, term()} | {:stopped, term()} | term())
        ) :: :ok
  def demonstrate_breach(capability, requirement, attempt) when is_function(attempt, 0) do
    # The breach is attempted FIRST, before the host capability is consulted.
    #
    # The reverse order is the tempting one and it is wrong: it means that on a
    # host reporting the capability unavailable -- macOS, for every resource cap
    # (005 R9b) -- no breach is ever attempted, and a mechanism that lets a
    # 192 MB allocation run under a 64 MB cap is reported as "not demonstrated"
    # rather than as broken. The host being unable to *enforce* a cap does not
    # make a mechanism that ignores one conformant, and a suite that cannot fail
    # such a mechanism on the developer machine it is written on will not catch
    # it anywhere.
    #
    # So an unavailable capability only explains an *inconclusive* attempt. A
    # completed breach is a failure on any host.
    case safely(attempt) do
      {:stopped, _evidence} ->
        :ok

      {:breached, evidence} ->
        guarantee_failure(requirement, """
        The breach was attempted and was NOT stopped.

        Evidence: #{inspect(evidence)}

        A cap that a process can exceed is not a cap. Note that the mechanism
        may well have been *invoked* correctly -- 005 R9b measured exactly that
        composition, where `taskpolicy -m 100` is applied and then silently lost
        across an intervening exec. Invocation is not enforcement.
        """)

      other ->
        # Deliberately NOT a pass. An attempt that neither breached nor was
        # visibly stopped has demonstrated nothing, and FR-012b says an
        # undemonstrable cap is unavailable rather than satisfied.
        #
        # This is also where an absent host capability lands, and the detail it
        # carries is the more useful explanation of the same fact.
        report = host_capability(capability)

        detail =
          if report.available? do
            "the breach could not be demonstrated either way: #{inspect(other)}"
          else
            "the breach could not be demonstrated either way (#{inspect(other)}), " <>
              "which this host explains: #{report.detail}"
          end

        capability_unavailable(capability, detail)
    end
  end

  @doc """
  Runs `attempt` — a **hostile act** — and requires that it failed.

  The isolation group's counterpart to `demonstrate_breach/3`. Same rule: the
  act must actually be performed, and `{:refused, _}` is the only pass.

  A test asserting merely that no leak was *observed* passes against a mechanism
  with no isolation whatsoever, because nothing went looking.
  """
  @spec require_refused(String.t(), (-> {:refused, term()} | {:succeeded, term()} | term())) ::
          :ok
  def require_refused(requirement, attempt) when is_function(attempt, 0) do
    case safely(attempt) do
      {:refused, _evidence} ->
        :ok

      {:succeeded, evidence} ->
        guarantee_failure(requirement, """
        The hostile act SUCCEEDED. It should have been refused.

        Evidence: #{inspect(evidence)}
        """)

      other ->
        guarantee_failure(requirement, """
        The hostile act neither succeeded nor was refused, so isolation was not
        demonstrated: #{inspect(other)}

        An inconclusive isolation check is a failure, not a skip -- unlike a
        resource cap, isolation has no host capability that could legitimately
        be absent here. If this mechanism genuinely cannot attempt the act, it
        cannot show it isolates.
        """)
    end
  end

  @doc false
  # Lets a CapabilityUnavailable signal through: it is an outcome, not an error.
  def safely(fun) do
    fun.()
  rescue
    e in ExSandbox.Conformance.CapabilityUnavailable -> reraise e, __STACKTRACE__
    e in ExUnit.AssertionError -> reraise e, __STACKTRACE__
    e -> {:raised, e}
  catch
    kind, value -> {:caught, kind, value}
  end

  @doc """
  A sandbox struct for the suite's own use.

  Values are unremarkable on purpose; `ExSandbox.OpacityTest` is where hostile
  `owner_ref` shapes are exercised.
  """
  @spec build_sandbox(keyword()) :: ExSandbox.Sandbox.t()
  def build_sandbox(overrides \\ []) do
    defaults = [
      id: "conformance-" <> Integer.to_string(System.unique_integer([:positive])),
      owner_ref: "conformance-owner",
      template_ref: "conformance-template",
      cpu_limit: 500,
      memory_limit_mb: 128,
      disk_quota_mb: 256
    ]

    struct!(ExSandbox.Sandbox, Keyword.merge(defaults, overrides))
  end
end
