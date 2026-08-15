defmodule ExSandbox.Conformance.Group do
  @moduledoc """
  Emits one conformance check as an ExUnit test (012 T034).

  Every check in every group goes through `check/2`, which is the single place
  the third outcome is turned into something a test run can show. A group that
  emitted `test/2` directly would have to decide, per check, what to do with a
  `CapabilityUnavailable` — and the tempting answer is "rescue it and return
  `:ok`", which reports as **green**. That is `FR-012b`'s exact failure mode
  wearing the costume of a careful handler.

  ## Why the third outcome is not an ExUnit skip

  ExUnit's skip tag is resolved before the test runs, and `ExSandbox.Capability`
  answers only at runtime — the whole point of `FR-016`. There is no runtime
  skip in ExUnit, so the choice is between reporting unavailable as a pass or as
  a failure. It is reported as a **failure**, with a message that says plainly
  it is the third outcome and what would make it a pass.

  Erring this way is deliberate. A suite that goes green on a host where nothing
  was demonstrated is the artefact `SC-008` exists to prevent; a suite that goes
  red until you read why costs an engineer five minutes.
  """

  @doc """
  Defines a conformance check named `name`.

  A `ExSandbox.Conformance.CapabilityUnavailable` raised inside `body` is
  re-raised as a failure tagged as the third outcome — never swallowed.
  """
  defmacro check(name, do: body) do
    quote do
      test unquote(name), var!(context) do
        # `context` is bound with `var!` so a check can reach values a group's
        # `setup` returned (the isolation group's provisioned sandbox, above
        # all) without every call site threading it explicitly.
        _ = var!(context)

        try do
          unquote(body)
        rescue
          unavailable in ExSandbox.Conformance.CapabilityUnavailable ->
            reraise ExUnit.AssertionError,
                    [
                      message:
                        "NOT DEMONSTRATED (host capability unavailable) -- this is the " <>
                          "suite's third outcome, neither a pass nor a mechanism defect.\n\n" <>
                          Exception.message(unavailable) <>
                          "\nTo turn this into a pass, run the suite on a host providing " <>
                          "the capability. It is reported as a failure because ExUnit has " <>
                          "no runtime skip, and reporting it as a pass would claim a " <>
                          "guarantee that was never demonstrated (FR-012b)."
                    ],
                    __STACKTRACE__
        end
      end
    end
  end
end
