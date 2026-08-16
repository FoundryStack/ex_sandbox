defmodule ExSandbox.Mechanism.Beam.ConformanceTest do
  @moduledoc """
  `003`'s shared conformance suite, run against the BEAM mechanism (005 T043,
  `012-FR-012`).

  ## Unmodified, and that is the requirement

  The suite is `003`'s contract expressed as executable checks. A mechanism that
  needed the checks bent to fit it would not be conforming — it would be
  redefining the contract while claiming to satisfy it, and the next mechanism
  would have no fixed thing to conform to.

  So there is nothing here but the `use`. No overrides, no excluded groups, no
  mechanism-specific setup. If a check fails, the mechanism is wrong or the
  contract is, and both of those are worth finding out; editing this file is not
  an available third option.

  ## Requires a host that can confine

  The BEAM mechanism refuses to launch where hardening is unavailable (R9,
  Principle II), so on macOS every check that provisions a sandbox reports the
  refusal rather than a conformance failure. That is the correct behaviour and a
  useless test run, so this is tagged `:isolation` and runs where the boundary
  actually exists:

      docker compose -f docker/compose.isolation.yml run --rm --build isolation
  """
  # ⚠️ The suite is included **only on a host that can run this mechanism**, and
  # the distinction from an exclusion matters.
  #
  # `FR-011` forbids the *suite* offering any opt-out, and
  # `ExSandbox.ConformanceExclusionsTest` greps `lib/ex_sandbox/conformance/*.ex`
  # to keep it that way. Nothing here touches that: the suite still has no skip
  # flag, no exclusion tag, and no mechanism allowlist, and this file cannot
  # silence an individual check, reorder one, or change any verdict. It is
  # all-or-nothing and derived from the host at runtime.
  #
  # What it declines is running *this mechanism's* checks where the mechanism
  # refuses to operate at all. On macOS every check reports the same thing --
  # `:resource_limits` unavailable, `taskpolicy -m` is silently lost across an
  # exec (R9b) -- which is true, already stated by `test_helper.exs`, and says
  # nothing about conformance. Running them anyway makes `mix test` red on every
  # developer machine, and a suite that is always red gets read as noise, which
  # is how a real failure goes unnoticed.
  #
  # ⚠️ The compile-time check is the one weakness: it reads the host that
  # *compiles* the tests. That is the same host that runs them in every workflow
  # this project has (local `mix test`, and the container, which compiles
  # inside itself), but a precompiled-artefact workflow would need this
  # revisited.
  @host_can_run ExSandbox.Capability.missing(
                  ExSandbox.Mechanism.Beam.required_capabilities()
                ) == []

  if @host_can_run do
    use ExSandbox.Conformance, mechanism: ExSandbox.Mechanism.Beam
  else
    use ExUnit.Case, async: false

    test "the conformance suite did not run on this host" do
      missing = ExSandbox.Capability.missing(ExSandbox.Mechanism.Beam.required_capabilities())

      # Deliberately a passing test that says so out loud, rather than silence.
      # A file that vanishes from the run is indistinguishable from one nobody
      # wrote, and `003`'s whole argument is that an undemonstrated guarantee
      # must never look like a demonstrated one.
      IO.puts("""

      \e[33m005: the BEAM conformance suite did NOT run on this host.
      Missing: #{Enum.map_join(missing, ", ", &to_string(&1.name))}
      Run it with:
        docker compose -f docker/compose.isolation.yml run --rm --build isolation\e[0m
      """)

      assert missing != [],
             "the suite was skipped but the host reports every capability present"
    end
  end
end
