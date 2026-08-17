defmodule ExSandbox.Conformance do
  @moduledoc """
  The conformance suite every mechanism is held to (012 T030–T035, FR-010).

      defmodule MyMechanismConformanceTest do
        use ExSandbox.Conformance, mechanism: MyMechanism
      end

  It runs under **the consumer's own ExUnit**, in their own project. That shape
  is what makes `SC-004` possible: a suite runnable only inside this repository
  could never be run against a third-party mechanism at all.

  ## This suite is authoritative for the capability

  If a mechanism needs the suite edited to pass, that is evidence the *contract*
  leaked a mechanism assumption. **Fix the contract, not the test.** A suite that
  bends to accommodate each mechanism measures nothing, and the guarantee it
  claims to enforce quietly becomes whatever the last mechanism could manage.

  ## There are no exclusions (`FR-011`)

  No skip flag, no exclusion tag, no mechanism allowlist. `ExSandbox.ConformanceExclusionsTest`
  greps this file's source to keep it that way. The check is blunt on purpose —
  the requirement is absolute, so a nuanced check would only be a way to argue
  about it.

  ## The one legitimate non-run, and the trap beside it

  A check needing a host capability that is absent reports **host capability
  unavailable** — a third outcome, distinct from pass and fail. That is not an
  exclusion: the consumer cannot request it, `ExSandbox.Capability` determines it
  at runtime, and it is reported rather than hidden.

  Research R7a found a fourth state that is worse than any of these, because it
  is **indistinguishable from success**:

  | Suite observes | Verdict |
  |---|---|
  | Breach attempted, stopped | ✅ guarantee holds |
  | Breach attempted, **not** stopped | ❌ mechanism failed |
  | Breach cannot be attempted on this host | ⚠️ capability unavailable |
  | Mechanism present, breach **never attempted** | ❌ **not evidence** — unavailable |

  The fourth row is `FR-012b`. `005` R9b measured it: `taskpolicy -m 100
  sandbox-exec … ./hog 300` allocates 300 MB under a nominal 100 MB cap and
  **exits 0**, because the limit is silently lost across the intervening exec.
  No error, no warning, nothing observably different from a correct invocation
  except that the cap does not exist.

  A suite asserting *the limiter was invoked with the right arguments* passes
  that. So would one asserting the wrapper appears in the process tree, or that
  configuration names the cap. **Every formulation short of "trigger a breach
  and observe it stopped" accepts the defect as conformant** (`FR-012a`).

  That is why every resource-limit check below breaches the cap.
  """

  @doc false
  defmacro __using__(opts) do
    quote bind_quoted: [opts: opts] do
      # `async: false` is not a default worth revisiting: the checks provision
      # real sandboxes and breach real resource caps, and two of those running
      # concurrently would contend for exactly the resources under test.
      use ExUnit.Case, async: false

      @mechanism Keyword.fetch!(opts, :mechanism)
      @target_stack Keyword.get(opts, :target_stack)

      # Optional, and its absence is an *outcome* rather than a skip. A host
      # with no data store legitimately has no probe; a host that has one and
      # supplies no probe gets `host capability unavailable` on every check in
      # the credentials group, which is loud. Neither is an exclusion under
      # `FR-011` -- the consumer cannot use it to silence a check that would
      # otherwise fail, because the group reports rather than passes.
      @credential_probe Keyword.get(opts, :credential_probe)

      import ExSandbox.Conformance.Helpers

      require ExSandbox.Conformance.Credentials
      require ExSandbox.Conformance.Isolation
      require ExSandbox.Conformance.Lifecycle
      require ExSandbox.Conformance.Network
      require ExSandbox.Conformance.Reachability
      require ExSandbox.Conformance.Reconciliation
      require ExSandbox.Conformance.ResourceLimits

      ExSandbox.Conformance.Lifecycle.tests()
      ExSandbox.Conformance.Reachability.tests()
      ExSandbox.Conformance.Reconciliation.tests()
      ExSandbox.Conformance.Credentials.tests()
      ExSandbox.Conformance.Isolation.tests()
      ExSandbox.Conformance.Network.tests()
      ExSandbox.Conformance.ResourceLimits.tests()
    end
  end
end
