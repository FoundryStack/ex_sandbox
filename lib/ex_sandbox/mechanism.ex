defmodule ExSandbox.Mechanism do
  @moduledoc """
  The behaviour every isolation mechanism implements (012 T019, T020).

  A mechanism is the thing that actually runs code in isolation — a BEAM node
  under OS confinement (`005-sandbox-beam`), a container (`001-lxd`), or
  something a third party writes. `ExSandbox` dispatches to one; the conformance
  suite holds all of them to the same bar.

  Every callback takes an `ExSandbox.Sandbox.t()` — a plain struct — rather than
  `003`'s `SandboxRecord.t()`, which was an Ash resource struct (research R3).
  This is the change that would have been most expensive to defer: it alters the
  type in all seven callbacks.

  ## Why seven callbacks and not the obvious four

  The natural first cut of this API is `compile` / `start` / `stop` / `proxy`.
  Three of the seven here exist for a specific reason rather than for symmetry,
  and each would be easy to leave out:

    * `status` — `003-FR-024` requires distinguishing "starting" from "not
      running". `:absent` and `:unknown` must not collapse into each other:
      "we know it is gone" and "we cannot tell" lead to different actions.

    * `list_running` — **the one most easily dropped, because nothing in the
      happy path calls it.** It is what makes post-restart reconciliation
      possible at all (`003-FR-015`). Without it a sandbox that crashed while
      the host was down stays recorded as running indefinitely, and `003-SC-008`
      — recorded status matches reality within 60 seconds — is unsatisfiable by
      construction.

    * `usage` — per-sandbox CPU, memory, and disk, attributable to the owner
      (`003-FR-026`, `010` Story 3).

  ## There is no `compile` callback

  Building a tenant's application is **per-stack work**, owned by
  `009-stack-adapters` and run *inside* an already-provisioned sandbox
  (`007-FR-041`, `013-FR-021`). Putting it on the mechanism would require every
  mechanism to know how to build every stack — precisely the coupling
  Principle VI exists to prevent. A mechanism provisions a place to run things;
  what gets built there is not its business.

  ## Optional: declaring required capabilities

  A mechanism may export `required_capabilities/0` returning a list of
  `ExSandbox.Capability.name()`. `ExSandbox` refuses to provision or start when
  any of them is unavailable on this host. A mechanism that does **not** export
  it is treated as requiring all of them — under-declaring must not be a way to
  escape the check (`FR-012b`).
  """

  alias ExSandbox.Sandbox

  @typedoc """
  What a mechanism observes about a sandbox.

  `:absent` ("it is definitely not there") and `:unknown` ("we could not
  determine") are deliberately distinct — collapsing them loses the difference
  between a sandbox that is gone and a mechanism that cannot see (`003-FR-024`).
  """
  @type status :: :absent | :provisioned | :starting | :running | :stopping | :stopped | :unknown

  @typedoc "Current consumption, for attribution to the owner (`003-FR-026`)."
  @type usage :: %{
          optional(:cpu_millicores) => non_neg_integer(),
          optional(:memory_mb) => non_neg_integer(),
          optional(:disk_mb) => non_neg_integer()
        }

  @doc """
  Creates the sandbox's resources without starting it.

  Returns the sandbox with `mechanism_ref` set — the opaque handle by which this
  mechanism will recognise it later.
  """
  @callback provision(Sandbox.t()) :: {:ok, Sandbox.t()} | {:error, term()}

  @doc "Starts a provisioned sandbox."
  @callback start(Sandbox.t()) :: {:ok, Sandbox.t()} | {:error, term()}

  @doc "Stops a running sandbox, leaving its resources intact."
  @callback stop(Sandbox.t()) :: {:ok, Sandbox.t()} | {:error, term()}

  @doc """
  Destroys the sandbox and releases its resources.

  Must be idempotent: a second destroy returns `:ok` rather than an error
  (`003-FR-013`). A cleanup path that errors on "already gone" turns every
  crash-recovery sweep into a source of spurious failures.
  """
  @callback destroy(Sandbox.t()) :: :ok | {:error, term()}

  @doc "The sandbox's current state as this mechanism observes it (`003-FR-024`)."
  @callback status(Sandbox.t()) :: {:ok, status()} | {:error, term()}

  @doc """
  Every `mechanism_ref` this mechanism currently believes is running.

  Exists for reconciliation after a restart (`003-FR-015`). Nothing in the happy
  path calls it, which is exactly why it is specified rather than left to each
  mechanism to provide or not.
  """
  @callback list_running() :: {:ok, [String.t()]} | {:error, term()}

  @doc "Current resource consumption for one sandbox (`003-FR-026`)."
  @callback usage(Sandbox.t()) :: {:ok, usage()} | {:error, term()}

  @doc """
  Capabilities this mechanism requires of the host.

  Optional. A mechanism that omits it is treated as requiring every known
  capability — see the moduledoc.
  """
  @callback required_capabilities() :: [ExSandbox.Capability.name()]

  @optional_callbacks required_capabilities: 0
end
