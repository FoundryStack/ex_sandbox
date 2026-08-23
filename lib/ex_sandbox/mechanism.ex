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
  type in every callback.

  ⚠️ **Do not trust a count of callbacks written in prose, here or anywhere
  else.** This moduledoc said "seven" while the file declared eight, and
  `012/contracts/execution-seam.md` re-titled its own heading for the same
  reason. Count them in the file.

  ## Why more callbacks than the obvious four

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

    * `execute` — **the seam that lets a caller run a command inside a sandbox
      that is already running**, added by `012/contracts/execution-seam.md`
      (decided 2026-08-20, Option A shape A2). Until it existed this behaviour
      could start a workload and stop it and never run anything beside it, so
      `008-FR-002` (verification runs inside a sandbox, never on the platform's
      runtime) and `007-FR-041` (a run does not get a private isolation
      mechanism separate from its environment's sandbox) were both unbuildable.
      The argument that every mechanism can keep this promise honestly is short:
      a mechanism that cannot run a command inside a sandbox cannot have started
      an application in one either.

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

  @typedoc """
  What one completed command produced.

  `stdout` and `stderr` are **separate** because a merged stream cannot
  attribute a failure, and `015` research R17 measured `MuonTrap`'s
  `:logger_fun` corrupting lines past a 256-byte buffer — so how the two are
  captured is a decision a mechanism must make deliberately, not a detail it may
  inherit.

  `truncated?` is explicit for the same reason: silent truncation of a build log
  is how a real error disappears from a diagnosis. It is `true` when either
  stream was cut, and the bytes returned are that stream's first bytes.
  """
  @type completion :: %{
          exit_status: integer(),
          stdout: binary(),
          stderr: binary(),
          truncated?: boolean()
        }

  @typedoc """
  A chunk of output as it is produced, for `opts[:on_output]`.

  ⚠️ **A chunk is a chunk, not a line.** Nothing here promises line framing, and
  a mechanism must not impose one: `015` R17's defect is precisely a line buffer
  that corrupts what does not fit it. A caller wanting lines assembles them from
  the byte stream, where a long line is late rather than mangled.
  """
  @type output_chunk :: {:stdout | :stderr, binary()}

  @doc """
  Runs `{cmd, args}` inside a **running** sandbox and returns what it produced.

  This is `012/contracts/execution-seam.md` Option A at shape A2: the call
  returns on completion, and `opts[:on_output]` may supply a one-argument
  function receiving `t:output_chunk/0` as output is produced. A caller passing
  no sink gets exactly the run-to-completion shape, so nothing is paid for what
  is not used, and `008-FR-061` / `007-FR-023` (in-progress visibility) do not
  need a second breaking change to this behaviour later.

  ## The three returns are three different facts, and collapsing any two breaks
  a requirement

    * `{:ok, completion}` — the command **ran**. `exit_status` is the command's
      own, whatever it is. A non-zero status is a *result*, not an error.
    * `{:error, {:could_not_run, reason}}` — the command **did not run**: the
      sandbox was gone, the binary was not there, the mechanism could not reach
      in. ⚠️ **This is not an exit status and must never be reported as one.**
      `008-FR-016` and `008-FR-026` both rest on it: an implementation that maps
      "the sandbox was gone" onto a non-zero exit has converted an *unperformed*
      check into a *failed* one, and a failed check consumes a refinement
      iteration that `FR-026` says it must not.
    * `{:error, {:limit_exceeded, capability}}` — the command was **stopped** by
      a limit the sandbox was launched under.

  ## Limits are the launch's, never this call's

  A mechanism must not read a limit here and enforce it around the command.
  `ExSandbox.Hardening`'s moduledoc records why: `005` R9b measured a cap
  silently lost across an intervening exec, allocating 300 MB under a nominal
  100 MB cap and **exiting 0**. A limit re-applied at execution time is a limit
  applied after the process it governs already exists, which is the shape that
  fails open. The sandbox is launched under `ExSandbox.Hardening.apply/2`, and
  what runs inside it inherits that confinement or the mechanism has none.

  ## Options

    * `:on_output` — `(t:output_chunk/0 -> any())`, optional.
    * `:timeout` — a wall-clock ceiling for this call, optional. A sandbox that
      declares its own budget is bounded by that budget regardless.

  A mechanism may accept further options; it must not *require* any.
  """
  @callback execute(Sandbox.t(), {cmd :: String.t(), args :: [String.t()]}, opts :: keyword()) ::
              {:ok, completion()}
              | {:error, {:could_not_run, term()}}
              | {:error, {:limit_exceeded, :wall_clock | :memory | :cpu}}

  @doc """
  Capabilities this mechanism requires of the host.

  Optional. A mechanism that omits it is treated as requiring every known
  capability — see the moduledoc.
  """
  @callback required_capabilities() :: [ExSandbox.Capability.name()]

  @optional_callbacks required_capabilities: 0
end
