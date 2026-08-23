defmodule ExSandbox do
  @moduledoc """
  Isolated execution sandboxes, as a library with no host-application concepts.

  `ex_sandbox` is a **composition and evidence layer over operating-system
  facilities**, not a new isolation mechanism. Nothing here invents containment:
  the primitives are the OS's (cgroup v2, namespaces, `bubblewrap`,
  `sandbox-exec`, Job Objects). What this library adds is a uniform behaviour
  over them, a capability report that is honest about what the host cannot do,
  and a conformance suite that establishes claims by *observing breaches being
  stopped* rather than by confirming a limiter was invoked.

  It depends on Elixir/OTP and nothing else — no Ash, no web framework, no host
  application (`FR-001`).

  ## Public interface

  These modules are public. A breaking change to any of them is a major version
  (`FR-015`):

    * `ExSandbox` — this module; the top-level API
    * `ExSandbox.Mechanism` — the behaviour every isolation mechanism implements
    * `ExSandbox.Sandbox` — the struct passed to every mechanism callback
    * `ExSandbox.Capability` — the host capability report (`FR-016`)
    * `ExSandbox.Hardening` — the OS-level enforcement seam
    * `ExSandbox.Conformance` — the conformance suite, included via `use`
    * `ExSandbox.Proxy` — forwards a request to a running sandbox's address
    * `ExSandbox.Telemetry` — the events both libraries emit, and their metadata
    * `ExSandbox.Conformance.{Lifecycle, Isolation, ResourceLimits, Execution,
      Helpers, Group}` — public *by consequence*: `use ExSandbox.Conformance` expands
      into calls on them inside the consumer's own module, so they are part of
      the compiled surface whether or not anyone intended it

  ## Everything else is private

  **A module not listed above is private, whether or not it is namespaced
  `Internal`** (`FR-014`). The `ExSandbox.Internal.*` namespace makes the common
  case obvious from the module name, but the list above is what defines the
  boundary — a module that merely lacks the `Internal` prefix has not thereby
  become public.

  There is no compatibility promise for private modules. Calling one from a
  consuming application is the coupling `FR-004` forbids, and
  `Axonn.LibraryBoundaryTest` checks for it mechanically.

  ## What a consumer must supply

  | Consumer supplies | Why this library cannot |
  |---|---|
  | `owner_ref` | It has no owner concept (`FR-007`) |
  | Run policy | It has no lifecycle concept (`FR-008`) |
  | `context` value, or `nil` | It has no request-scoping type (`FR-003`) |
  | Mechanism selection and configuration | The host decides what it can run |

  A consumer supplying nothing beyond a mechanism gets a working sandbox.

  ## Capability honesty

  Every entry point below refuses to start a sandbox when a required capability
  is unavailable, rather than starting it unconfined (`FR-016`; `005` R9). A
  mechanism that cannot isolate must say so — reporting less than it does rather
  than more is the discipline that makes a cross-platform floor mean anything.
  """

  alias ExSandbox.Capability
  alias ExSandbox.Telemetry
  alias ExSandbox.Sandbox

  @typedoc "A module implementing `ExSandbox.Mechanism`."
  @type mechanism :: module()

  @typedoc """
  Why an operation was refused before the mechanism was ever asked.

  `{:capability_unavailable, reports}` is not an error in the mechanism — it is
  this library declining to pretend.
  """
  @type refusal :: {:capability_unavailable, [Capability.t()]}

  @doc """
  Creates the sandbox's resources without starting it.

  Refuses when the host lacks a capability the mechanism requires, rather than
  provisioning something that would run unconfined.
  """
  @spec provision(mechanism(), Sandbox.t()) ::
          {:ok, Sandbox.t()} | {:error, refusal() | term()}
  def provision(mechanism, %Sandbox{} = sandbox) do
    with :ok <- ensure_capable(mechanism, sandbox) do
      Telemetry.span(:provision, mechanism, sandbox, fn -> mechanism.provision(sandbox) end)
    end
  end

  @doc """
  Starts a provisioned sandbox.

  The capability check is repeated here rather than trusted from `provision/2`:
  a sandbox may be provisioned on one host and started on another, and a cap
  that was enforceable at provision time is not thereby enforceable now.
  """
  @spec start(mechanism(), Sandbox.t()) :: {:ok, Sandbox.t()} | {:error, refusal() | term()}
  def start(mechanism, %Sandbox{} = sandbox) do
    with :ok <- ensure_capable(mechanism, sandbox) do
      Telemetry.span(:start, mechanism, sandbox, fn -> mechanism.start(sandbox) end)
    end
  end

  @doc "Stops a running sandbox, leaving its resources in place."
  @spec stop(mechanism(), Sandbox.t()) :: {:ok, Sandbox.t()} | {:error, term()}
  def stop(mechanism, %Sandbox{} = sandbox) do
    Telemetry.span(:stop, mechanism, sandbox, fn -> mechanism.stop(sandbox) end)
  end

  @doc """
  Destroys a sandbox and releases its resources.

  Deliberately **not** capability-gated. Refusing to clean up because the host
  cannot isolate would strand resources on exactly the hosts least able to
  afford them.
  """
  @spec destroy(mechanism(), Sandbox.t()) :: :ok | {:error, term()}
  def destroy(mechanism, %Sandbox{} = sandbox) do
    Telemetry.span(:destroy, mechanism, sandbox, fn -> mechanism.destroy(sandbox) end)
  end

  @doc "The sandbox's current state, as the mechanism observes it."
  @spec status(mechanism(), Sandbox.t()) ::
          {:ok, ExSandbox.Mechanism.status()} | {:error, term()}
  def status(mechanism, %Sandbox{} = sandbox), do: mechanism.status(sandbox)

  @doc """
  Every sandbox the mechanism currently believes is running.

  Nothing in the happy path calls this; it exists so a host can reconcile
  recorded state against actual state after a restart (`003-FR-015`).
  """
  @spec list_running(mechanism()) :: {:ok, [String.t()]} | {:error, term()}
  def list_running(mechanism), do: mechanism.list_running()

  @doc "Current resource consumption for one sandbox (`003-FR-026`)."
  @spec usage(mechanism(), Sandbox.t()) ::
          {:ok, ExSandbox.Mechanism.usage()} | {:error, term()}
  def usage(mechanism, %Sandbox{} = sandbox), do: mechanism.usage(sandbox)

  @doc """
  Runs `{cmd, args}` inside a running sandbox (`008-FR-002`, `007-FR-041`).

  Deliberately **not** capability-gated the way `provision/2` and `start/2` are,
  and the reason is not laxity: this call reaches into a sandbox that is already
  running, which means the capability decision was taken at its launch and taken
  correctly, or there is no sandbox here to reach into. Re-asking now would only
  add a second answer to a question already settled, and on a host whose report
  changed mid-flight the second answer would refuse to read the output of work
  that ran perfectly well under confinement that was real when it started.

  The three returns are three different facts — see `c:ExSandbox.Mechanism.execute/3`.
  In particular `{:error, {:could_not_run, _}}` is **not** an exit status.
  """
  @spec execute(mechanism(), Sandbox.t(), {String.t(), [String.t()]}, keyword()) ::
          {:ok, ExSandbox.Mechanism.completion()}
          | {:error, {:could_not_run, term()}}
          | {:error, {:limit_exceeded, :wall_clock | :memory | :cpu}}
  def execute(mechanism, %Sandbox{} = sandbox, {cmd, args}, opts \\ [])
      when is_binary(cmd) and is_list(args) do
    Telemetry.span(:execute, mechanism, sandbox, fn ->
      mechanism.execute(sandbox, {cmd, args}, opts)
    end)
  end

  @doc """
  Reports on every capability this host provides.

  Public so a consumer can decide *before* provisioning whether this host can
  run what they need, rather than discovering it from a refusal.
  """
  @spec capabilities() :: [Capability.t()]
  def capabilities, do: Capability.check_all()

  defp ensure_capable(mechanism, sandbox) do
    case Capability.missing(required_capabilities(mechanism)) do
      [] ->
        :ok

      missing ->
        # Emitted here rather than left to the caller. A mechanism refusing to
        # start is correct behaviour but invisible behaviour, and an operator
        # seeing no sandboxes start needs to know it was a capability decision
        # rather than a crash.
        Telemetry.capability_unavailable(mechanism, sandbox, missing)
        {:error, {:capability_unavailable, missing}}
    end
  end

  # A mechanism that does not say what it needs is assumed to need everything.
  # Erring toward refusal here is FR-012b's rule applied to the entry points: a
  # mechanism that under-declares must not thereby escape the check.
  #
  # `ensure_loaded?` first: `function_exported?/3` answers for *loaded* modules
  # only, so under lazy loading it reports false for a callback the mechanism
  # does export -- which would silently promote every mechanism to requiring
  # every capability.
  defp required_capabilities(mechanism) do
    if Code.ensure_loaded?(mechanism) and
         function_exported?(mechanism, :required_capabilities, 0) do
      mechanism.required_capabilities()
    else
      Capability.known()
    end
  end
end
