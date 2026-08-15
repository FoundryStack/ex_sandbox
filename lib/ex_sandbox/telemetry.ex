defmodule ExSandbox.Telemetry do
  @moduledoc """
  Events both libraries emit, carrying the opaque `owner_ref` (012 T043).

  ## Attribution is the host's, not the library's

  Every event carries `owner_ref` verbatim and nothing else identifying. The
  library has no tenant concept, no project concept, and no way to decompose the
  value — `FR-007` makes it opaque precisely so it cannot try. A host attaching a
  `:telemetry` handler knows what its own `owner_ref` means and resolves it to
  whatever attribution its observability stack wants.

  This is the stated resolution of the plan's Constitution VII risk: the library
  emits, the host attributes.

  ## ⚠️ Recorded mismatch with `010-observability` (T043)

  T043 asks that this be checked against `010`'s actual requirements and that any
  mismatch be **recorded rather than adapted to silently**. There is one, and it
  is not resolvable inside this library:

  **`010-FR-002`** requires telemetry be attributed to *"a tenant, project, and
  thread where each applies"*. These events carry a single opaque `owner_ref`.
  Three consequences follow:

    1. A host whose `owner_ref` encodes only a tenant cannot satisfy `010-FR-002`
       from these events alone — the project and thread are simply not present.
    2. The library **cannot** fix this by splitting `owner_ref` into parts. That
       would require parsing it, which `FR-007` forbids and which `012`'s opacity
       tests actively check for.
    3. Therefore the resolution must be at the host: either the host's
       `owner_ref` resolves to full attribution through a lookup it owns, or the
       host enriches these events in its own handler.

  **`010-FR-006`** forbids secrets and raw tenant data in telemetry, *including
  within error text*. These events pass mechanism error reasons through
  unredacted, because the library cannot know what a mechanism's error term
  contains. A host forwarding these to a telemetry backend is responsible for
  redaction. Recorded here rather than solved because solving it in the library
  would mean inspecting the opaque values `FR-007` forbids inspecting.

  Neither mismatch is a defect in this module; both are boundary consequences
  that `010`'s implementation will need to handle explicitly. They are written
  down so that work starts from a known position rather than discovering it.

  ## Events

  | Event | Measurements | Metadata |
  |---|---|---|
  | `[:ex_sandbox, :provision, :stop]` | `:duration` | `:owner_ref`, `:mechanism`, `:result` |
  | `[:ex_sandbox, :start, :stop]` | `:duration` | `:owner_ref`, `:mechanism`, `:result` |
  | `[:ex_sandbox, :stop, :stop]` | `:duration` | `:owner_ref`, `:mechanism`, `:result` |
  | `[:ex_sandbox, :destroy, :stop]` | `:duration` | `:owner_ref`, `:mechanism`, `:result` |
  | `[:ex_sandbox, :capability, :unavailable]` | `:count` | `:owner_ref`, `:mechanism`, `:missing` |

  `:result` is `:ok` or `{:error, reason}`, kept distinguishable per `010-FR-004`
  — an emitting capability may not collapse distinct causes into one generic
  error.
  """

  @doc """
  Runs `fun`, emitting a span for `operation` with `sandbox`'s owner attached.

  Uses `:telemetry.span/3` so the start, stop, and exception events follow the
  conventions a host's handlers already expect.
  """
  @spec span(atom(), module(), ExSandbox.Sandbox.t(), (-> result)) :: result when result: term()
  def span(operation, mechanism, sandbox, fun) when is_function(fun, 0) do
    metadata = %{owner_ref: sandbox.owner_ref, mechanism: mechanism, sandbox_id: sandbox.id}

    :telemetry.span([:ex_sandbox, operation], metadata, fn ->
      result = fun.()
      {result, Map.put(metadata, :result, outcome(result))}
    end)
  end

  @doc """
  Records that a host could not provide what a mechanism requires.

  Emitted where the refusal happens rather than left to the caller: a mechanism
  refusing to start is the correct behaviour but an invisible one, and an
  operator seeing no sandboxes start needs to know it was a capability decision
  rather than a crash.
  """
  @spec capability_unavailable(module(), ExSandbox.Sandbox.t() | nil, [ExSandbox.Capability.t()]) ::
          :ok
  def capability_unavailable(mechanism, sandbox, missing) do
    :telemetry.execute(
      [:ex_sandbox, :capability, :unavailable],
      %{count: 1},
      %{
        owner_ref: sandbox && sandbox.owner_ref,
        mechanism: mechanism,
        missing: Enum.map(missing, & &1.name),
        detail: Enum.map(missing, & &1.detail)
      }
    )
  end

  # 010-FR-004: distinct causes stay distinct. Collapsing every error into
  # `:error` is what makes a telemetry stream useless for diagnosis, and it is
  # the cheapest thing to get wrong here.
  defp outcome(:ok), do: :ok
  defp outcome({:ok, _}), do: :ok
  defp outcome({:error, reason}), do: {:error, reason}
  defp outcome(other), do: {:unexpected, other}
end
