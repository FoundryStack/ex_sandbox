defmodule ExSandbox.Sandbox do
  @moduledoc """
  The struct every `ExSandbox.Mechanism` callback receives (012 T012).

  Carries **only what a mechanism needs to do its job**, which is materially
  less than what a host application stores about a sandbox. This replaces
  `003`'s `SandboxRecord.t()` in the mechanism contract (research R3) — that
  type was an Ash resource struct, and `FR-001` forbids `ex_sandbox` an Ash
  dependency.

  ## Deliberately absent

  `environment_id`, `data_store_ref`, `data_store_placement`, tenant
  attribution, `last_request_at`, `state_changed_at`. Each exists in `003`'s
  data model and stays in `ash_sandbox` or the host application. A mechanism
  that needed any of them would be reaching into host concepts, which is the
  dependency direction this library exists to prevent.

  ## Opaque fields

  `owner_ref`, `mechanism_ref`, and `context` are stored, compared, and
  propagated — never parsed, and never used to make a decision (`FR-007`,
  `FR-003`). `owner_ref` is a bare binary rather than a richer type for exactly
  this reason: any structure is an invitation to interpret it.
  """

  @type t :: %__MODULE__{
          id: String.t(),
          owner_ref: String.t(),
          template_ref: String.t(),
          cpu_limit: non_neg_integer() | nil,
          memory_limit_mb: non_neg_integer() | nil,
          disk_quota_mb: non_neg_integer() | nil,
          mechanism_ref: String.t() | nil,
          context: term()
        }

  @enforce_keys [:id, :owner_ref, :template_ref]
  defstruct [
    :id,
    :owner_ref,
    :template_ref,
    # Millicores (003-FR-004).
    :cpu_limit,
    :memory_limit_mb,
    :disk_quota_mb,
    # An opaque handle the mechanism assigns once the sandbox exists (003 R5).
    :mechanism_ref,
    context: nil
  ]
end
