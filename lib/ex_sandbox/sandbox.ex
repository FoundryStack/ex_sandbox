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
  data model and stays in the consumer's own data layer -- in the originating
  application, a separate `ash_sandbox` package; anywhere else, the host. A mechanism
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
          workspace_path: String.t() | nil,
          service_port: :inet.port_number() | nil,
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
    # An absolute host directory the sandbox's contents live in, supplied by the
    # host and made reachable from inside by whatever means the mechanism has.
    #
    # ⚠️ NOT opaque, unlike the three fields below it. A mechanism reads this
    # one and acts on it, which is why it is a path rather than a reference: the
    # host is what knows where a tenant's files live (`FR-008` keeps tenancy out
    # of this library), and the mechanism is what knows how to put a directory
    # inside a sandbox. Neither can do the other's half.
    #
    # `nil` means the sandbox has no workspace, which a mechanism must treat as
    # "mount nothing" rather than as "mount somewhere sensible".
    :workspace_path,
    # The port an application inside the sandbox listens on, or `nil`.
    #
    # ⚠️ NOT opaque either, and it is the field that decides a sandbox's network
    # posture rather than merely describing it. A sandbox that names a port is
    # asking to be reachable from the host, and a mechanism that can offer that
    # must publish the port on the loopback interface and report the resulting
    # address through `c:ExSandbox.Mechanism.address/1`. A sandbox that names
    # none must be given no network at all -- which is the default, so a host
    # that never sets this field keeps the posture it has today.
    #
    # It is the port **inside** the sandbox. The host-side port is not stored
    # here because the host does not choose it: the mechanism publishes on an
    # ephemeral port and `address/1` reports what it got, so two sandboxes
    # cannot be handed the same host port by two callers who each checked it
    # was free.
    :service_port,
    context: nil
  ]
end
