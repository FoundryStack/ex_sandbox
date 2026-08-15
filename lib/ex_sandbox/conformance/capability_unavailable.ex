defmodule ExSandbox.Conformance.CapabilityUnavailable do
  @moduledoc """
  The suite's third outcome (012 T034).

  Raised when a check needs a host capability that `ExSandbox.Capability` reports
  absent, or when a resource cap could not be demonstrated either way
  (`FR-012b`).

  It is an exception so it terminates the check, but it is **not a failure** —
  the group wrappers translate it into an `ExUnit` skip carrying the reason. The
  distinction is `FR-011`'s: an exclusion is something a consumer asks for, and
  nothing here is reachable from consumer configuration.
  """
  defexception [:capability, :detail]

  @impl true
  def message(%{capability: capability, detail: detail}) do
    """
    Host capability unavailable: #{inspect(capability)}

    #{detail || "no further detail"}

    This is neither a pass nor a failure. The check could not be performed on
    this host, and reporting it as passing would claim a guarantee that was
    never demonstrated (FR-012b).
    """
  end
end
