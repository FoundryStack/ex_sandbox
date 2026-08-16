defmodule ExSandbox.Mechanism.Beam.PlacementTelemetryTest do
  @moduledoc """
  Placements are announced, not written (005 T041, `FR-016`, `012-FR-001`).

  ## The constraint being tested is an absence

  `012-FR-001` requires `ex_sandbox` to reference no host module. A placement row
  lives in Axonn's schema, so the mechanism cannot write one — it emits an event
  and a host that cares attaches a handler.

  That is easy to satisfy accidentally and easy to break accidentally, because
  nothing fails at compile time when a library starts reaching for a host
  module. So this asserts the event carries everything a host needs to write the
  row itself: if it did not, the pressure to close the gap with a direct call
  would be real.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Telemetry

  @event [:ex_sandbox, :sandbox, :placed]

  defp sandbox do
    %ExSandbox.Sandbox{
      id: "placed-#{System.unique_integer([:positive])}",
      owner_ref: "owner-#{System.unique_integer([:positive])}",
      template_ref: "t",
      memory_limit_mb: 128
    }
  end

  defp attach do
    test = self()
    handler = "placement-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler,
      @event,
      fn _event, measurements, metadata, _ -> send(test, {:placed, measurements, metadata}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler) end)
  end

  test "the event carries everything a host needs to record a placement" do
    attach()
    sb = sandbox()

    Telemetry.sandbox_placed(ExSandbox.Mechanism.Beam, sb, %{
      gateway_id: "gw-1",
      node_name: nil,
      cookie_ref: "sandbox:" <> sb.id,
      os_pid: 4321
    })

    assert_receive {:placed, %{count: 1}, metadata}

    # Every field `Placement` requires. A missing one here is what would make a
    # host reach into the library instead.
    assert metadata.sandbox_id == sb.id
    assert metadata.owner_ref == sb.owner_ref
    assert metadata.gateway_id == "gw-1"
    assert metadata.os_pid == 4321
    assert metadata.cookie_ref == "sandbox:" <> sb.id
  end

  test "node_name is nil for an undistributed sandbox rather than absent" do
    # A sandbox does not run distributed -- naming the peer aborts its kernel
    # with `nodistribution`. The key must still be present, so a host writing a
    # placement row distinguishes "no node name" from "this mechanism forgot to
    # send one".
    attach()
    sb = sandbox()

    Telemetry.sandbox_placed(ExSandbox.Mechanism.Beam, sb, %{
      gateway_id: "gw-1",
      cookie_ref: "sandbox:" <> sb.id,
      os_pid: 1
    })

    assert_receive {:placed, _, metadata}
    assert Map.has_key?(metadata, :node_name)
    assert metadata.node_name == nil
  end

  test "the cookie itself is never in the metadata" do
    # Telemetry metadata reaches log aggregators and APM vendors. The cookie is
    # defence in depth for FR-003; emitting it would scatter it across exactly
    # the systems chosen for how searchable they are.
    attach()
    sb = sandbox()

    Telemetry.sandbox_placed(ExSandbox.Mechanism.Beam, sb, %{
      gateway_id: "gw-1",
      cookie_ref: "sandbox:" <> sb.id,
      os_pid: 1
    })

    assert_receive {:placed, _, metadata}

    refute Map.has_key?(metadata, :cookie)

    refute metadata.cookie_ref =~ ~r/^[A-Za-z0-9_-]{32,}$/,
           "cookie_ref looks like a cookie rather than a reference to one"
  end
end
