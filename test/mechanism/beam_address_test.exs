defmodule ExSandbox.Mechanism.BeamAddressTest do
  @moduledoc """
  A mechanism with no address says so, rather than offering the handle it has
  (design D13).

  `ExSandbox.Mechanism.Beam` publishes `"peer:<id>"` as its conformance context
  address -- a name for the sandbox that no socket can reach. The risk this file
  exists against is that it gets returned from `address/1` because it is there
  and it is a string: a caller would then put it in an `iframe` and read a
  broken frame instead of the clear absence the callback documents.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  defp sandbox do
    %Sandbox{
      id: "beam-address-#{System.unique_integer([:positive])}",
      owner_ref: "test",
      template_ref: "test"
    }
  end

  test "reports no address" do
    assert {:ok, nil} = Beam.address(sandbox())
  end

  test "does not return the opaque peer handle as though it were an address" do
    sandbox = sandbox()

    # ⚠️ Called through a variable, so the compiler cannot fold this to a
    # constant. Written as `Beam.address(sandbox)` it infers the return value
    # from the implementation and reports the comparison below as always false
    # -- which is the assertion passing for the wrong reason: it would go on
    # "passing" if the implementation started returning the handle, because the
    # warning, not the test, is what carries the finding.
    mechanism = Beam

    assert {:ok, address} = mechanism.address(sandbox)
    refute is_binary(address)
    refute address == "peer:" <> sandbox.id
  end

  test "reports none for a sandbox that names a service port, since it can publish none" do
    # A host may set the field for every sandbox it creates without knowing
    # which mechanism will run it. The field is a request, not a promise.
    assert {:ok, nil} = Beam.address(%{sandbox() | service_port: 4000})
  end
end
