defmodule ExSandbox.Mechanism.BeamAddressTest do
  @moduledoc """
  A launched sandbox that names a service port is addressed at the host
  loopback port `pasta` publishes it on; any other sandbox says it has no
  address, rather than offering the handle it has (design D13).

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

  test "reports none for a sandbox this mechanism never launched, service port or not" do
    assert {:ok, nil} = Beam.address(%{sandbox() | service_port: 4000})
  end

  describe "a launched row" do
    test "with a forward is addressed at the host loopback port pasta publishes" do
      assert Beam.address_of(%{forward: {52_111, 4000}}) == "127.0.0.1:52111"
    end

    test "without a forward has no address" do
      assert Beam.address_of(%{forward: nil}) == nil
      assert Beam.address_of(%{}) == nil
    end

    test "with several forwards is addressed at the primary pair" do
      assert Beam.address_of(%{forward: [{52_111, 4000}, {52_112, 4001}]}) == "127.0.0.1:52111"
      assert Beam.address_of(%{forward: []}) == nil
    end

    test "that is stopped has no address, though it keeps its old forward" do
      assert Beam.address_of(%{forward: {52_111, 4000}, stopped: true, peer: nil}) == nil
    end
  end

  describe "a launched row, asked for one port" do
    @forward [{52_111, 4000}, {52_112, 4001}]

    test "is addressed at the pair whose namespace port matches" do
      assert Beam.address_of(%{forward: @forward}, 4000) == "127.0.0.1:52111"
      assert Beam.address_of(%{forward: @forward}, 4001) == "127.0.0.1:52112"
    end

    test "has no address for a port it does not publish" do
      assert Beam.address_of(%{forward: @forward}, 4002) == nil
      assert Beam.address_of(%{forward: nil}, 4000) == nil
      assert Beam.address_of(%{}, 4000) == nil
    end

    test "persisted as a legacy tuple still answers for its one port" do
      assert Beam.address_of(%{forward: {52_111, 4000}}, 4000) == "127.0.0.1:52111"
      assert Beam.address_of(%{forward: {52_111, 4000}}, 4001) == nil
    end

    test "that is stopped has no address for any port" do
      assert Beam.address_of(%{forward: @forward, stopped: true}, 4001) == nil
    end

    test "never launched reports none" do
      assert {:ok, nil} = Beam.address(%{sandbox() | service_port: 4000}, 4000)
    end
  end
end
