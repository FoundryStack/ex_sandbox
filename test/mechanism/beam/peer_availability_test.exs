defmodule ExSandbox.Mechanism.Beam.PeerAvailabilityTest do
  @moduledoc """
  `:peer` is present on this OTP release (005 T002, research R1).

  ## Why assert something OTP ships

  `:peer` arrived in **OTP 25**, replacing `:slave`. The BEAM mechanism has no
  dependency to add for launching a separate runtime — it uses this — which
  means the OTP floor is invisible: nothing in `mix.exs` records it, and
  `mix deps.get` cannot enforce it.

  Without this test, running on OTP 24 fails at the first *provision*, in
  production, as `:undef`. With it, the failure is a named test at compile
  time saying exactly which OTP version is required.
  """
  use ExUnit.Case, async: true

  test "the :peer module is loadable" do
    assert {:module, :peer} = :code.ensure_loaded(:peer),
           """
           `:peer` is not available on this OTP release (#{System.otp_release()}).

           The BEAM mechanism launches each sandbox as a separate node via
           `:peer.start_link/1`, which OTP 25 introduced. There is no fallback:
           `:slave` was removed, and running tenant code in the platform's own
           runtime is the thing this mechanism exists to prevent.
           """
  end

  test "the launch and shutdown functions the mechanism calls are exported" do
    # Named individually rather than checking the module loads: `:peer` could
    # load while an arity the mechanism depends on differs across releases,
    # and that failure would otherwise surface at first provision.
    for {function, arity} <- [{:start_link, 1}, {:stop, 1}, {:call, 4}, {:random_name, 0}] do
      assert function_exported?(:peer, function, arity),
             ":peer.#{function}/#{arity} is not exported on OTP #{System.otp_release()}"
    end
  end

  test "the OTP release is at least 25" do
    # The floor `:peer` implies, asserted directly so the requirement is
    # readable rather than inferred from a missing-module error.
    release = String.to_integer(System.otp_release())

    assert release >= 25,
           "the BEAM mechanism requires OTP 25 or later for `:peer`; this is OTP #{release}"
  end
end
