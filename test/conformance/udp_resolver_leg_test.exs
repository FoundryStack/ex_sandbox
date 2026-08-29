defmodule ExSandbox.Conformance.UdpResolverLegTest do
  @moduledoc """
  The UDP egress check must not read the sandbox's OWN resolver as an escape
  (029 T015, `FR-013`).

  `attempt_udp_egress/2` was written when nothing served `127.0.0.1:53` inside
  a sandbox's namespace, so an answer from that address could only mean the
  datagram had left the namespace and reached the host's resolver. `FR-013`
  changes what that address is: it is now served from *inside* the namespace by
  the acceptor's DNS leg, and an answer from it is the exemption working.

  Measured in the isolation image before this change, against a sandbox whose
  UDP drop was installed and enforcing:

      Evidence: "a UDP datagram sent from inside the sandbox to 127.0.0.1:53
      was ANSWERED -- it left the namespace unpoliced and the reply came back,
      so the egress policy covers TCP only (029-FR-013)"

  The opposite of the truth. This file pins the corrected reading, and pins the
  control that stops the correction turning into a check that cannot fail.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Conformance.CapabilityUnavailable
  alias ExSandbox.Conformance.Network

  # ⚠️ Seeded rather than measured, and ONLY this one value. `require_host_answers_udp/0`
  # asks whether this host gets a UDP answer from the denied address at all --
  # a real network question this file has no business asking, and whose answer
  # on a CI runner would decide whether these assertions run. Everything the
  # tests actually assert is still driven through the probe below.
  @udp_control_key {Network, :denied_address_udp_control}

  setup do
    previous = :persistent_term.get(@udp_control_key, :unknown)
    :persistent_term.put(@udp_control_key, :yes)

    on_exit(fn ->
      case previous do
        :unknown -> :persistent_term.erase(@udp_control_key)
        other -> :persistent_term.put(@udp_control_key, other)
      end
    end)

    :ok
  end

  defp sandbox(context) do
    %ExSandbox.Sandbox{
      id: "udp-leg-#{System.unique_integer([:positive])}",
      owner_ref: "test",
      template_ref: "test",
      cpu_limit: 1000,
      memory_limit_mb: 128,
      disk_quota_mb: 64,
      context: context
    }
  end

  # Answers only the addresses named, records every address asked.
  defp probe(answers) do
    parent = self()

    fn host, port ->
      send(parent, {:probed, {host, port}})
      if {host, port} in answers, do: :answered, else: :unanswered
    end
  end

  defp probed do
    receive do
      {:probed, leg} -> [leg | probed()]
    after
      0 -> []
    end
  end

  test "an answer from the sandbox's own resolver is not an escape" do
    resolver = {"127.0.0.1", 53}

    sandbox =
      sandbox(%{
        resolver: resolver,
        gateway: "10.0.0.1",
        udp_probe: probe([resolver])
      })

    assert {:refused, _} = Network.attempt_udp_egress(ExSandbox.Mechanism.Beam, sandbox)

    legs = probed()
    assert resolver in legs, "the resolver must still be probed -- it is the control"

    refute Enum.count(legs, &(&1 == resolver)) > 1,
           "the resolver was probed a second time as an escape leg"
  end

  test "an answer from any OTHER destination is still an escape" do
    resolver = {"127.0.0.1", 53}
    gateway = {"10.0.0.1", 53}

    sandbox =
      sandbox(%{
        resolver: resolver,
        gateway: "10.0.0.1",
        udp_probe: probe([resolver, gateway])
      })

    assert {:succeeded, evidence} =
             Network.attempt_udp_egress(ExSandbox.Mechanism.Beam, sandbox)

    assert evidence =~ "10.0.0.1:53"
  end

  test "a resolver that does not answer makes the check report the third outcome" do
    # ⚠️ The control this file exists to protect. With the resolver silent,
    # every remaining leg is silent too -- which is indistinguishable from a
    # namespace with no network at all, and used to score as the boundary
    # holding.
    sandbox =
      sandbox(%{
        resolver: {"127.0.0.1", 53},
        gateway: "10.0.0.1",
        udp_probe: probe([])
      })

    assert_raise CapabilityUnavailable, ~r/did not answer/, fn ->
      Network.attempt_udp_egress(ExSandbox.Mechanism.Beam, sandbox)
    end
  end

  test "a mechanism declaring no resolver keeps the loopback leg" do
    # A sandbox with no name resolution at all is a legitimate configuration
    # (`LaunchPlan` takes `resolver: nil`), and its loopback leg is the one it
    # had before `FR-013`.
    sandbox = sandbox(%{udp_probe: probe([{"127.0.0.1", 53}])})

    assert {:succeeded, evidence} =
             Network.attempt_udp_egress(ExSandbox.Mechanism.Beam, sandbox)

    assert evidence =~ "127.0.0.1:53"
  end
end
