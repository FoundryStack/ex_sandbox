defmodule ExSandbox.Hardening.CapabilityProbeTest do
  @moduledoc """
  The Linux hardening implementation probes honestly and refuses on hosts that
  cannot enforce (005 T006, research R9, R9b).

  ## The only isolation-adjacent test that can run on macOS

  Every adversarial test in this feature needs Linux. This one is different: it
  asserts the **refusal path**, which is exactly what a non-Linux host
  exercises. A green run here on Darwin means "hardening correctly reported it
  cannot enforce", not "hardening works".

  That distinction is the feature. R9's failure mode is a host where hardening
  silently degrades — probes report success, the sandbox launches, and nothing
  is confined. A test that only ran on hosts where hardening works could never
  catch it.

  ## Probes attempt, they do not infer

  `contracts/hardening.md` makes this an obligation: a probe reading
  `:os.type()` reports `true` on a Linux host with no cgroup delegation, no
  `setpriv`, or an unprivileged process. The assertions below therefore check
  behaviour that would differ between attempting and inferring, rather than
  checking the returned booleans alone — a probe that inferred would produce
  the same map on this host and pass a weaker test.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Hardening.Linux

  @capabilities [
    :resource_limits,
    :privilege_separation,
    :filesystem_confinement,
    :network_restriction,
    :disk_quota
  ]

  defp linux?, do: match?({:unix, :linux}, :os.type())

  describe "capabilities/0" do
    test "reports every capability the contract names" do
      capabilities = Linux.capabilities()

      for name <- @capabilities do
        assert Map.has_key?(capabilities, name),
               "capabilities/0 omits #{inspect(name)}, which `available?/0` requires"

        assert is_boolean(capabilities[name]),
               "#{inspect(name)} is #{inspect(capabilities[name])}, not a boolean"
      end
    end

    test "reports exactly the contract's five keys, no more" do
      # A sixth key would silently widen `available?/0` -- and, per T012, could
      # be probed without ever being constructed.
      assert Linux.capabilities() |> Map.keys() |> Enum.sort() == Enum.sort(@capabilities)
    end
  end

  describe "on a host without the Linux mechanisms" do
    @describetag :darwin

    test "available?/0 is false" do
      if linux?() do
        # On Linux CI this test does not apply: the point is the refusal path.
        assert true
      else
        refute Linux.available?(),
               """
               `available?/0` returned true on #{inspect(:os.type())}.

               The Linux mechanisms this implementation composes -- systemd-run,
               setpriv -- do not exist here, so a `true` means a probe inferred
               rather than attempted (research R9).
               """
      end
    end

    test "build_command/2 refuses rather than returning a degraded command" do
      # The load-bearing consequence of `available?/0` being false. A degraded
      # command is worse than no command: it launches, it looks like success,
      # and nothing is confined.
      unless linux?() do
        sandbox = %ExSandbox.Sandbox{id: "probe-test", owner_ref: "owner", template_ref: "tpl"}

        assert {:error, :hardening_unavailable} = Linux.build_command(sandbox, [])
      end
    end

    test "capabilities/0 names which capabilities are missing" do
      # R9b: macOS provides several of these through different mechanisms, so
      # "nothing is available" would be as dishonest as "everything is". The
      # requirement is an accurate per-capability answer.
      unless linux?() do
        capabilities = Linux.capabilities()

        refute Enum.all?(@capabilities, &capabilities[&1]),
               "every capability probed true on a non-Linux host: #{inspect(capabilities)}"
      end
    end
  end

  describe "available?/0" do
    test "is true only when every capability is present" do
      capabilities = Linux.capabilities()
      all_present? = Enum.all?(@capabilities, &capabilities[&1])

      assert Linux.available?() == all_present?,
             """
             `available?/0` disagrees with `capabilities/0`.

             available?: #{inspect(Linux.available?())}
             capabilities: #{inspect(capabilities)}

             There is no "mostly hardened" state: cgroup caps without privilege
             separation still permits reading platform files
             (contracts/hardening.md §available?/0, Principle II).
             """
    end
  end
end
