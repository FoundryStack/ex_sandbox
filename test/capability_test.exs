defmodule ExSandbox.CapabilityTest do
  @moduledoc """
  `Capability.known/0` is the vocabulary a mechanism can require in, and
  anything outside it is unrequireable (005 T060c, `012-FR-016`).

  ## The gap that made this file necessary

  `ExSandbox.Hardening.Linux` has probed `network_restriction` since it was
  written. `Capability.known/0` did not list it, so no mechanism could name it
  in `required_capabilities/0` — `check/1` would have reported it unknown. The
  BEAM mechanism therefore required three capabilities while
  `build_command/2` composed `--unshare-net` unconditionally, and a host that
  could not create a network namespace was never asked about the one boundary
  `005-SC-002` rests on.

  Nothing failed. Every test in this suite passed, the probe returned an honest
  answer, and no code read it. That is the shape worth guarding: not a wrong
  value, but a correct value with no consumer.

  ## Why parity, and why in this direction

  `ExSandbox.Hardening.CapabilityBuildParityTest` already asserts probe ↔
  command. This asserts probe ↔ *vocabulary*, which is the other half and the
  half that was missing. The direction is deliberate: a probed capability
  absent from `known/0` is the silent case, because it looks like an
  unrequired capability rather than an unrequirable one.

  The reverse — a known name the Linux prober does not report — is checked
  separately and more loosely, because a capability could legitimately be
  determined without a Linux probe.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Capability
  alias ExSandbox.Hardening.Linux

  describe "known/0 as a vocabulary" do
    test "every capability the Linux prober reports can be named by a mechanism" do
      probed = Linux.capabilities() |> Map.keys() |> MapSet.new()
      known = MapSet.new(Capability.known())

      unrequireable = MapSet.difference(probed, known) |> MapSet.to_list() |> Enum.sort()

      assert unrequireable == [],
             """
             `Hardening.Linux` probes #{inspect(unrequireable)}, but `Capability.known/0` \
             does not list #{if length(unrequireable) == 1, do: "it", else: "them"}.

             A mechanism cannot require a name outside `known/0` -- `check/1` reports it \
             unknown -- so this capability is probed, answered honestly, and consulted by \
             nobody. That is exactly how `:network_restriction` went unrequired while \
             `build_command/2` composed `--unshare-net` unconditionally.

             Either add it to `known/0` with a `do_check/2` clause, or stop probing it.
             """
    end

    test "check/1 answers for every known name without raising" do
      # `check/1`'s docstring promises it never raises, because "cannot
      # determine" must be reported rather than thrown (FR-012b). A `known/0`
      # entry with no `do_check/2` clause would fall to the catch-all and
      # report unavailable, which is the correct direction -- this asserts it
      # reaches an answer at all.
      for name <- Capability.known() do
        report = Capability.check(name)

        assert %Capability{name: ^name} = report
        assert is_boolean(report.available?)

        unless report.available? do
          assert is_binary(report.detail) and report.detail != "",
                 "#{inspect(name)} is unavailable with no detail; FR-016 requires saying why"
        end
      end
    end
  end

  describe "network_restriction" do
    test "is a known capability" do
      assert :network_restriction in Capability.known(),
             "005-SC-002 (cluster isolation) rests on the network namespace; " <>
               "a mechanism must be able to require it"
    end

    @tag :darwin
    test "is unavailable on macOS, and says why" do
      if match?({:unix, :darwin}, :os.type()) do
        report = Capability.check(:network_restriction)

        refute report.available?,
               "macOS has no network namespace; reporting this available would let " <>
                 "provisioning succeed with no egress boundary"

        assert report.detail =~ "exec",
               "the detail must name the reason (005 R9b: a sandbox-exec profile is " <>
                 "not inherited across an intervening exec), not just say unavailable"
      end
    end
  end

  describe "agreement with the Linux prober" do
    test "every capability both modules answer gets the same verdict" do
      # The two are independent implementations of the same question -- one in
      # `Capability`, one in `Hardening.Linux` -- deliberately, because
      # `Capability` is consulted before a mechanism is chosen and must not
      # depend on one mechanism's hardening module.
      #
      # Independent implementations are what makes agreement worth asserting.
      # `ExSandbox.provision/2` consults the first and `build_command/2` the
      # second, so a disagreement means provisioning admits a sandbox the
      # hardening layer then refuses to build -- or, in the other direction,
      # builds one whose boundary was never checked.
      probed = Linux.capabilities()

      disagreements =
        for name <- Capability.known(),
            Map.has_key?(probed, name),
            Capability.check(name).available? != Map.fetch!(probed, name),
            do: {name, capability: Capability.check(name).available?, linux: probed[name]}

      assert disagreements == [],
             """
             `Capability.check/1` and `Hardening.Linux.capabilities/0` disagree:

             #{inspect(disagreements, pretty: true)}

             Both answer "can this host enforce it". A split verdict means one of the \
             two gates admits what the other refuses, and which one you hit depends on \
             whether you asked before provisioning or during the launch.
             """
    end
  end

  describe "agreement with the Darwin backend (014 T023)" do
    # ⚠️ The same guard as the Linux one above, pointed at the other backend —
    # and it exists for the same recorded reason. `005` T060c caught the Linux
    # clauses disagreeing with `Hardening.Linux` *on macOS*, and the symptom was
    # never "one probe is wrong": it was a boundary reported present on a host
    # that had not built it.
    #
    # `Capability.check/1` is what `ExSandbox.provision/2` consults; the
    # backend's map is what the launch is built from. A split verdict means one
    # gate admits what the other refuses, and which you hit depends on when you
    # asked.
    #
    # ⚠️ ONE name is expected to diverge, and expecting it is the point.
    # `:filesystem_confinement` means different things to the two modules and
    # the difference is load-bearing:
    #
    #   * `Hardening.Darwin` reports `true`: its `sandbox-exec` profile does
    #     confine where the target may write, and T016 verifies that by
    #     breaching it.
    #   * `Capability` reports `false`: that name is in `gating_defaults/0` AND
    #     in `Mechanism.Beam.required_capabilities/0`, where its own comment
    #     says it means *the mount namespace*. Flipping it on macOS would make
    #     `ExSandbox.provision/2` admit a BEAM sandbox on a host with no
    #     `bwrap`, which fails at launch — a fail-open change to the gate, not a
    #     reporting change.
    #
    # That asymmetry is why `014` T020 names three capabilities and not four:
    # `:memory_cap`, `:cpu_cap` and `:process_separation` are report-only here,
    # so flipping them on measured evidence changes what is *said* and nothing
    # about what is *admitted*.
    #
    # Asserted as an exact set rather than skipped, so it cannot rot: making the
    # two agree on this name — in either direction — turns this red and asks for
    # the decision to be made deliberately.
    @documented_divergences [:filesystem_confinement]

    @tag :darwin_hardening
    test "every shared capability agrees, apart from the documented divergence" do
      probed = ExSandbox.Hardening.Darwin.capabilities()

      shared =
        for name <- Capability.known(),
            Map.has_key?(probed, name),
            do: {name, capability: Capability.check(name).available?, darwin: probed[name]}

      disagreements =
        for {name, capability: mine, darwin: theirs} <- shared, mine != theirs, do: name

      assert Enum.sort(disagreements) == Enum.sort(@documented_divergences),
             """
             `Capability.check/1` and `Hardening.Darwin.capabilities/0` disagree on \
             #{inspect(Enum.sort(disagreements))}; the documented set is \
             #{inspect(Enum.sort(@documented_divergences))}.

             #{inspect(shared, pretty: true)}

             Both answer "can this host enforce it". A split verdict that is not in the \
             documented list means one of the two gates admits what the other refuses.

             If a divergence became correct, add it to `@documented_divergences` with the \
             reason. If one disappeared, remove it. Do not widen the list to make a run green.
             """
    end

    @tag :darwin_hardening
    test "the agreement is not vacuous: shared names are actually enforced here" do
      # ⚠️ Two modules that both answered `false` everywhere would satisfy the
      # test above while establishing nothing. This requires the agreement to be
      # over at least one `true`, which on this host it is — T020 flipped three
      # names on T016/T017's evidence.
      probed = ExSandbox.Hardening.Darwin.capabilities()

      agreed_true =
        for name <- Capability.known(),
            Map.fetch(probed, name) == {:ok, true},
            Capability.check(name).available?,
            do: name

      assert :memory_cap in agreed_true
      assert :cpu_cap in agreed_true
      assert :process_separation in agreed_true
    end

    @tag :darwin_hardening
    test "the divergence is exactly the one documented, in the direction documented" do
      # Named individually so the failure says which half moved.
      refute Capability.check(:filesystem_confinement).available?,
             "`Capability` now reports :filesystem_confinement available on macOS. That " <>
               "name gates `Mechanism.Beam`, which composes `bwrap` — so this admits a " <>
               "sandbox the launch cannot build. If Phase 5 changed what the mechanism " <>
               "composes here, change the gate deliberately and update the guard above."

      assert ExSandbox.Hardening.Darwin.capabilities()[:filesystem_confinement],
             "the Darwin backend no longer reports :filesystem_confinement; the divergence " <>
               "recorded above has gone away and the documented set should shrink"
    end
  end

  describe "an unknown name" do
    test "is reported, not raised" do
      report = Capability.check(:no_such_capability)

      refute report.available?
      assert is_binary(report.detail)
    end
  end

  describe "missing/1" do
    test "returns only unavailable capabilities, each with a detail" do
      for report <- Capability.missing(Capability.known()) do
        refute report.available?
        assert is_binary(report.detail) and report.detail != ""
      end
    end
  end
end
