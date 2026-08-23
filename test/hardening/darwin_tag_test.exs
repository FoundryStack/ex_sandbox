defmodule ExSandbox.Hardening.DarwinTagTest do
  @moduledoc """
  The `:darwin_hardening` tag makes `014`'s macOS tests **absent** off Darwin
  rather than green, and the per-capability vocabulary they will report through
  answers on every host (014 T003-T006).

  ## Why an exclusion needs its own test

  `test_helper.exs` already carries the argument at length: a suite that looks
  like it ran, on a host where the thing it checks does not exist, is the same
  false confidence as a cap that was configured and silently not applied. The
  exclusion is the fix, and it has two failure modes that are invisible from
  inside a green run:

    * the exclusion is dropped or misspelled, and macOS tests execute on Linux
      CI, failing for a reason that reads as a mechanism defect; or
    * the exclusion works and the test modules never carry the tag, so nothing
      is excluded and the first failure mode happens anyway.

  The canary below covers both from the only angle that works: it is a test
  that must **fail** if it ever runs off Darwin. An exclusion cannot be proven
  by a test that passes either way.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Capability

  # `:resource_limits`' per-capability decomposition (014-FR-013a).
  @decomposed [:process_separation, :memory_cap, :cpu_cap, :time_budget]

  # The three that are host-enforced, and so derived from the cgroup v2 probe.
  # `:time_budget` is deliberately absent: `014-FR-014b` puts its enforcement in
  # the supervising BEAM, so it decomposes `:resource_limits`' *reporting*
  # without sharing its evidence.
  @derived_from_resource_limits [:process_separation, :memory_cap, :cpu_cap]

  defp darwin?, do: match?({:unix, :darwin}, :os.type())
  defp linux?, do: match?({:unix, :linux}, :os.type())

  describe "the :darwin_hardening exclusion" do
    test "is configured off Darwin and lifted on Darwin" do
      excluded? = :darwin_hardening in ExUnit.configuration()[:exclude]

      assert excluded? == not darwin?(),
             """
             `:darwin_hardening` is #{if excluded?, do: "excluded", else: "included"} \
             on #{inspect(:os.type())}.

             Off Darwin it must be excluded: these tests breach macOS caps \
             (`taskpolicy -m`, `RLIMIT_CPU`, `sandbox-exec`) that no Linux host \
             provides, so running them there reports the failure of a guarantee \
             that was never this host's to give.

             On Darwin it must NOT be excluded, which is the half that is easy to \
             get wrong silently: an over-broad exclusion turns the whole macOS \
             floor into a green run on the one host that could have verified it.
             """
    end

    @tag :darwin_hardening
    test "canary: a tagged test never executes off Darwin" do
      # ⚠️ This test exists to FAIL, not to pass. Off Darwin the exclusion above
      # must keep it from running at all; if it runs there, the assertion below
      # reports that in the only way ExUnit can hear -- a failure.
      #
      # A canary written the other way round (`assert true`) would pass on Linux
      # and prove exactly nothing, which is the shape of check this feature
      # exists to remove.
      assert darwin?(),
             """
             A `:darwin_hardening` test executed on #{inspect(:os.type())}.

             The exclusion in `test/test_helper.exs` is not reaching this module. \
             Every other `014` Darwin test is now running here too, and each will \
             fail against a macOS mechanism this host does not have -- read those \
             failures as this defect, not as a broken cap.
             """
    end
  end

  describe "the per-capability vocabulary (014-FR-013a)" do
    test "every decomposed name is requirable and answerable" do
      for name <- @decomposed do
        assert name in Capability.known(),
               "`#{inspect(name)}` is not in `known/0`, so no mechanism can require it " <>
                 "and `check/1` reports it unknown -- the unrequirable-capability shape " <>
                 "`:network_restriction` was in for as long as it existed (005 T060c)"

        report = Capability.check(name)
        assert %Capability{name: ^name} = report
        assert is_boolean(report.available?)

        unless report.available? do
          assert is_binary(report.detail) and report.detail != "",
                 "#{inspect(name)} is unavailable with no detail; FR-016 requires saying why"
        end
      end
    end

    test "the coarse name it decomposes is still requirable" do
      # The decomposition is additive. `Mechanism.Beam.required_capabilities/0`
      # names `:resource_limits`, and removing it would silently drop the gate
      # that keeps a launch off a host with no cgroup v2 scope.
      assert :resource_limits in Capability.known()
    end
  end

  describe "derivation, not re-probing (014 T006)" do
    test "each host-enforced name carries the same verdict as :resource_limits" do
      # ⚠️ The invariant this guards is that there is ONE probe of the cgroup v2
      # scope, read under several names. Two probes of one fact are two things
      # that must stay equal forever; this file has already recorded them
      # splitting twice (005 T060a5c, T060c), and the visible symptom both times
      # was a boundary reported present on a host that never built it.
      #
      # Asserted on Linux, where the probe has something to find. Elsewhere the
      # comparison is vacuous -- every clause reports false -- and a vacuous
      # pass is not evidence, so it is not claimed as one.
      if linux?() do
        coarse = Capability.check(:resource_limits).available?

        for name <- @derived_from_resource_limits do
          assert Capability.check(name).available? == coarse,
                 """
                 `#{inspect(name)}` disagrees with `:resource_limits` on this host.

                 It is meant to be *derived* from that clause, not probed again. A \
                 disagreement means a second probe of the cgroup v2 scope has been \
                 introduced, and from here on the two can drift -- with the failure \
                 landing as a cap reported enforced on a host that does not enforce it.
                 """
        end
      else
        assert Capability.check(:resource_limits).available? == false
      end
    end

    test ":time_budget is not derived from the cgroup probe" do
      # It is not a host fact: `014-FR-014b` places its enforcement in the
      # supervising BEAM. Deriving it would report the budget missing on a
      # cgroup-less Linux host -- and `FR-014b` makes a missing budget refuse
      # the run outright, so that under-claim costs the deployment rather than
      # a warning.
      report = Capability.check(:time_budget)

      refute report.available?

      assert report.detail =~ "supervising BEAM",
             "the detail must say where enforcement actually lives, or a reader takes " <>
               "`false` to mean the host cannot do it"
    end
  end

  describe "the Darwin caps, before any backend exists" do
    @tag :darwin_hardening
    test "every decomposed capability reports unavailable" do
      # ⚠️ TO WHOEVER IMPLEMENTS `014` T020: this test is the gate, and editing
      # it is meant to cost you a decision.
      #
      # Flipping a name here to `available` is the claim `FR-014a` governs, and
      # the evidence for it is T017 passing -- the ordering regression test that
      # shows the misordered composition allocating 300 MB under a 100 MB cap
      # and the backend's own composition killing it at 137. Until that test
      # exists and passes, a Darwin `available` is a cap nobody has watched stop
      # a breach, which is the state this whole slice exists to remove.
      for name <- @decomposed do
        report = Capability.check(name)

        refute report.available?,
               "#{inspect(name)} reports available on macOS. If T017 now passes, update " <>
                 "this test deliberately; if it does not, this is the fail-open claim " <>
                 "FR-014a forbids."

        assert is_binary(report.detail) and report.detail != ""
      end
    end
  end
end
