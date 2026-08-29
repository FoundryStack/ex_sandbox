defmodule ExSandbox.ConformancePeerHandlesMetaTest do
  @moduledoc """
  The peer-handle rule can fail, can pass, and today does neither
  (029 T034a; `029-FR-017`).

  ## Why a check needs all three demonstrated before the address exists

  `FR-017` holds today **structurally**: a sandbox's address is unnameable
  (`beam.ex:561-565`), so nothing enforces it and nothing can fail to. 029
  Phase 3 publishes a dialable address, which converts that property into a rule
  something must enforce forever. An enforcement point that has never refused
  anything is `029-FR-015`'s *"a control that reads as the guarantee it is
  not"* — so the rule and its check land **before** the address, and the check
  is held to the same standard the suite holds mechanisms to: demonstrated, not
  asserted.

  Three demonstrations, one per file section:

    * it FAILS against `ExSandbox.SharedRouteMechanism`, whose peers share a
      link and genuinely reach each other;
    * it PASSES against `ExSandbox.SeparatedPeersMechanism`, whose peers listen
      on sockets the platform genuinely opens and refuse each other;
    * it reports the THIRD OUTCOME against `ExSandbox.Mechanism.Beam` as that
      mechanism publishes context today, because there is no handle to attempt.

  ## The fourth section is the one that changes an existing verdict

  `ExSandbox.EditablePolicyMechanism` passes the *existing* peer check, and its
  own source says why: *"Nothing listens there, so the attempt is refused."* A
  refusal at a dead port is what a mechanism with no boundary produces. This
  check reports the third outcome there instead, which is the honest reading and
  the reason the liveness control exists.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Conformance.Network
  alias ExSandbox.SuiteRunner

  @check "every published handle of another sandbox is refused from inside"

  defp names(results) do
    Enum.map(results.passed, &Atom.to_string/1) ++
      Enum.map(results.failures ++ results.unavailable, fn {n, _} -> Atom.to_string(n) end)
  end

  defp matching(list, check) do
    Enum.filter(list, fn
      {name, _} -> Atom.to_string(name) =~ check
      name -> Atom.to_string(name) =~ check
    end)
  end

  defp network_results(mechanism), do: SuiteRunner.run(mechanism, describe: "network")

  defp sandbox(context) do
    ExSandbox.Conformance.Helpers.build_sandbox(context: context)
  end

  test "the check exists in the network group" do
    # Guards every assertion below: a rename makes them all match nothing and
    # stay green, which is the failure mode this file exists to catch arriving
    # through its own guard.
    present = names(network_results(ExSandbox.PorousMechanism))

    assert Enum.any?(present, &String.contains?(&1, @check)),
           "no network check named #{inspect(@check)} -- this file's assertions are vacuous"
  end

  describe "it can FAIL" do
    test "against a mechanism whose sandboxes share one route" do
      results = network_results(ExSandbox.SharedRouteMechanism)

      assert matching(results.failures, @check) != [],
             """
             The peer-handle check did not FAIL against a mechanism that puts every
             sandbox on one shared route with a real listener behind it.

             Passed:      #{inspect(matching(results.passed, @check))}
             Unavailable: #{inspect(matching(results.unavailable, @check))}
             """
    end

    test "when ONE of two declared handles is crossed and the other is refused" do
      # ⚠️ The property that distinguishes this check from the one probing
      # `context.address`, and the reason 029 Phase 3 needs it: a sandbox is
      # about to acquire a second handle (a host-side tuple, T033) and a third
      # (a public name, T040a) while `context.address` keeps naming the first.
      # A check that probes one handle reports green with the others open.
      {:ok, refused_listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      {:ok, crossed_listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      {:ok, refused_port} = :inet.port(refused_listener)
      {:ok, crossed_port} = :inet.port(crossed_listener)

      on_exit(fn ->
        :gen_tcp.close(refused_listener)
        :gen_tcp.close(crossed_listener)
      end)

      dialler =
        sandbox(%{
          connect: fn
            _host, ^crossed_port -> :connected
            _host, _port -> :refused
          end
        })

      target =
        sandbox(%{
          peer_handles: [{"127.0.0.1", refused_port}, {"127.0.0.1", crossed_port}]
        })

      error =
        assert_raise ExUnit.AssertionError, fn ->
          Network.require_every_peer_handle_refused(ExSandbox.EchoMechanism, dialler, target)
        end

      message = Exception.message(error)

      assert message =~ "029-FR-017"

      assert message =~ "1 of 2 published handle(s)",
             """
             The failure did not name how many handles were crossed, so a reader
             cannot tell a total breach from the one that matters here: a
             mechanism refusing the handle the suite knows about and leaking
             through the one it does not.

             Got: #{message}
             """

      refute message =~ "NOT DEMONSTRATED",
             "a crossing was reported as the third outcome, which files a breach as a gap"
    end

    test "against a mechanism that crosses a handle nothing is listening on" do
      # ⚠️ MEASURED 2026-08-29, and this test exists because the answer was
      # wrong. The liveness control used to run BEFORE the attempt, so a
      # mechanism whose `connect` reports success for every destination -- an
      # actual crossing -- was filed as the third outcome whenever the handle
      # happened to be dead. `probe_connect/5` was never reached, and a breach
      # was reported as an unfinished mechanism.
      #
      # Nothing has listened on this port in this VM, which is the whole point:
      # the handle is dead AND the mechanism crosses it. Only one of those two
      # facts is about the boundary.
      dead_port = 24_411

      dialler = sandbox(%{connect: fn _host, _port -> :connected end})
      target = sandbox(%{peer_handles: [{"127.0.0.1", dead_port}]})

      error =
        assert_raise ExUnit.AssertionError, fn ->
          Network.require_every_peer_handle_refused(ExSandbox.EchoMechanism, dialler, target)
        end

      message = Exception.message(error)

      refute message =~ "NOT DEMONSTRATED",
             """
             A mechanism that crossed a published handle was reported as the third
             outcome because nothing was listening on it.

             Liveness answers one question -- whether a REFUSAL distinguished
             anything -- and it cannot answer the other. A connection that
             succeeded is a breach at a live handle and at a dead one alike, and
             filing it as a gap puts a real leak under the same label as a
             mechanism that has not built the boundary yet.

             Got: #{message}
             """

      assert message =~ "029-FR-017",
             "the failure did not cite the rule it enforces\n\nGot: #{message}"
    end
  end

  describe "it can PASS" do
    test "against a mechanism whose peers listen and refuse each other" do
      results = network_results(ExSandbox.SeparatedPeersMechanism)

      assert matching(results.passed, @check) != [],
             """
             The peer-handle check did not PASS against a mechanism whose sandboxes
             listen on sockets the platform can open and refuse each other.

             Failures:    #{inspect(matching(results.failures, @check))}
             Unavailable: #{inspect(matching(results.unavailable, @check))}

             If it cannot pass here it cannot pass anywhere, and a check with no
             reachable pass is a permanent third outcome wearing a rule's clothes.
             """
    end

    test "and the pass is earned: the platform reaches the handle it refuses from inside" do
      # ⚠️ The half that makes the pass above mean something. Without it, the
      # fixture's pass is indistinguishable from `EditablePolicyMechanism`'s --
      # a refusal against a port nothing answers on.
      {:ok, provisioned} = ExSandbox.provision(ExSandbox.SeparatedPeersMechanism, sandbox(%{}))
      {:ok, started} = ExSandbox.start(ExSandbox.SeparatedPeersMechanism, provisioned)
      on_exit(fn -> ExSandbox.destroy(ExSandbox.SeparatedPeersMechanism, started) end)

      assert [{host, port}] = Network.peer_handles(started)

      assert {:ok, socket} = :gen_tcp.connect(to_charlist(host), port, [:binary, active: false])
      :gen_tcp.close(socket)
    end
  end

  describe "today it does NEITHER" do
    test "against the BEAM mechanism's published context, it reports the third outcome" do
      # ⚠️ The real mechanism's real context, built by the real function
      # (`context_for/1` is public for exactly this reason -- the launch path
      # refuses on a host that cannot confine, and this contract still has to be
      # pinned there).
      subject = ExSandbox.Conformance.Helpers.build_sandbox([])
      published = %{subject | context: ExSandbox.Mechanism.Beam.context_for(subject)}

      assert Network.peer_handles(published) == [],
             """
             The BEAM mechanism now declares a dialable peer handle. That is 029
             T033's work, not T034a's, and when it lands this test is the one that
             should change -- deliberately, with its reason rewritten.
             """

      error =
        assert_raise ExSandbox.Conformance.CapabilityUnavailable, fn ->
          Network.require_every_peer_handle_refused(
            ExSandbox.Mechanism.Beam,
            published,
            published
          )
        end

      message = Exception.message(error)

      assert message =~ "declares no dialable handle"
      assert message =~ "was not exercised"

      assert message =~ "structurally",
             "the third outcome must say WHY -- that FR-017 holds structurally " <>
               "while the address is unnameable -- or it reads as work not done"
    end

    test "a declared handle nothing answers on is the third outcome, not a pass" do
      # ⚠️ This is a verdict CHANGE, not a new gap. The existing peer check
      # passes against `EditablePolicyMechanism` because nothing listens at the
      # address it publishes -- `:refused` scored as the boundary holding. The
      # hazard 029 T034 warns will arrive with a dialable address is already in
      # the suite; this is the check that declines it.
      results = network_results(ExSandbox.EditablePolicyMechanism)

      assert matching(results.passed, @check) == [],
             """
             The peer-handle check PASSED against a mechanism that publishes an
             address with no listener behind it.

             A refusal at a dead port is produced by a mechanism with no boundary
             at all, so the pass is not attributable to `FR-017`.
             """

      assert matching(results.unavailable, @check) != [],
             """
             The peer-handle check neither passed nor reported the third outcome
             against a declared-but-dead handle.

             Failures: #{inspect(matching(results.failures, @check))}
             """
    end

    test "a mechanism declaring no handle at all is the third outcome, not a pass" do
      results = network_results(ExSandbox.PorousMechanism)

      assert matching(results.passed, @check) == [],
             """
             The peer-handle check PASSED against a mechanism that declares no
             handle and confines nothing. An unaddressable sandbox is
             indistinguishable from one with no boundary.
             """

      assert matching(results.unavailable, @check) != [],
             "a mechanism with nothing to attempt must report the third outcome"
    end
  end

  describe "what the mechanism declares (D27: this is the mechanism-neutral part)" do
    test "an explicitly declared list wins over `context.address`" do
      # A second mechanism -- a container runtime -- publishes a port AND a
      # runtime-resolvable name for the same sandbox, and `context.address` can
      # only carry one of them. The declaration is where the rest become
      # governed rather than invisible.
      declared = [{"10.0.0.2", 8080}, {"sandbox-b.internal", 443}]

      assert Network.peer_handles(sandbox(%{address: {"127.0.0.1", 1}, peer_handles: declared})) ==
               declared
    end

    test "a non-dialable declared handle is reported, not silently dropped" do
      target = sandbox(%{peer_handles: ["peer:sandbox-b"]})

      error =
        assert_raise ExSandbox.Conformance.CapabilityUnavailable, fn ->
          Network.require_every_peer_handle_refused(
            ExSandbox.EchoMechanism,
            sandbox(%{}),
            target
          )
        end

      assert Exception.message(error) =~ "not a `{host, port}`",
             """
             A handle the suite cannot dial was dropped without saying so. Silence
             there lets a mechanism declare an unattemptable set and collect the
             same result as one that declared nothing.
             """
    end

    test "a `{host, port}` in `context.address` needs no separate declaration" do
      assert Network.peer_handles(sandbox(%{address: {"127.0.0.1", 4001}})) ==
               [{"127.0.0.1", 4001}]
    end

    test "a string address is not a handle" do
      # `beam.ex` publishes `"peer:" <> id` deliberately. Coercing it into a
      # handle hands `:gen_tcp.connect/4` something unresolvable and scores the
      # failure as the boundary holding -- the false pass `BeamContextTest` pins
      # out, arriving through this function instead.
      assert Network.peer_handles(sandbox(%{address: "peer:abc"})) == []
    end
  end
end
