defmodule ExSandbox.Egress.ByteProbeTest do
  @moduledoc """
  ⚠️ **An instrument that has never been shown to disagree with itself is not an
  instrument.**

  The point of this file is not coverage. It is the two differing answers: this
  probe is run against a destination that answers and a destination that does
  not, and the results must not be the same. Every other test here exists to
  show that the *difference* comes from bytes rather than from anything else.

  The `"the obvious instrument cannot tell these apart"` test is the one to read
  first — it runs `:gen_tcp.connect/4` against both destinations, gets `:ok`
  from both, and is the whole argument for `029-FR-016` in six lines.
  """

  use ExUnit.Case, async: true

  alias ExSandbox.Egress.ByteProbe

  # Loopback, so a destination that is going to answer answers in microseconds.
  # ⚠️ Short only because every destination in this file is on this machine. A
  # probe aimed anywhere real must not shorten the default -- the timeout is the
  # instrument's resolution, and anything slower than it reads as silence.
  @timeout 400

  # --- fixtures ---------------------------------------------------------------

  defp answering_responder(transport) do
    {:ok, responder} = ByteProbe.responder(transport)
    on_exit(fn -> ByteProbe.close_responder(responder) end)
    responder
  end

  # ⚠️ The acceptor's actual refusal path: accept, then close without answering.
  # `FR-011a` requires a denied destination to be indistinguishable from an
  # unreachable one, so this is what a real refusal looks like from the outside
  # -- a completed handshake and nothing else.
  defp closing_black_hole do
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false, reuseaddr: true])

    {:ok, port} = :inet.port(listen)
    pid = spawn(fn -> accept_and_close(listen) end)
    :ok = :gen_tcp.controlling_process(listen, pid)
    on_exit(fn -> Process.exit(pid, :kill) end)

    %{address: {127, 0, 0, 1}, port: port}
  end

  defp accept_and_close(listen) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        :gen_tcp.close(socket)
        accept_and_close(listen)

      {:error, _reason} ->
        :ok
    end
  end

  # The other refusal shape: the packets are swallowed and nothing ever comes
  # back. A dropping firewall rule looks like this.
  defp silent_black_hole(:tcp) do
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false, reuseaddr: true])

    {:ok, port} = :inet.port(listen)
    pid = spawn(fn -> accept_and_hold(listen, []) end)
    :ok = :gen_tcp.controlling_process(listen, pid)
    on_exit(fn -> Process.exit(pid, :kill) end)

    %{address: {127, 0, 0, 1}, port: port}
  end

  defp silent_black_hole(:udp) do
    {:ok, socket} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}, active: false])
    {:ok, port} = :inet.port(socket)
    # Bound, and deliberately never reads or replies.
    pid = spawn(fn -> Process.sleep(:infinity) end)
    :ok = :gen_udp.controlling_process(socket, pid)
    on_exit(fn -> Process.exit(pid, :kill) end)

    %{address: {127, 0, 0, 1}, port: port}
  end

  defp accept_and_hold(listen, held) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} -> accept_and_hold(listen, [socket | held])
      {:error, _reason} -> :ok
    end
  end

  defp subject_leg(transport, %{address: address, port: port}) do
    fn -> ByteProbe.leg(transport, address, port, timeout: @timeout) end
  end

  # --- the disagreement -------------------------------------------------------

  describe "the instrument disagrees with itself (029-FR-016)" do
    test "TCP: a destination that answers and one that does not give different verdicts" do
      responder = answering_responder(:tcp)
      refused = closing_black_hole()
      reference = ByteProbe.reference_leg(responder, timeout: @timeout)

      permitted_verdict = ByteProbe.attempt(reference, subject_leg(:tcp, responder))
      refused_verdict = ByteProbe.attempt(reference, subject_leg(:tcp, refused))

      assert {:reached, banner} = permitted_verdict
      assert banner == responder.banner
      assert {:refused, :silent} = refused_verdict

      # ⚠️ Stated as an assertion rather than left implicit. If a later change
      # collapses these two, every FR-016 probe built on this module starts
      # reporting a boundary it has not observed, and nothing else goes red.
      refute permitted_verdict == refused_verdict
    end

    test "UDP: the same disagreement, where bytes are the only signal there is" do
      responder = answering_responder(:udp)
      refused = silent_black_hole(:udp)
      reference = ByteProbe.reference_leg(responder, timeout: @timeout)

      permitted_verdict = ByteProbe.attempt(reference, subject_leg(:udp, responder))
      refused_verdict = ByteProbe.attempt(reference, subject_leg(:udp, refused))

      assert {:reached, banner} = permitted_verdict
      assert banner == responder.banner
      assert {:refused, :silent} = refused_verdict
      refute permitted_verdict == refused_verdict
    end

    test "a destination that swallows packets reads the same as one that closes" do
      # Both are refusals, and the instrument is not asked to tell them apart --
      # `FR-011f` forbids ranking one above the other.
      responder = answering_responder(:tcp)
      reference = ByteProbe.reference_leg(responder, timeout: @timeout)

      assert {:refused, :silent} =
               ByteProbe.attempt(reference, subject_leg(:tcp, closing_black_hole()))

      assert {:refused, :silent} =
               ByteProbe.attempt(reference, subject_leg(:tcp, silent_black_hole(:tcp)))
    end

    test "a port with nothing listening is a refusal, carrying its reason" do
      responder = answering_responder(:tcp)
      reference = ByteProbe.reference_leg(responder, timeout: @timeout)

      # An ephemeral port that was bound and released -- nothing is there now.
      {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
      {:ok, port} = :inet.port(socket)
      :ok = :gen_tcp.close(socket)

      assert {:refused, {:no_socket, _reason}} =
               ByteProbe.attempt(
                 reference,
                 subject_leg(:tcp, %{address: {127, 0, 0, 1}, port: port})
               )
    end
  end

  describe "the obvious instrument cannot tell these apart (029-FR-016)" do
    test "connect/4 returns :ok for the destination that answers AND the one that refuses" do
      # ⚠️ **The entire argument for this module, executable.** These are the
      # same two destinations the first test above distinguishes. A probe asking
      # "did connect succeed?" gets an identical `:ok` from both and reports a
      # boundary that is not there. MEASURED, and this test is the measurement.
      responder = answering_responder(:tcp)
      refused = closing_black_hole()

      assert {:ok, permitted_socket} =
               :gen_tcp.connect(responder.address, responder.port, [:binary], @timeout)

      assert {:ok, refused_socket} =
               :gen_tcp.connect(refused.address, refused.port, [:binary], @timeout)

      :gen_tcp.close(permitted_socket)
      :gen_tcp.close(refused_socket)
    end
  end

  # --- silence is not a refusal ----------------------------------------------

  describe "silence is not a refusal without a reference leg (029-FR-016)" do
    test "a silent subject under a silent reference leg is inconclusive, not refused" do
      # ⚠️ The vacuous pass this module exists to prevent, reproduced. The
      # previous phase's UDP check probed two legs that were both under no
      # obligation to answer, got silence from both, and reported a held
      # boundary. Here both legs are black holes -- and the verdict is
      # `:inconclusive`, which is a *result*, not a failure.
      dead_reference = fn ->
        ByteProbe.leg(:tcp, {127, 0, 0, 1}, port_of(silent_black_hole(:tcp)), timeout: @timeout)
      end

      assert {:inconclusive, {:reference_leg, :before, :silent}} =
               ByteProbe.attempt(dead_reference, subject_leg(:tcp, closing_black_hole()))
    end

    test "a reference leg that dies during the subject leg is inconclusive" do
      # ⚠️ Why the reference leg is bracketed rather than run once up front. The
      # responder answers the first reference leg, then is torn down; the
      # subject's silence is no longer attributable to policy, and saying
      # `:refused` here would be a boundary claimed from a dead instrument.
      {:ok, responder} = ByteProbe.responder(:tcp)
      refused = closing_black_hole()

      reference = ByteProbe.reference_leg(responder, timeout: @timeout)

      subject = fn ->
        ByteProbe.close_responder(responder)
        ByteProbe.leg(:tcp, refused.address, refused.port, timeout: @timeout)
      end

      assert {:inconclusive, {:reference_leg, :after, _answer}} =
               ByteProbe.attempt(reference, subject)
    end

    test "an inconclusive verdict is reported even when the subject DID cross" do
      # Symmetry check: the gate is not a one-sided filter that only suppresses
      # refusals. If the instrument cannot see, it cannot see either answer.
      responder = answering_responder(:tcp)

      dead_reference = fn ->
        ByteProbe.leg(:tcp, {127, 0, 0, 1}, port_of(silent_black_hole(:tcp)), timeout: @timeout)
      end

      assert {:inconclusive, {:reference_leg, :before, :silent}} =
               ByteProbe.attempt(dead_reference, subject_leg(:tcp, responder))
    end
  end

  defp port_of(%{port: port}), do: port

  # --- the interpretation table, without a network ---------------------------

  describe "verdict/2 is pure and refuses to interpret an unattributable leg" do
    test "a crossing reference leg licenses both readings" do
      assert {:reached, "hi"} = ByteProbe.verdict({:crossed, "ref"}, {:crossed, "hi"})
      assert {:refused, :silent} = ByteProbe.verdict({:crossed, "ref"}, :silent)

      assert {:refused, {:no_socket, :econnrefused}} =
               ByteProbe.verdict({:crossed, "ref"}, {:no_socket, :econnrefused})
    end

    test "no reference leg means no refusal, whatever the subject saw" do
      # ⚠️ There is deliberately no clause from a non-crossing reference leg to
      # `{:refused, _}`. The gate is pattern matching, not discipline -- it
      # cannot be forgotten at a call site.
      for subject <- [:silent, {:no_socket, :econnrefused}, {:crossed, "bytes"}] do
        assert {:inconclusive, {:reference_leg, :before, :silent}} =
                 ByteProbe.verdict(:silent, subject)

        assert {:inconclusive, {:reference_leg, :before, {:no_socket, :enetunreach}}} =
                 ByteProbe.verdict({:no_socket, :enetunreach}, subject)
      end
    end
  end

  # --- leg/4 reports observations, not conclusions ---------------------------

  describe "leg/4 does not interpret what it saw" do
    test "it returns :silent rather than a refusal" do
      # ⚠️ A caller reading this `:silent` as a refusal has rebuilt the bug.
      # The type is what stops them: `:silent` is an `answer`, and only
      # `verdict/2` turns answers into claims.
      refused = closing_black_hole()
      assert :silent = ByteProbe.leg(:tcp, refused.address, refused.port, timeout: @timeout)
    end

    test "it speaks first, so a destination that waits for the client still answers" do
      # ⚠️ `ByteProbe.responder/2` reads before it replies, exactly like the
      # real services this probe is aimed at. A read-only probe gets `:silent`
      # here and calls a reachable destination refused.
      responder = answering_responder(:tcp)

      assert {:crossed, banner} =
               ByteProbe.leg(:tcp, responder.address, responder.port, timeout: @timeout)

      assert banner == responder.banner
    end
  end
end
