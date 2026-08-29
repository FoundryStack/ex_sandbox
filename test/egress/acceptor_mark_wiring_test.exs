defmodule ExSandbox.Egress.AcceptorMarkWiringTest do
  @moduledoc """
  The redirect's exemption and the relay's upstream socket name the same mark
  (005 T060a4e).

  ## Why this file exists

  `Netns.redirect_commands/2` installs `meta mark 42 return` ahead of the
  redirect, and its comment states that the acceptor sets that mark on its own
  upstream connections. **Nothing did.** `acceptor_mark/0` was referenced only
  by the rule that exempts it: the escape hatch was built, documented, and never
  used.

  The consequence is that the relay's connect to a permitted destination — made
  *inside* the sandbox's namespace, whose `nat output` hook redirects all
  outbound TCP to this very acceptor — is caught by the redirect it exists to
  serve, and the acceptor talks to itself. Measured in the namespace with a real
  origin behind a real acceptor (`docker/acceptor-mark-probe.py`):

      without SO_MARK: TENANT-GOT:RELAY-ERR:TimeoutError
      with    SO_MARK: TENANT-GOT:ORIGIN-REPLY

  ⚠️ **Why it survived so long.** The symptom is a *permitted* destination
  timing out, which reads as an unreachable network rather than a broken
  enforcement point — and every denial check still passes, because denial is
  unaffected. A suite that measures only denial cannot see it. `Netns` predicted
  this failure in prose and the code shipped without the mark anyway, which is
  why this is pinned by a test rather than by another comment.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Netns
  alias ExSandbox.Egress.NetnsSocket
  alias ExSandbox.Egress.Relay

  describe "the exemption and the socket agree" do
    test "the redirect exempts the mark the relay actually sets" do
      # ⚠️ Asserted as a RELATIONSHIP between the two, not against the literal
      # 42. A test comparing both to a constant passes when one is changed and
      # the other is not, which is the drift this exists to prevent.
      mark = Netns.acceptor_mark()

      exemption =
        Netns.redirect_commands(4242, 9999)
        |> Enum.find(&("return" in &1))

      assert exemption, "the redirect must carry a return rule for the acceptor"
      assert "#{mark}" in exemption

      value = Relay.upstream_mark()

      assert value == mark,
             """
             The relay's SO_MARK (#{value}) and the redirect's exemption
             (#{mark}) disagree, so the relay's own upstream connect is caught
             by the redirect and the acceptor talks to itself. The symptom is a
             PERMITTED destination timing out; every denial check still passes.
             """
    end

    test "the exemption is evaluated BEFORE the redirect" do
      # nft evaluates in order, so a `return` placed after the redirect never
      # runs -- the mark would be set correctly and matter not at all.
      commands = Netns.redirect_commands(4242, 9999)
      exempt_at = Enum.find_index(commands, &("return" in &1))
      redirect_at = Enum.find_index(commands, &("redirect" in &1))

      assert exempt_at < redirect_at,
             "a return rule after the redirect never runs"
    end

    test "a namespace whose mark cannot be set yields no upstream connection" do
      # ⚠️ This replaced an assertion that `splice/3`'s options carried
      # `raw: {1, 36, _}`. That option was the defect, not the guarantee:
      # `:inet.setopts/2` reports `:ok` when the kernel refuses `SO_MARK` for
      # want of `CAP_NET_ADMIN`, and the option then reads back as zero --
      # measured. The old test passed in exactly the configuration where the
      # mark was silently dropped and the acceptor talked to itself.
      #
      # The mark now comes from `NetnsSocket.socket/2`, which verifies it in C
      # and returns no descriptor if it did not stick. So the property worth
      # asserting is the one that option could never give: when a marked socket
      # is unobtainable, NOTHING is connected and the sandbox's socket is closed.
      # ⚠️ The destination is a port nothing listens on, deliberately. An earlier
      # version pointed at a live listener, and on a host where the NIF loads
      # `splice/3` genuinely connected -- then blocked in `pump/3` waiting for
      # either side to close, and the test timed out at 60s. The property here
      # is about what happens when NO upstream is established, so the upstream
      # must not be establishable.
      {:ok, listener} = :gen_tcp.listen(0, [:binary, {:active, false}, {:ip, {127, 0, 0, 1}}])
      {:ok, port} = :inet.port(listener)
      {:ok, sandbox_side} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, {:active, false}])
      {:ok, _accepted} = :gen_tcp.accept(listener, 1_000)

      # Port 1: reserved, and nothing in this suite binds it.
      result =
        Relay.splice(sandbox_side, {{127, 0, 0, 1}, 1},
          netns: "/proc/self/ns/net",
          connect_timeout_ms: 500
        )

      assert {:error, reason} = result

      unless NetnsSocket.available?() do
        # On a host with no NIF the refusal happens BEFORE any connect is
        # attempted, and naming it is the point: `:netns_sockets_unavailable`
        # says the mark could not be guaranteed, which is a different fact from
        # a destination that was tried and refused.
        assert reason == :netns_sockets_unavailable
      end

      # Closed on every path out, refusal included: a socket left open turns a
      # refusal into an indefinite hang, which the conformance probe scores as a
      # timeout rather than as a refusal.
      assert {:error, :closed} = :gen_tcp.recv(sandbox_side, 0, 200)

      :gen_tcp.close(listener)
    end
  end
end
