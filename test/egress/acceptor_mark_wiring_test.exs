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

      raw = Relay.upstream_connect_opts() |> Keyword.fetch!(:raw)
      assert {1, 36, <<value::native-32>>} = raw

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

    test "the relay's connect options are the ones actually used" do
      # ⚠️ The seam that makes the first test mean something. If `splice/3`
      # built its options inline, this test could assert on a value no socket
      # ever received -- which is the shape of the defect it is checking for.
      opts = Relay.upstream_connect_opts()

      assert :binary in opts
      assert Keyword.get(opts, :active) == false
      assert Keyword.has_key?(opts, :raw)
    end
  end
end
