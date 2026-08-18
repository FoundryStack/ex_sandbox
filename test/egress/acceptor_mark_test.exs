defmodule ExSandbox.Egress.AcceptorMarkTest do
  @moduledoc """
  The exemption that keeps the acceptor out of its own redirect (005 T060a3).

  ## Why this needs a test rather than being obvious

  The redirect matches **all** outbound TCP in the sandbox's namespace, which is
  deliberate — filtering by port would let an unlisted port bypass the
  enforcement point rather than be refused by it. But that also catches the
  acceptor's own upstream connection, so it relays to itself.

  ⚠️ Measured with a TCP upstream, with and without the exemption:

      without: conn#1 ORIGINAL_DST=93.184.216.34:443
               conn#2 ORIGINAL_DST=127.0.0.1:9100   <- its own upstream
               conn#3 ... conn#4 ...  LOOP DETECTED
      with:    conn#1 ORIGINAL_DST=93.184.216.34:443
               upstream said b'ORIGIN-REPLY'  -> TENANT: got b'DONE'

  The symptom of the loop is a **permitted** destination timing out, which reads
  as an unreachable network rather than as a broken enforcement point — and
  every denial check still passes, because denial is unaffected. It survived the
  first end-to-end run for exactly that reason: the deny case looked perfect.

  The mark is a value two languages must agree on, so the agreement is asserted
  rather than trusted.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Netns

  @helper Path.join([__DIR__, "..", "..", "priv", "egress", "nsacceptor.py"])

  test "the helper and the rule use the same mark" do
    # ⚠️ If these drift the acceptor's upstream stops being exempt and it
    # re-enters its own redirect. Nothing else in the system would notice: the
    # boundary still denies correctly, and only permitted traffic breaks.
    source = File.read!(Path.expand(@helper))

    assert source =~ ~r/^ACCEPTOR_MARK = #{Netns.acceptor_mark()}$/m,
           """
           priv/egress/nsacceptor.py does not set ACCEPTOR_MARK to \
           #{Netns.acceptor_mark()}, the value Netns installs the exemption for.

           A mismatch is silent: denial still works, and only permitted
           destinations break — by timing out, which reads as an unreachable
           network rather than a broken boundary.
           """
  end

  test "the helper sets the mark on its upstream socket" do
    source = File.read!(Path.expand(@helper))

    assert source =~ "setsockopt(socket.SOL_SOCKET, SO_MARK, ACCEPTOR_MARK)",
           "the helper defines a mark but never applies it, which exempts nothing"
  end

  describe "redirect_commands/2" do
    setup do
      %{commands: Netns.redirect_commands(4242, 18_080)}
    end

    test "installs an exemption for the acceptor's own traffic", %{commands: commands} do
      assert Enum.any?(commands, fn c ->
               "mark" in c and "return" in c and "#{Netns.acceptor_mark()}" in c
             end),
             "no exemption rule: the acceptor will relay to itself"
    end

    test "the exemption is installed before the redirect", %{commands: commands} do
      # ⚠️ Order is load-bearing. `nft` evaluates rules in order, so a `return`
      # placed after the redirect never runs and the exemption does nothing —
      # while still being present, which is the version that reads as correct.
      exempt = Enum.find_index(commands, &("return" in &1))
      redirect = Enum.find_index(commands, &("redirect" in &1))

      assert exempt < redirect,
             "the exemption must precede the redirect or nft never reaches it"
    end
  end
end
