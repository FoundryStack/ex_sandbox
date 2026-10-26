defmodule ExSandbox.Egress.NetnsTest do
  @moduledoc """
  The namespace setup commands (T060a3).

  ⚠️ These assert the *shape* of commands, which is weak evidence by design —
  a correct `nft` string is not a boundary. They exist to pin the specific
  elements whose absence produced a misleading result when measured, so a later
  edit that drops one fails here instead of in a container run whose verdict
  reads as something else. The boundary itself is established by the
  conformance network group attempting real connections.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Netns
  alias ExSandbox.Egress.Policy

  describe "addresses/1" do
    test "splits a /30 into gateway and sandbox as the spike measured" do
      assert %{gateway: "10.0.0.1", sandbox: "10.0.0.2"} = Netns.addresses({10, 0, 0, 0})
    end

    test "the sandbox address masks back to the key that owns its policy" do
      # ⚠️ This is the join between the namespace and the allowlist. The pool
      # sees the sandbox address via `peername`, masks it with `source_key/1`,
      # and looks the policy up under the result. If these two disagreed, every
      # sandbox would look like an unregistered source and be denied — failing
      # closed, and so invisible to every denial check.
      for base <- [{10, 0, 0, 0}, {10, 0, 0, 4}, {10, 4, 8, 252}] do
        %{sandbox: sandbox} = Netns.addresses(base)
        {:ok, parsed} = :inet.parse_address(String.to_charlist(sandbox))
        assert Policy.source_key(parsed) == base
      end
    end

    test "adjacent /30s produce distinct, non-overlapping addresses" do
      a = Netns.addresses({10, 0, 0, 0})
      b = Netns.addresses({10, 0, 0, 4})
      assert a.sandbox != b.sandbox
      assert a.gateway != b.gateway
      # A /30 holds four addresses; the next block must not reuse either host.
      refute a.sandbox == b.gateway
    end
  end

  describe "redirect_commands/2" do
    setup do
      %{commands: Netns.redirect_commands(4242, 18_080)}
    end

    test "every command enters the holder's namespace", %{commands: commands} do
      # ⚠️ The whole point of the module. An `nft` command that does NOT carry
      # `nsenter -t <pid> -n` runs in the **host** namespace and installs the
      # sandbox's redirect there -- it succeeds, warns about nothing, and
      # leaves the tenant unpoliced while the host acquires a stray NAT rule.
      for command <- commands do
        assert Enum.take(command, 4) ==
                 ["nsenter", "-t", "4242", "-n"],
               "a policy command that does not enter the namespace configures the host: " <>
                 Enum.join(command, " ")
      end
    end

    test "entry joins the netns alone, never bwrap's user namespace", %{
      commands: commands
    } do
      # bwrap's user namespace maps no root, so `-U` fails with
      # `setgid() failed: Invalid argument` and no redirect is installed.
      for command <- commands do
        refute "-U" in command,
               "joining a userns that maps only the sandbox uid is refused: " <>
                 Enum.join(command, " ")
      end
    end

    test "namespace loopback is exempt, ahead of the redirect", %{commands: commands} do
      steps = Enum.map(commands, &Enum.join(&1, " "))
      exempt = Enum.find_index(steps, &String.ends_with?(&1, "ip daddr 127.0.0.0/8 return"))
      redirect = Enum.find_index(steps, &String.contains?(&1, "meta l4proto tcp redirect"))

      assert exempt, "the tenant's own loopback servers are redirected and refused"
      assert exempt < redirect
    end

    test "redirects to the acceptor's port", %{commands: commands} do
      rule = rule(commands)
      assert ":18080" in rule
    end

    # ⚠️ These two pin the rule's *grammar*, which nothing checked until the
    # policed path was first executed on Linux and every rule was rejected:
    #
    #     nft add rule ip nat output tcp redirect to :44697
    #     Error: syntax error, unexpected redirect
    #
    # The port assertion above passed throughout -- `":18080" in rule` is true
    # of a rule `nft` will not accept. That is the gap worth naming: the
    # assertion checked the part that was right. A malformed rule is not
    # cosmetic, because a redirect that fails to install leaves the namespace
    # with a working default route and no interception, which is an *unpoliced*
    # sandbox whose denial checks all still pass for want of anything to deny.
    test "the redirect rule matches TCP in grammar nft accepts", %{commands: commands} do
      rule = rule(commands)

      assert rule
             |> Enum.chunk_every(3, 1, :discard)
             |> Enum.any?(&(&1 == ["meta", "l4proto", "tcp"])),
             """
             the redirect rule does not carry an `nft` protocol match.

             Built: #{Enum.join(rule, " ")}

             A bare `tcp` is not valid `nft` grammar -- measured in the isolation
             container, `nft` rejects it with `syntax error, unexpected redirect`
             and installs nothing. `meta l4proto tcp` is accepted and matches all
             TCP without a port predicate.
             """
    end

    test "the redirect rule carries no port predicate", %{commands: commands} do
      # The allowlist is enforced at the acceptor, which is the only component
      # that knows the destination. `tcp dport 1-65535` also parses, and
      # choosing it would move a filtering decision into `nft` where an unlisted
      # port would bypass the enforcement point rather than be refused by it.
      refute "dport" in rule(commands),
             "the redirect must match all TCP; a port predicate lets traffic bypass the acceptor entirely"
    end

    test "the redirect hooks output, not prerouting", %{commands: commands} do
      # Traffic originates inside the namespace, so it traverses `output`.
      # A `prerouting` rule installs cleanly, lists correctly, and matches
      # nothing -- enforcement that looks present and is absent.
      chain = Enum.find(commands, &("chain" in &1))
      assert "output" in chain
      refute Enum.any?(commands, fn cmd -> "prerouting" in cmd end)
    end

    test "no command configures an interface or a route", %{commands: commands} do
      # The route is `route_commands/2`'s, run after these.
      # ⚠️ Checks the *program*, not membership. `"ip" in command` is true of
      # every rule here -- `nft add table ip nat` names the address family --
      # so a membership test fails against correct commands and would be
      # "fixed" by deleting it.
      # ⚠️ The program is *located*, not read from a fixed offset, so a change
      # to the `nsenter` flags does not fail a correct test.
      for command <- commands do
        program =
          command
          |> Enum.drop_while(&(&1 != "-n"))
          |> Enum.drop(1)
          |> List.first()

        assert program == "nft",
               "the redirect must only police the namespace: " <>
                 Enum.join(command, " ")
      end
    end

    test "commands are argv lists, never interpolated shell strings", %{commands: commands} do
      # A string invites a sandbox-controlled value into a command line. Every
      # element must be a discrete argument.
      for command <- commands do
        assert is_list(command)
        assert Enum.all?(command, &is_binary/1)
      end
    end

    # ⚠️ Finds the REDIRECT rule specifically, not merely "a rule". Two `add
    # rule` commands are now emitted -- the acceptor's mark exemption comes
    # first -- and a plain `"rule" in &1` matched the exemption, so these
    # assertions began describing the wrong command while still reading as
    # correct.
    defp rule(commands), do: Enum.find(commands, &("redirect" in &1))
  end

  # ⚠️ **These assert a command shape, which the moduledoc above already calls
  # weak evidence — and for this rule the gap is wider than usual.** The hole
  # being closed was measured by *sending a datagram*: Phase 0 recorded that
  # "a UDP datagram sent from inside the sandbox to 8.8.8.8:53 was ANSWERED".
  # Nothing below sends anything. These exist so a later edit that drops the
  # drop, reorders it ahead of the exemption, or scopes it to IPv4 fails here
  # rather than in a container run whose verdict reads as something else. The
  # boundary itself is 029 T014's checkpoint: `nc -u` from inside the namespace
  # to the host loopback and to the gateway address, getting nothing.
  describe "redirect_commands/3 — the UDP rule (029 T012, FR-013/FR-015)" do
    setup do
      %{
        unconfigured: Netns.redirect_commands(4242, 18_080),
        resolved: Netns.redirect_commands(4242, 18_080, {"10.0.0.53", 53})
      }
    end

    test "with no resolver configured, ALL UDP is dropped", %{unconfigured: commands} do
      # ⚠️ The unconfigured case is the one that decides whether this is
      # default-deny. The resolver is Phase 2's first deliverable (029 T015), so
      # "no resolver yet" is the state of the world today, and permitting UDP
      # until it arrives would leave the measured hole open for a whole phase
      # while every rule below installed cleanly.
      assert drop_rule(commands),
             "no rule refuses UDP; a sandbox with no resolver configured must reach nothing over UDP"

      refute Enum.any?(commands, &("accept" in &1)),
             "an exemption was emitted for a resolver that was never supplied"
    end

    test "the drop is NOT in the nat chain", %{unconfigured: commands} do
      # ⚠️ `nat` chains translate; they are consulted by conntrack for the first
      # packet of a flow only. A filtering verdict placed there is evaluated on
      # a schedule unrelated to the traffic it refuses. The tempting edit is to
      # append `drop` beside the redirect because that is where the neighbouring
      # rule lives.
      for command <- commands, "drop" in command do
        refute "nat" in command,
               "a drop belongs in a filter chain, not the nat chain that holds the redirect: " <>
                 Enum.join(command, " ")
      end
    end

    test "the drop's chain is a filter chain hooked on output", %{unconfigured: commands} do
      chain = Enum.find(commands, &("filter" in &1 and "chain" in &1))
      assert chain, "no filter chain is created for the drop to live in"
      assert "output" in chain, "traffic originates inside the namespace, so it traverses output"

      spec = List.last(chain)
      assert spec =~ "type filter", "the drop's chain must be a filter chain: #{spec}"
      assert spec =~ "hook output", "the drop's chain must hook output: #{spec}"
    end

    test "the filter chain's POLICY is accept, so TCP is not dropped with the UDP", %{
      unconfigured: commands
    } do
      # ⚠️ The obvious reading of "default-deny" is a `policy drop` chain, and it
      # takes the TCP path down with it: TCP is policed by the redirect in the
      # nat chain, not by this one, so a drop policy here refuses every
      # permitted destination too. Default-deny for UDP is the terminal
      # `meta l4proto udp drop` rule, not the chain policy.
      chain = Enum.find(commands, &("filter" in &1 and "chain" in &1))
      spec = List.last(chain)

      assert spec =~ "policy accept",
             "a drop policy on this chain refuses the TCP the redirect exists to permit: #{spec}"
    end

    test "the drop matches UDP in grammar nft accepts, with no port predicate", %{
      unconfigured: commands
    } do
      # ⚠️ Same measured grammar trap as the TCP redirect above -- a bare `udp`
      # is rejected at install time with `syntax error`, and a rule that fails
      # to install leaves UDP walking out exactly as it does today.
      #
      # ⚠️ And no `dport`. This refuses UDP *as such*; a port predicate would let
      # a tenant pick an unlisted port and walk past it, which is the same
      # argument the redirect's own comment makes for matching all TCP.
      rule = drop_rule(commands)

      assert rule
             |> Enum.chunk_every(3, 1, :discard)
             |> Enum.any?(&(&1 == ["meta", "l4proto", "udp"])),
             """
             the drop rule does not carry an `nft` protocol match.

             Built: #{Enum.join(rule, " ")}
             """

      refute "dport" in rule,
             "the drop must refuse all UDP; a port predicate leaves the other 65534 open"
    end

    test "the drop covers IPv6 as well as IPv4", %{unconfigured: commands} do
      # ⚠️ The redirect's table is `ip` (IPv4 only), which is defensible for a
      # translation whose target is an IPv4 acceptor. A *refusal* scoped to IPv4
      # would leave the identical IPv6 datagram to walk out -- a control that
      # reads as the guarantee it is not, which is the exact shape FR-015 names.
      rule = drop_rule(commands)

      assert "inet" in rule,
             "an `ip`-family drop leaves IPv6 UDP unpoliced: " <> Enum.join(rule, " ")
    end

    test "the resolver exemption comes BEFORE the drop", %{resolved: commands} do
      # ⚠️ `nft` evaluates in order, so an exemption placed after a terminal drop
      # never runs -- the same ordering trap the acceptor's `meta mark ... return`
      # is documented for. The symptom is a resolver that is configured, whose
      # rules all installed, and which nothing can reach.
      accept_at = Enum.find_index(commands, &("accept" in &1))
      drop_at = Enum.find_index(commands, &("drop" in &1))

      assert accept_at, "a configured resolver produced no exemption"
      assert drop_at, "the exemption is present but nothing refuses the rest of UDP"

      assert accept_at < drop_at,
             "an exemption after a terminal drop never runs; the resolver would be unreachable"
    end

    test "the resolver is the SOLE permitted UDP destination", %{resolved: commands} do
      # The ruling (029 T011) is resolver-as-sole-destination, not an allowlist
      # over UDP. Both exemptions are pinned to one address and one port.
      #
      # ⚠️ **TWO rules, and this test asserted ONE until the round trip was
      # measured.** A DNS exchange has an answer, the answer is also `output`
      # traffic from this chain's point of view, and it carries the resolver as
      # its SOURCE -- so the query rule cannot match it. Measured inside
      # `unshare -n` against a stub nameserver on `127.0.0.1:53` under the
      # one-rule shape this test used to require: the query was sent, the
      # stub's reply was refused with EPERM, and the client timed out. The
      # sandbox had no DNS while every rule installed cleanly.
      #
      # "Sole destination" is still exactly what is enforced. The second rule
      # readmits datagrams whose source is that same one address and port, and
      # nothing else -- so no new destination becomes reachable.
      exemptions = Enum.filter(commands, &("accept" in &1))

      assert length(exemptions) == 2,
             "the exemption must cover the query and its answer, and no more"

      for rule <- exemptions do
        assert "10.0.0.53" in rule
        assert "53" in rule

        assert "daddr" in rule or "saddr" in rule,
               "an exemption with no address match permits UDP to anywhere"
      end

      assert Enum.count(exemptions, &("daddr" in &1)) == 1
      assert Enum.count(exemptions, &("saddr" in &1)) == 1
    end

    test "an IPv6 resolver is matched with ip6 daddr, not ip daddr", %{} do
      # In an `inet` table `ip daddr` matches IPv4 packets only, so an IPv6
      # resolver named with it would install cleanly and match nothing --
      # a configured resolver that is unreachable.
      rules =
        Netns.redirect_commands(4242, 18_080, {{0xFD00, 0, 0, 0, 0, 0, 0, 1}, 53})
        |> Enum.filter(&("accept" in &1))

      # Both halves of the round trip, or the answer is dropped -- see the
      # measurement recorded on the test above.
      assert length(rules) == 2

      for rule <- rules do
        assert "ip6" in rule
        assert "fd00::1" in rule
      end
    end

    test "a resolver address that is not an address is refused, not ignored", %{} do
      # ⚠️ Degrading to "no exemption" would produce a sandbox with no DNS whose
      # rules all installed cleanly -- indistinguishable from one that was never
      # given a resolver. Raising halts the launch, and a tenant that could not
      # be policed is terminated rather than left running.
      assert_raise ArgumentError, fn ->
        Netns.redirect_commands(4242, 18_080, {"resolver.internal", 53})
      end
    end

    test "the UDP rules enter the holder's namespace like every other", %{resolved: commands} do
      # Same reason as the redirect: an `nft` command without `nsenter -t <pid> -n`
      # configures the HOST, succeeds, and warns about nothing.
      for command <- commands do
        assert Enum.take(command, 4) == ["nsenter", "-t", "4242", "-n"],
               "a policy command that does not enter the namespace configures the host: " <>
                 Enum.join(command, " ")
      end
    end

    test "the TCP redirect is untouched by the UDP rules", %{resolved: commands} do
      # Regression guard: the UDP work must not disturb the path that already
      # works. A redirect that stopped matching would surface as a permitted
      # destination timing out, which reads as an unreachable network.
      redirect = Enum.find(commands, &("redirect" in &1))
      assert redirect
      assert "nat" in redirect
      assert ":18080" in redirect

      assert redirect
             |> Enum.chunk_every(3, 1, :discard)
             |> Enum.any?(&(&1 == ["meta", "l4proto", "tcp"]))
    end

    defp drop_rule(commands), do: Enum.find(commands, &("drop" in &1))
  end

  describe "route_commands/2 (D6 of let-sandboxes-outlive-a-deploy)" do
    setup do
      %{commands: Netns.route_commands(4242, "10.0.0.2")}
    end

    test "puts the sandbox address on lo, then routes default over lo from it", %{
      commands: commands
    } do
      assert [
               [
                 "nsenter",
                 "-t",
                 "4242",
                 "-n",
                 "ip",
                 "addr",
                 "add",
                 "10.0.0.2/32",
                 "dev",
                 "lo"
               ],
               [
                 "nsenter",
                 "-t",
                 "4242",
                 "-n",
                 "ip",
                 "route",
                 "add",
                 "default",
                 "dev",
                 "lo",
                 "src",
                 "10.0.0.2"
               ]
             ] == commands
    end
  end

  describe "the redirect with forwards" do
    setup do
      %{pairs: [{52_111, 4000}, {52_112, 4001}]}
    end

    test "exempts every forwarded ns port from the redirect, ahead of it", %{pairs: pairs} do
      steps = Enum.map(Netns.redirect_commands(4242, 18_080, nil, pairs), &Enum.join(&1, " "))
      redirect = Enum.find_index(steps, &String.contains?(&1, "meta l4proto tcp redirect"))

      for ns_port <- [4000, 4001] do
        exempt =
          Enum.find_index(
            steps,
            &String.ends_with?(&1, "ip daddr 127.0.0.1 tcp dport #{ns_port} return")
          )

        assert exempt, "no exemption for #{ns_port} in:\n" <> Enum.join(steps, "\n")
        assert exempt < redirect
      end
    end

    test "a legacy tuple still gets its one exemption" do
      assert Netns.redirect_commands(4242, 18_080, nil, {52_111, 4000}) ==
               Netns.redirect_commands(4242, 18_080, nil, [{52_111, 4000}])
    end
  end

  describe "forward_pairs/1" do
    test "reads every persisted shape as a list" do
      assert Netns.forward_pairs(nil) == []
      assert Netns.forward_pairs({52_111, 4000}) == [{52_111, 4000}]

      assert Netns.forward_pairs([{52_111, 4000}, {52_112, 4001}]) == [
               {52_111, 4000},
               {52_112, 4001}
             ]
    end
  end
end
