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
        assert Enum.take(command, 5) ==
                 ["nsenter", "-t", "4242", "-n", "-U"],
               "a policy command that does not enter the namespace configures the host: " <>
                 Enum.join(command, " ")
      end
    end

    test "entry joins the userns that owns the netns, not the netns alone", %{
      commands: commands
    } do
      # ⚠️ Regression guard for a mechanism/probe divergence that ran the other
      # way from the one `probe_composability_test.exs` catches. There the probe
      # measured a sequence the mechanism never ran; here the mechanism ran a
      # sequence the probe never measured, so `network_restriction` reported
      # `ok` while every real `nsenter` would have been refused at runtime.
      #
      # Measured on `docker-isolation:latest`, unprivileged, both forms from
      # both vantage points in one run:
      #
      #   caller OUTSIDE the platform userns (the BEAM's position):
      #     nsenter -t <holder> -n ...                          -> REFUSED
      #     nsenter -t <holder> -n -U ... -> OK
      #
      # A bare `-n` here fails closed in the worst way: the redirect is never
      # installed, so the tenant runs unpoliced while every denial check passes.
      for command <- commands do
        assert "-U" in command,
               "bare `-n` is refused from outside the owning userns: " <>
                 Enum.join(command, " ")
      end
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
      # ⚠️ `pasta --config-net` does this, and an earlier version of this module
      # emitted `ip addr add`/`ip link set`/`ip route add` of its own. All three
      # failed with `Cannot find device "sb0"`: nothing had created the device,
      # because the thing that creates it had not run yet. They were not merely
      # redundant -- they ran *before* what makes them possible.
      # ⚠️ Checks the *program*, not membership. `"ip" in command` is true of
      # every rule here -- `nft add table ip nat` names the address family --
      # so a membership test fails against correct commands and would be
      # "fixed" by deleting it.
      # ⚠️ The program is *located*, not read from a fixed offset. This assertion
      # was `Enum.at(command, 4)` and broke when the userns-join flags
      # (`-U`) were added ahead of it -- a correct change
      # failing a correct test because the test encoded an argument position.
      # Dropping the `nsenter` flags finds the first real program either way.
      for command <- commands do
        program =
          command
          |> Enum.drop_while(&(&1 != "-U"))
          |> Enum.drop(1)
          |> List.first()

        assert program == "nft",
               "pasta configures the namespace; this must only police it: " <>
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
      # over UDP. Exactly one exemption, pinned to one address and one port.
      exemptions = Enum.filter(commands, &("accept" in &1))
      assert length(exemptions) == 1, "more than one UDP destination was permitted"

      [rule] = exemptions
      assert "10.0.0.53" in rule
      assert "daddr" in rule, "an exemption with no destination match permits UDP to anywhere"
      assert "53" in rule
    end

    test "an IPv6 resolver is matched with ip6 daddr, not ip daddr", %{} do
      # In an `inet` table `ip daddr` matches IPv4 packets only, so an IPv6
      # resolver named with it would install cleanly and match nothing --
      # a configured resolver that is unreachable.
      [rule] =
        Netns.redirect_commands(4242, 18_080, {{0xFD00, 0, 0, 0, 0, 0, 0, 1}, 53})
        |> Enum.filter(&("accept" in &1))

      assert "ip6" in rule
      assert "fd00::1" in rule
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
        assert Enum.take(command, 5) == ["nsenter", "-t", "4242", "-n", "-U"],
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

  describe "default_route?/1" do
    test "recognises the route pasta installs" do
      # Measured output from the isolation container. Without a default route
      # the kernel rejects an outbound connect with `enetunreach` *before* the
      # nat hook runs, so a missing route prints exactly like a refused
      # redirect -- the defect that cost the first spike a cycle.
      assert Netns.default_route?("default via 172.19.0.1 dev eth0\n172.19.0.0/16 dev eth0")
    end

    test "an isolated namespace is not mistaken for a policed one" do
      # ⚠️ The failure this guards. A namespace with addresses but no default
      # route reaches nothing, which passes every denial check while enforcing
      # no policy at all -- the `--unshare-net` shape.
      refute Netns.default_route?("172.19.0.0/16 dev eth0 proto kernel scope link")
      refute Netns.default_route?("")
    end
  end

  describe "pasta_command/2" do
    test "uses --config-net, the flag measured to need no host capability" do
      command = Netns.pasta_command("/run/p.pid", ["bwrap", "erlexec"])
      assert "--config-net" in command
    end

    test "runs as root, without which pasta cannot enter the namespace it made" do
      # ⚠️ Not a hardening choice. Measured: without `--runas 0`, pasta drops to
      # `nobody` and then fails with `Failed to join network namespace:
      # Permission denied` -- it cannot re-enter the namespace it just created.
      command = Netns.pasta_command("/run/p.pid", ["bwrap", "erlexec"])
      assert Enum.chunk_every(command, 2, 1, :discard) |> Enum.member?(["--runas", "0"])
    end

    test "does not pass --interface, which names a HOST device" do
      # ⚠️ An earlier version passed `--interface sb0` believing it named the
      # namespace-side device. `-i` selects the **host** interface to copy
      # addresses and routes *from*; the namespace-side name is `-I`. Measured:
      # `pasta --config-net --interface sb0 ...` fails with
      # `Invalid interface name sb0: No such device`.
      command = Netns.pasta_command("/run/p.pid", ["bwrap", "erlexec"])
      refute "--interface" in command
      refute "-i" in command
    end

    test "the tenant command follows the argument separator" do
      # Everything after `--` is the tenant. Without the separator, a tenant
      # flag that happens to match one of pasta's own would be consumed by
      # pasta instead of reaching the tenant.
      command = Netns.pasta_command("/run/p.pid", ["bwrap", "--die-with-parent", "erlexec"])
      [_pasta | rest] = command
      tenant = rest |> Enum.drop_while(&(&1 != "--")) |> Enum.drop(1)
      assert tenant == ["bwrap", "--die-with-parent", "erlexec"]
    end
  end
end
