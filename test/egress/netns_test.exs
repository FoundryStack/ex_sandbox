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

  describe "the flags that close the host off (029-FR-015, 029-FR-018)" do
    # ⚠️ **What this describe block can and cannot prove.** Every assertion here
    # reads a list of strings. It shows the flags are *passed*; it does not show
    # they *close* anything. The claim that the netns can no longer reach the
    # host needs a live namespace and a probe that watches for bytes, and that
    # evidence is `T012`/`T014`'s. Do not read a green run here as `FR-015`
    # demonstrated -- that reading is exactly the "confirm a flag was passed"
    # failure `012-FR-012a` and `029-FR-016` exist to forbid.

    setup do
      %{command: Netns.pasta_command("/run/p.pid", ["bwrap", "erlexec"])}
    end

    test "the gateway address is not mapped to the host", %{command: command} do
      # Without this, pasta maps the namespace's default gateway to the host,
      # and the host answers on it.
      assert "--no-map-gw" in command
    end

    test "inbound and outbound TCP forwarding are both off", %{command: command} do
      # ⚠️ `-t auto` is `FR-018` directly: MEASURED under the default, a tenant
      # binding `0.0.0.0:8080` binds `0.0.0.0:8080` **on the host**.
      assert flag_value(command, "-t") == "none"
      assert flag_value(command, "-T") == "none"
    end

    test "inbound and outbound UDP forwarding are both off", %{command: command} do
      assert flag_value(command, "-u") == "none"
      assert flag_value(command, "-U") == "none"
    end

    test "--no-map-gw is not passed alone", %{command: command} do
      # ⚠️ **The whole reason this test is written as a set rather than as four
      # independent ones.** The netns reaches host `127.0.0.1` by two
      # independent paths; `--no-map-gw` closes one. A build passing only that
      # flag has a narrower hole, not no hole -- and it looks identical from
      # outside, because a `curl` to the gateway address gets nothing either
      # way. A regression that drops the port-forwarding flags while keeping
      # `--no-map-gw` is the shape this asserts against.
      assert "--no-map-gw" in command

      for flag <- ~w(-t -T -u -U) do
        assert flag_value(command, flag) == "none",
               "#{flag} must be none: --no-map-gw closes only one of the two paths to the host"
      end
    end

    test "the closing flags precede the argument separator", %{command: command} do
      # A flag emitted after `--` is not pasta's -- it is handed to the tenant,
      # which ignores it, and the door stays open while the command string reads
      # correct.
      before_separator = Enum.take_while(command, &(&1 != "--"))

      for flag <- ~w(--no-map-gw -t -T -u -U) do
        assert flag in before_separator, "#{flag} must reach pasta, not the tenant"
      end
    end

    test "the flags do not disturb the runas pair or the pidfile" do
      # Regression guard for the callers that locate `--runas` and `-P` by
      # scanning for the flag and taking the next element.
      command = Netns.pasta_command("/run/p.pid", ["bwrap", "erlexec"], "4242:4242")

      assert flag_value(command, "--runas") == "4242:4242"
      assert flag_value(command, "-P") == "/run/p.pid"
    end

    defp flag_value(command, flag) do
      command |> Enum.drop_while(&(&1 != flag)) |> Enum.at(1)
    end
  end
end
