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

  describe "setup_commands/3" do
    setup do
      %{commands: Netns.setup_commands({10, 0, 0, 0}, 18_080)}
    end

    test "the namespace is created before anything runs inside it", %{commands: commands} do
      # Ordering is not expressible as a set, and it is the whole content of
      # this list. A step that runs in a namespace that does not exist yet
      # fails with "Cannot open network namespace".
      add_at = Enum.find_index(commands, &match?(["ip", "netns", "add" | _], &1))
      first_exec = Enum.find_index(commands, &match?(["ip", "netns", "exec" | _], &1))

      assert add_at != nil, "the namespace is never created"
      assert add_at < first_exec
    end

    test "the veth pair exists before either end is configured", %{commands: commands} do
      pair_at = Enum.find_index(commands, &match?(["ip", "link", "add" | _], &1))
      move_at = Enum.find_index(commands, fn step -> "netns" in step and "link" in step end)

      assert pair_at != nil, "no veth pair: the namespace would have no interface at all"
      assert pair_at < move_at

      # ⚠️ The defect the pasta design shipped: three steps configured `dev sb0`
      # before anything created it, and all three failed with
      # `Cannot find device "sb0"`.
      configure_at =
        Enum.find_index(commands, &match?(["ip", "addr", "add" | _], &1))

      assert pair_at < configure_at
    end

    test "installs a default route", %{commands: commands} do
      # ⚠️ The single most important assertion in this file. Omitting the route
      # made the end-to-end spike report `redirect did NOT fire`: the kernel
      # returned `enetunreach` before the nat hook ran, so a missing route
      # printed exactly like a refused redirect.
      #
      # Without it the sandbox is merely *isolated* -- the state `--unshare-net`
      # already provided, which passes every denial check while enforcing no
      # policy at all.
      assert Enum.any?(commands, fn step ->
               "route" in step and "default" in step
             end),
             "no default route: the sandbox would be isolated, not policed, and every denial check would still pass"
    end

    test "the route's gateway is the /30's gateway address", %{commands: commands} do
      route = Enum.find(commands, fn step -> "route" in step and "default" in step end)
      assert "10.0.0.1" in route
    end

    test "the sandbox end carries an address that masks to its policy key", %{commands: commands} do
      # The join between the namespace and the allowlist: the acceptor sees this
      # address, masks it with `source_key/1`, and looks the policy up under the
      # result. Measured working -- `peer=('10.77.0.2', 32856)`.
      addr_step =
        Enum.find(commands, fn step ->
          "addr" in step and Enum.any?(step, &String.starts_with?(&1, "10.0.0.2/"))
        end)

      assert addr_step, "the sandbox end has no address, so it cannot be attributed"
    end

    test "the redirect is installed as part of setup", %{commands: commands} do
      assert Enum.any?(commands, fn step -> "rule" in step end),
             "no redirect: the namespace would have a route out and no interception"
    end

    test "commands are argv lists, never interpolated shell strings", %{commands: commands} do
      # A string invites a sandbox-controlled value into a command line. Every
      # element must be a discrete argument.
      for command <- commands do
        assert is_list(command)
        assert Enum.all?(command, &is_binary/1)
      end
    end
  end

  describe "redirect_commands/2" do
    setup do
      %{commands: Netns.redirect_commands("sb-10-0-0-0", 18_080)}
    end

    test "every command runs inside the named namespace", %{commands: commands} do
      # ⚠️ A command that omits the namespace configures the **host**. On a
      # developer machine that fails; on the isolation host it succeeds, and the
      # host acquires a NAT rule redirecting its own outbound TCP while the
      # sandbox is left entirely unpoliced.
      for command <- commands do
        assert Enum.take(command, 4) == ["ip", "netns", "exec", "sb-10-0-0-0"],
               "a policy command that does not enter the namespace configures the host: " <>
                 Enum.join(command, " ")
      end
    end

    test "redirects to the acceptor's port", %{commands: commands} do
      assert ":18080" in rule(commands)
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
      r = rule(commands)

      assert r
             |> Enum.chunk_every(3, 1, :discard)
             |> Enum.any?(&(&1 == ["meta", "l4proto", "tcp"])),
             """
             the redirect rule does not carry an `nft` protocol match.

             Built: #{Enum.join(r, " ")}

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

    defp rule(commands), do: Enum.find(commands, &("rule" in &1))
  end

  describe "interface_names/1" do
    test "names fit the kernel's 15-character limit" do
      # ⚠️ Measured constraint, not a style rule. `sbh-10-255-255-252` is 18
      # characters and the kernel rejects it -- so a sandbox at the top of the
      # range would fail to launch while every one below it worked.
      for key <- [{10, 0, 0, 0}, {10, 255, 255, 252}, {10, 4, 8, 128}] do
        {host, sandbox} = Netns.interface_names(key)
        assert String.length(host) <= 15, "host interface name too long: #{host}"
        assert String.length(sandbox) <= 15, "sandbox interface name too long: #{sandbox}"
      end
    end

    test "adjacent /30s get distinct host-side names" do
      # ⚠️ The host end lives in the **host** namespace alongside every other
      # sandbox's. A name that collided would fail the second sandbox with
      # `RTNETLINK answers: File exists` -- after the first worked.
      {a, _} = Netns.interface_names({10, 0, 0, 0})
      {b, _} = Netns.interface_names({10, 0, 0, 4})
      assert a != b
    end
  end

  describe "teardown_commands/2" do
    test "removes the namespace and the host-side veth" do
      commands = Netns.teardown_commands({10, 0, 0, 0})

      assert Enum.any?(commands, &match?(["ip", "netns", "delete" | _], &1))

      # ⚠️ The host end survives a namespace delete when the pair was created
      # but the move failed, and it lives in the host's namespace -- so leaking
      # it exhausts host interface names rather than the sandbox's.
      {host_if, _} = Netns.interface_names({10, 0, 0, 0})
      assert Enum.any?(commands, fn step -> "delete" in step and host_if in step end)
    end
  end

  describe "in_namespace/3" do
    test "the tenant launches inside the namespace that was configured" do
      command = Netns.in_namespace({10, 0, 0, 0}, ["bwrap", "erlexec"])
      assert ["ip", "netns", "exec", "sb-10-0-0-0", "bwrap", "erlexec"] == command
    end
  end
end
