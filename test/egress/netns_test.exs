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

    test "installs a default route", %{commands: commands} do
      # ⚠️ The single most important assertion in this file. Omitting the route
      # made the end-to-end spike report `redirect did NOT fire`: the kernel
      # returned `enetunreach` before the nat hook ran, so a missing route
      # printed exactly like a refused redirect.
      #
      # Without it the sandbox is merely *isolated* — the state `--unshare-net`
      # already provided, which passes every denial check while enforcing no
      # policy at all. That is the regression this test exists to catch.
      assert Enum.any?(commands, &match?(["ip", "route", "add", "default" | _], &1)),
             "no default route: the sandbox would be isolated, not policed, and every denial check would still pass"
    end

    test "the route's gateway is the /30's gateway address", %{commands: commands} do
      route = Enum.find(commands, &match?(["ip", "route", "add", "default" | _], &1))
      assert "10.0.0.1" in route
    end

    test "redirects to the pool's port", %{commands: commands} do
      rule = Enum.find(commands, &match?(["nft", "add", "rule" | _], &1))
      assert ":18080" in rule
    end

    test "the redirect hooks output, not prerouting", %{commands: commands} do
      # Traffic originates inside the namespace, so it traverses `output`.
      # A `prerouting` rule installs cleanly, lists correctly, and matches
      # nothing — enforcement that looks present and is absent.
      chain = Enum.find(commands, &match?(["nft", "add", "chain" | _], &1))
      assert "output" in chain
      refute Enum.any?(commands, fn cmd -> "prerouting" in cmd end)
    end

    test "the redirect matches all outbound TCP rather than a port list", %{commands: commands} do
      # ⚠️ Filtering by port here would let an unlisted destination port bypass
      # the enforcement point entirely instead of being refused by it — a hole
      # that widens as an allowlist grows, and one no denial check aimed at a
      # listed port would ever find.
      rule = Enum.find(commands, &match?(["nft", "add", "rule" | _], &1))
      assert "tcp" in rule
      refute Enum.any?(rule, &String.contains?(&1, "dport"))
    end

    test "brings both loopback and the sandbox interface up", %{commands: commands} do
      assert ["ip", "link", "set", "lo", "up"] in commands
      assert Enum.any?(commands, &match?(["ip", "link", "set", "sb0", "up"], &1))
    end

    test "commands are argv lists, never interpolated shell strings" do
      # A string invites a sandbox-controlled value into a command line. Every
      # element must be a discrete argument.
      for command <- Netns.setup_commands({10, 0, 0, 0}, 18_080) do
        assert is_list(command)
        assert Enum.all?(command, &is_binary/1)
      end
    end
  end

  describe "pasta_command/2" do
    test "uses --config-net, the flag measured to need no host capability" do
      command = Netns.pasta_command("/proc/123/ns/net")
      assert "--config-net" in command
      assert "/proc/123/ns/net" in command
    end
  end
end
