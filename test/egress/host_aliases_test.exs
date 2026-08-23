defmodule ExSandbox.Egress.HostAliasesTest do
  @moduledoc """
  The supply side of `029-FR-015`'s alias exclusion (029 T014, D103).

  ⚠️ **`:host_alias` was a refusal class that could never fire in production
  until something passed a list.** `parse/2` has taken `host_aliases` since
  T009a and no caller supplied one, which is the same defect as a check that
  cannot fail, in the error vocabulary instead of the suite. What is asserted
  here is that a list is produced, that it is produced by *looking*, and that
  the produced list actually reaches a refusal.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Allowlist
  alias ExSandbox.Egress.HostAliases

  describe "the list is discovered from the running host" do
    test "it contains this machine's own loopback, because that is this machine" do
      # Every host has one, on every platform this runs on, so this is a real
      # assertion rather than one that passes by being empty.
      aliases = HostAliases.detect()
      assert {127, 0, 0, 1} in aliases
    end

    test "it holds addresses, not strings" do
      assert Enum.all?(HostAliases.detect(), &is_tuple/1)
    end
  end

  describe "gateway parsing, exercised where there is no gateway" do
    test "a default route yields its via address" do
      # ⚠️ Parsed from text on purpose. On a developer machine there is no
      # `ip(8)` and no default route to read, so a parser exercised only where
      # the command runs is one whose failure mode is a silently empty guard —
      # and an empty guard is indistinguishable from a working one.
      assert HostAliases.parse_default_via(
               "default via 172.19.0.1 dev eth0 proto kernel\n" <>
                 "172.19.0.0/16 dev eth0 proto kernel scope link src 172.19.0.4\n"
             ) == [{172, 19, 0, 1}]
    end

    test "more than one default route yields all of them" do
      assert HostAliases.parse_default_via(
               "default via 10.0.0.1 dev eth0\ndefault via 10.1.0.1 dev eth1\n"
             ) == [{10, 0, 0, 1}, {10, 1, 0, 1}]
    end

    test "output with no default route yields nothing" do
      assert HostAliases.parse_default_via("192.168.1.0/24 dev en0 scope link\n") == []
    end

    test "an unreadable via address is dropped rather than kept as a string" do
      # A string in the alias set would compare against nothing and silently
      # widen the guard back out.
      assert HostAliases.parse_default_via("default via not-an-address dev eth0\n") == []
    end
  end

  describe "the produced list reaches a refusal" do
    test "an entry naming a discovered alias is refused as :host_alias" do
      # ⚠️ The end-to-end shape, with the alias supplied the way provisioning
      # supplies it. `127.0.0.1` would be refused anyway as `:loopback`, so a
      # public-looking address is used to make the class unambiguous.
      assert {:error, {:refused_entries, [{"198.51.100.7:443", :host_alias}]}} =
               Allowlist.parse(["198.51.100.7:443"], [{198, 51, 100, 7}])
    end

    test "and the same entry parses cleanly when it is not an alias" do
      # ⚠️ The permitted-path control. A parser that refused everything would
      # pass the assertion above.
      assert {:ok, [{"198.51.100.7", 443}]} = Allowlist.parse(["198.51.100.7:443"], [])
    end

    test ":host_alias wins over :rfc1918_private, so the list is not invisible" do
      # Nearly every address a host answers to is also private. Without this
      # ordering the whole discovered list would never show up in what an
      # operator reads.
      assert {:error, {:refused_entries, [{"10.0.0.1:443", :host_alias}]}} =
               Allowlist.parse(["10.0.0.1:443"], [{10, 0, 0, 1}])

      assert {:error, {:refused_entries, [{"10.0.0.2:443", :rfc1918_private}]}} =
               Allowlist.parse(["10.0.0.2:443"], [{10, 0, 0, 1}])
    end

    test "classify/2 names the same class the parser would" do
      # The resolver runs answers through `classify/2`; a second classifier
      # would drift, and the drift shows up as one surface refusing what the
      # other permits.
      assert Allowlist.classify({127, 0, 0, 1}) == :loopback
      assert Allowlist.classify({169, 254, 169, 254}) == :cloud_metadata
      assert Allowlist.classify({93, 184, 216, 34}) == nil
      assert Allowlist.classify({198, 51, 100, 7}, [{198, 51, 100, 7}]) == :host_alias
    end
  end
end
