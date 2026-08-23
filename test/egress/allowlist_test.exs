defmodule ExSandbox.Egress.AllowlistTest do
  @moduledoc """
  ⚠️ **The adversarial cases come first, and they are the reason this module
  exists separately from `Policy`.**

  The implementation this file is written against is the *wrong* one: parsing a
  project's destinations with `Enum.filter/2` + `Enum.map/2`. That version
  passes every "well-formed input parses correctly" test, and silently discards
  entries an operator wrote. The first four tests below are the ones that
  distinguish the two implementations; everything after them is ordinary
  coverage that both would pass.
  """

  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Allowlist
  alias ExSandbox.Egress.Policy

  describe "a configuration that cannot be read is refused, not partially applied (T060a2)" do
    test "one unreadable entry refuses the whole list" do
      # ⚠️ The defect this exists to catch: a filtering parser returns
      # `{:ok, [{"api.example.com", 443}]}` here -- a working allowlist, one
      # rule short, with nothing anywhere reporting that a rule was dropped.
      assert {:error, {:invalid_entries, ["10.0.0.5"]}} =
               Allowlist.parse(["api.example.com:443", "10.0.0.5"])
    end

    test "the refusal names every unreadable entry, not just the first" do
      # An operator fixing configuration one error per deploy is an operator who
      # stops reading the error. All of them, or the message is a poor bargain.
      assert {:error, {:invalid_entries, entries}} =
               Allowlist.parse(["good.example:443", "no-port", "bad:port", "also.bad"])

      assert entries == ["no-port", "bad:port", "also.bad"]
    end

    test "a wholly unreadable configuration does not collapse into default-deny" do
      # ⚠️ This is the failure that hides best. A filtering parser yields `[]`,
      # `Policy` denies everything, and every *denial* check passes -- so the
      # suite is green, egress is broken, and the census reports the network
      # group as demonstrated. It fails closed, which is why nothing goes red.
      assert {:error, {:invalid_entries, _}} = Allowlist.parse(["nonsense", "also nonsense"])
    end

    test "a port typo does not silently become a valid port" do
      # `Integer.parse("443x")` is `{443, "x"}`. Without a check on the
      # remainder this entry becomes port 443 -- permission the operator never
      # granted, produced by a typo they will never see.
      assert {:error, {:invalid_entries, ["api.example.com:443x"]}} =
               Allowlist.parse(["api.example.com:443x"])
    end

    test "a bare host is refused rather than read as every port" do
      # There is no safe default here: the permissive reading grants more than
      # was written, and the restrictive one silently drops the entry. Refusing
      # makes the operator state which they meant.
      assert {:error, {:invalid_entries, ["api.example.com"]}} =
               Allowlist.parse(["api.example.com"])
    end

    test "a non-list configuration is refused rather than wrapped" do
      assert {:error, {:invalid_entries, ["api.example.com:443"]}} =
               Allowlist.parse("api.example.com:443")
    end

    test "port zero and out-of-range ports are refused" do
      assert {:error, {:invalid_entries, _}} = Allowlist.parse(["host:0"])
      assert {:error, {:invalid_entries, _}} = Allowlist.parse(["host:65536"])
      assert {:error, {:invalid_entries, _}} = Allowlist.parse(["host:-1"])
    end

    test "an empty host is refused" do
      assert {:error, {:invalid_entries, [":443"]}} = Allowlist.parse([":443"])
    end
  end

  describe "an empty allowlist is a configuration, not a parse failure (T060a2)" do
    test "an empty list parses to an empty allowlist" do
      # ⚠️ Distinct from the unreadable case above, and the distinction is the
      # whole reason `parse/1` returns a tuple. A project permitted to reach
      # nothing is coherent; a project whose configuration was not understood is
      # not -- and both would be `[]` if this returned a bare list.
      assert {:ok, []} = Allowlist.parse([])
    end

    test "a missing configuration parses to an empty allowlist" do
      assert {:ok, []} = Allowlist.parse(nil)
    end
  end

  describe "well-formed destinations parse to what Policy enforces (T060a2)" do
    test "host and port" do
      assert {:ok, [{"api.example.com", 443}]} = Allowlist.parse(["api.example.com:443"])
    end

    test "a star port means every port" do
      assert {:ok, [{"api.example.com", :any_port}]} = Allowlist.parse(["api.example.com:*"])
    end

    test "an IPv4 literal keeps its dotted form for Policy to normalise" do
      assert {:ok, [{"93.184.216.34", 443}]} = Allowlist.parse(["93.184.216.34:443"])
    end

    test "already-parsed tuples pass through" do
      assert {:ok, [{"a.example", 80}, {"b.example", :any_port}]} =
               Allowlist.parse([{"a.example", 80}, {"b.example", :any_port}])
    end

    test "an IPv6 literal is not cut in half by the port split" do
      # ⚠️ Splitting from the left takes `"[2001` as the host. That parses as
      # nothing, so the entry is refused -- but for the wrong reason, and an
      # operator debugging it is told their address is invalid when the parser
      # is what is wrong.
      assert {:ok, [{"[2001:db8::1]", 443}]} = Allowlist.parse(["[2001:db8::1]:443"])
    end

    test "order is preserved" do
      assert {:ok, [{"first.example", 1}, {"second.example", 2}, {"third.example", 3}]} =
               Allowlist.parse(["first.example:1", "second.example:2", "third.example:3"])
    end
  end

  describe "the host's aliases are refused, and the caller supplies them (029 T009a, FR-015)" do
    test "parse/1 with no alias list behaves exactly as it did before" do
      # ⚠️ The compatibility half of the task. Every existing caller
      # (`provision.ex` among them) calls `parse/1`, and threading a second
      # argument must not change a single one of their answers.
      assert {:ok, []} = Allowlist.parse(nil)
      assert {:ok, []} = Allowlist.parse([])
      assert {:ok, [{"api.example.com", 443}]} = Allowlist.parse(["api.example.com:443"])
      assert {:error, {:invalid_entries, ["no-port"]}} = Allowlist.parse(["no-port"])

      # And explicitly passing an empty alias list is the same thing.
      assert Allowlist.parse(["api.example.com:443"]) ==
               Allowlist.parse(["api.example.com:443"], [])
    end

    test "an alias supplied by the caller is refused with its own class" do
      # ⚠️ `:host_alias`, not `:invalid_entries`. A refusal that says only
      # "invalid" is indistinguishable from a typo, and FR-014 requires an
      # operator be able to act on it. The entry is echoed back **as written**
      # so they can find it in their configuration.
      assert {:error, {:refused_entries, [{"10.0.0.1:5432", :host_alias}]}} =
               Allowlist.parse(["10.0.0.1:5432"], ["10.0.0.1"])
    end

    test "the same address spelled differently is still refused" do
      # ⚠️ **This is the test that pins the insertion point.** The alias check
      # runs AFTER `:inet.parse_address/1`, so both sides are compared as
      # normalised addresses. Compared as written, every spelling below would
      # walk past a `"10.0.0.1"` alias -- and `:inet.parse_address/1` is
      # permissive enough that a spelling table would never be complete.
      for entry <- ["10.0.0.1:5432", "10.0.0.01:5432", "10.1:5432", "0xa000001:5432"] do
        assert {:error, {:refused_entries, [{^entry, :host_alias}]}} =
                 Allowlist.parse([entry], ["10.0.0.1"]),
               "#{entry} is the alias 10.0.0.1 under another spelling and was permitted"
      end
    end

    test "an alias may be given as a tuple, and matches the string form" do
      # A mechanism holding `:inet.ip_address()` tuples should not have to
      # render them to strings to hand them over -- normalisation is what makes
      # both forms the same value.
      assert {:error, {:refused_entries, [{"10.0.0.1:5432", :host_alias}]}} =
               Allowlist.parse(["10.0.0.1:5432"], [{10, 0, 0, 1}])
    end

    test "a bracketed IPv6 entry is matched, not read as a hostname" do
      # ⚠️ MEASURED here, and it is a trap for any classifier in this module:
      # `parse/1` KEEPS the brackets -- `parse(["[::1]:5432"])` yields
      # `{"[::1]", 5432}` -- while `:inet.parse_address(~c"[::1]")` is
      # `{:error, :einval}`. A classifier that hands the host straight to
      # `parse_address/1` therefore reads every bracketed IPv6 literal as a
      # *hostname* and lets it through.
      assert {:ok, [{"[::1]", 5432}]} = Allowlist.parse(["[::1]:5432"])

      assert {:error, {:refused_entries, [{"[fd00::1]:443", :host_alias}]}} =
               Allowlist.parse(["[fd00::1]:443"], ["fd00::1"])
    end

    test "an IPv4-mapped IPv6 entry is refused by its IPv4 alias" do
      # One alias covers both spellings; otherwise a caller would have to supply
      # each of its addresses twice and would eventually supply one once.
      assert {:error, {:refused_entries, [{"[::ffff:10.0.0.1]:443", :host_alias}]}} =
               Allowlist.parse(["[::ffff:10.0.0.1]:443"], ["10.0.0.1"])
    end

    test "a name alias is matched case-insensitively" do
      # The host has names as well as addresses -- `host.docker.internal` is the
      # one the spec names for a container mechanism -- and DNS is
      # case-insensitive, so the comparison must be too.
      assert {:error, {:refused_entries, [{"HOST.docker.INTERNAL:443", :host_alias}]}} =
               Allowlist.parse(["HOST.docker.INTERNAL:443"], ["host.docker.internal"])
    end

    test "the port is not part of the match" do
      # A destination either is the host or is not. A class that read the port
      # would refuse `:5432` and permit `:5433`.
      assert {:error, {:refused_entries, [{"10.0.0.1:*", :host_alias}]}} =
               Allowlist.parse(["10.0.0.1:*"], ["10.0.0.1"])

      assert {:error, {:refused_entries, [{{"10.0.0.1", 9999}, :host_alias}]}} =
               Allowlist.parse([{"10.0.0.1", 9999}], ["10.0.0.1"])
    end

    test "every refused entry is named, not just the first" do
      # Same argument as `:invalid_entries`: an operator who fixes the one entry
      # they were told about and re-runs should not discover a second.
      assert {:error, {:refused_entries, refused}} =
               Allowlist.parse(["10.0.0.1:5432", "api.example.com:443", "10.0.0.1:*"], [
                 "10.0.0.1"
               ])

      assert refused == [{"10.0.0.1:5432", :host_alias}, {"10.0.0.1:*", :host_alias}]
    end

    test "destinations that are not aliases are still permitted" do
      # ⚠️ The permit direction, which is where every defect in this feature has
      # hidden. An alias list that refused everything would pass every test
      # above and enforce nothing but denial.
      assert {:ok, [{"api.example.com", 443}, {"93.184.216.34", 443}]} =
               Allowlist.parse(["api.example.com:443", "93.184.216.34:443"], ["10.0.0.1"])
    end

    test "an unreadable entry is reported before a refused one" do
      # An entry that could not be read was never classified, so reporting
      # refusals alongside it would describe a subset the operator has not been
      # told about.
      assert {:error, {:invalid_entries, ["no-port"]}} =
               Allowlist.parse(["no-port", "10.0.0.1:5432"], ["10.0.0.1"])
    end

    test "the module still names no mechanism" do
      # ⚠️ The constraint the whole design serves (D27's transfer analysis).
      # This module must move to a container mechanism untouched, which it can
      # only do if it never learned what pasta, Docker, or a gateway is. The
      # alias list arrives as data; it is never queried for.
      source = File.read!("lib/ex_sandbox/egress/allowlist.ex")

      for mechanism <- ~w[Pasta Netns nsenter nftables] do
        refute source =~ mechanism,
               "allowlist.ex names #{mechanism}; the alias list must arrive as data"
      end
    end

    test "a non-list alias set is raised, not silently treated as none" do
      # Coercing it to "no aliases" would drop the FR-015 exclusion silently,
      # which is the one failure this task exists to prevent.
      assert_raise ArgumentError, fn ->
        Allowlist.parse(["10.0.0.1:5432"], "10.0.0.1")
      end
    end
  end

  describe "the parsed form is the form Policy actually enforces (T060a2)" do
    test "a parsed allowlist permits the destination it names" do
      # ⚠️ The join between this module and `Policy`. Both sides are written
      # independently and nothing but this test asserts they agree -- the same
      # seam that already produced one real defect, where `Policy` compared a
      # tuple host against a string entry and refused every permitted
      # destination while reading as correct enforcement.
      {:ok, allowed} = Allowlist.parse(["93.184.216.34:443"])

      assert Policy.permits?(allowed, {{93, 184, 216, 34}, 443})
      refute Policy.permits?(allowed, {{93, 184, 216, 34}, 80})
      refute Policy.permits?(allowed, {{1, 2, 3, 4}, 443})
    end

    test "a star-port entry permits every port on that host and no other host" do
      {:ok, allowed} = Allowlist.parse(["93.184.216.34:*"])

      assert Policy.permits?(allowed, {{93, 184, 216, 34}, 443})
      assert Policy.permits?(allowed, {{93, 184, 216, 34}, 8080})
      refute Policy.permits?(allowed, {{1, 2, 3, 4}, 443})
    end

    test "an empty parsed allowlist permits nothing" do
      {:ok, allowed} = Allowlist.parse([])

      refute Policy.permits?(allowed, {{93, 184, 216, 34}, 443})
    end
  end
end
