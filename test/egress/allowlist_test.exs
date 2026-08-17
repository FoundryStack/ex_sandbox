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
