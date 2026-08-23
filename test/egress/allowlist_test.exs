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

  describe "addresses a sandbox may not be pointed at are refused by class (029-FR-015)" do
    # ⚠️ Every row asserts the **class**, never merely that the entry was
    # refused. A test asserting `{:error, _}` would pass against a parser that
    # simply failed to *read* `169.254.169.254:80` -- which is the outcome
    # `FR-014` exists to rule out: the operator is told "invalid", re-checks
    # their spelling, finds it correct, and files a bug against the parser.
    refusals = [
      # loopback, in every spelling that reaches it
      {"127.0.0.1:8080", :loopback},
      {"127.255.255.254:80", :loopback},
      {"[::1]:443", :loopback},
      {"::1:443", :loopback},
      {"localhost:5432", :loopback},
      {"LocalHost:5432", :loopback},
      {"ip6-localhost:80", :loopback},
      # ⚠️ `:inet.parse_address/1` normalises all three of these to
      # `{127, 0, 0, 1}`, and so does glibc. A dotted-quad-shaped check would
      # let every one of them through as a "hostname".
      {"127.1:80", :loopback},
      {"2130706433:80", :loopback},
      {"0x7f000001:80", :loopback},
      # ⚠️ No `127` anywhere in the tuple: `::ffff:127.0.0.1` parses to
      # `{0, 0, 0, 0, 0, 65535, 32512, 1}`, so every IPv4 clause misses it.
      {"::ffff:127.0.0.1:80", :loopback},

      # the operator's own private network
      {"10.0.0.5:443", :rfc1918_private},
      {"172.16.0.1:443", :rfc1918_private},
      {"172.31.255.254:443", :rfc1918_private},
      {"192.168.1.1:443", :rfc1918_private},
      {"::ffff:10.0.0.1:443", :rfc1918_private},

      # link-local, and the one link-local address that earns its own name
      {"169.254.1.1:80", :link_local},
      {"fe80::1:80", :link_local},
      {"febf::1:80", :link_local},
      {"169.254.169.254:80", :cloud_metadata},
      {"169.254.169.254:*", :cloud_metadata},

      # IPv6 unique-local
      {"fc00::1:443", :unique_local},
      {"fd12:3456::1:443", :unique_local},
      {"[fdff::1]:443", :unique_local},

      # ⚠️ `0.0.0.0` is not "nowhere" -- Linux connect(2) to it lands on
      # `127.0.0.1`. A loopback spelling that contains no `127`.
      {"0.0.0.0:8080", :unspecified},
      {"0.1.2.3:80", :unspecified},
      {"[::]:8080", :unspecified}
    ]

    for {entry, class} <- refusals do
      test "#{entry} is refused as #{class}" do
        assert {:error, {:refused_entries, [{unquote(entry), unquote(class)}]}} =
                 Allowlist.parse([unquote(entry)])
      end
    end

    test "the refusal names every refused entry, not just the first" do
      # Same bargain as the unreadable case above: an operator fixing one entry
      # per deploy is an operator who stops reading the error.
      assert {:error, {:refused_entries, refused}} =
               Allowlist.parse([
                 "api.example.com:443",
                 "127.0.0.1:80",
                 "10.0.0.5:443",
                 "169.254.169.254:80"
               ])

      assert refused == [
               {"127.0.0.1:80", :loopback},
               {"10.0.0.5:443", :rfc1918_private},
               {"169.254.169.254:80", :cloud_metadata}
             ]
    end

    test "a refusal is a different error from an unreadable entry" do
      # ⚠️ The distinction the whole class exists to draw. Collapsing both into
      # `:invalid_entries` makes a deliberate policy decision indistinguishable
      # from a typo.
      assert {:error, {:invalid_entries, _}} = Allowlist.parse(["127.0.0.1"])
      assert {:error, {:refused_entries, _}} = Allowlist.parse(["127.0.0.1:80"])
    end

    test "an already-parsed tuple destination is classified too" do
      # ⚠️ The tuple form bypasses `parse_entry/1`'s string path entirely, so a
      # guard wired only into string parsing lets `{{127, 0, 0, 1}, 80}`
      # straight through -- and this is the form `Policy` actually compares
      # against.
      assert {:error, {:refused_entries, [{{{127, 0, 0, 1}, 80}, :loopback}]}} =
               Allowlist.parse([{{127, 0, 0, 1}, 80}])

      assert {:error, {:refused_entries, [{{"10.0.0.5", :any_port}, :rfc1918_private}]}} =
               Allowlist.parse([{"10.0.0.5", :any_port}])
    end

    test "unreadable entries are reported before refused ones" do
      # ⚠️ Forced, not preferred: an entry that did not parse has no address to
      # classify. Pinned so the ordering is a decision on the record rather than
      # an accident of the reduce.
      assert {:error, {:invalid_entries, ["no-port"]}} =
               Allowlist.parse(["no-port", "127.0.0.1:80"])
    end
  end

  describe "destinations outside the refused classes still parse (029-FR-015)" do
    # ⚠️ The guard's other failure mode, and the quieter one. A classifier with
    # an off-by-one range refuses somewhere legitimate, and the operator is told
    # their correct configuration names a private address.
    permitted = [
      "8.8.8.8:53",
      "93.184.216.34:443",
      # ⚠️ Just outside `172.16/12` on both sides. A naive `172.*` rule -- or
      # `b >= 16 and b <= 32` -- refuses one of these.
      "172.15.255.255:443",
      "172.32.0.1:443",
      # Just outside `169.254/16`.
      "169.253.0.1:80",
      "169.255.0.1:80",
      # Just outside `127/8` and `0/8`.
      "126.255.255.255:80",
      "128.0.0.1:80",
      "1.0.0.1:80",
      # Just outside `fe80::/10` and `fc00::/7`.
      "[2001:db8::1]:443",
      "[fec0::1]:443",
      "[fb00::1]:443",
      "[fe00::1]:443",
      # A hostname that merely *contains* a refused name is not that name.
      "localhost.example.com:443",
      "notlocalhost:443",
      "my-10.0.0.5-box.example:443"
    ]

    for entry <- permitted do
      test "#{entry} parses" do
        assert {:ok, [_destination]} = Allowlist.parse([unquote(entry)])
      end
    end

    test "a hostname that resolves inward is NOT caught here" do
      # ⚠️ Deliberate, and stated so it is not mistaken for a gap. This guard is
      # parse-time and static; it does not resolve. An entry naming a host whose
      # A record is `10.0.0.5` parses clean. Catching that is `FR-015`'s
      # "resolved answers" half, which is neither this task nor this module.
      assert {:ok, [{"internal.corp.example", 443}]} =
               Allowlist.parse(["internal.corp.example:443"])
    end
  end
end
