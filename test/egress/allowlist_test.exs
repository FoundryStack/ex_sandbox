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
      #
      # ⚠️ This line asserted `{:ok, [{"[::1]", 5432}]}` when it was written,
      # because T009a was built against a tree where **T008 did not exist** and
      # `::1` therefore had no built-in class to be caught by. That made it an
      # honest control at the time and a false statement the moment the two
      # landed together. It is kept, inverted, rather than deleted: the trap it
      # documents is real, and the assertion below is the evidence that
      # `normalise_host/1`'s bracket stripping is what springs it.
      assert {:error, {:refused_entries, [{"[::1]:5432", :loopback}]}} =
               Allowlist.parse(["[::1]:5432"])

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
