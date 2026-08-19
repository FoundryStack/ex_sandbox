defmodule ExSandbox.Egress.PolicyTest do
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Policy

  describe "source_key/1 reduces an address to its /30" do
    test "every host address in a /30 maps to the same key" do
      # ⚠️ The point of masking. A sandbox's connections arrive from a host
      # address inside its /30, not from the network address, so keying on the
      # raw source would look up a policy that was never registered -- and
      # default-deny would then refuse a permitted destination. Worse, the
      # failure would look like correct enforcement.
      for last <- 0..3 do
        assert Policy.source_key({10, 0, 0, last}) == {10, 0, 0, 0}
      end

      for last <- 4..7 do
        assert Policy.source_key({10, 0, 0, last}) == {10, 0, 0, 4}
      end
    end

    test "adjacent /30s never collide" do
      # If they did, one sandbox would inherit its neighbour's allowlist -- the
      # cross-tenant leak this keying exists to prevent.
      keys = for n <- 0..63, do: Policy.source_key({10, 0, 0, n})
      assert length(Enum.uniq(keys)) == 16
    end
  end

  describe "permits?/2 is an allowlist over default-deny (FR-011a)" do
    test "an unknown source is refused, not admitted" do
      # The ordering is the entire guarantee: a lookup miss must never be the
      # path by which something becomes reachable.
      refute Policy.permits?([], {"93.184.216.34", 443})
    end

    test "the guard clause and the fallback clause are both default-deny" do
      # ⚠️ Written after sabotage measured what the tests above actually cover.
      # Stubbing the `_allowed, _destination` fallback to `true` turned only
      # ONE test red -- the `nil` case. "an unknown source is refused" kept
      # passing, because `[]` satisfies `is_list` and never reaches the
      # fallback at all.
      #
      # So the test named for default-deny was not exercising the clause the
      # name implies, and a reader auditing this file for that guarantee would
      # have been reassured by the wrong test. `permits?/2` has two independent
      # refusal paths and each needs its own case.
      refute Policy.permits?([], {"93.184.216.34", 443}), "empty allowlist (is_list clause)"
      refute Policy.permits?(nil, {"93.184.216.34", 443}), "non-list policy (fallback clause)"
      refute Policy.permits?(%{}, {"93.184.216.34", 443}), "map policy (fallback clause)"
      refute Policy.permits?(:deny_all, {"93.184.216.34", 443}), "atom policy (fallback clause)"
    end

    test "a permitted host:port is admitted" do
      assert Policy.permits?([{"93.184.216.34", 443}], {"93.184.216.34", 443})
    end

    test "a permitted host on a different port is refused" do
      refute Policy.permits?([{"93.184.216.34", 443}], {"93.184.216.34", 80})
    end

    test ":any_port admits every port on that host, and only that host" do
      allowed = [{"93.184.216.34", :any_port}]
      assert Policy.permits?(allowed, {"93.184.216.34", 443})
      assert Policy.permits?(allowed, {"93.184.216.34", 8080})
      refute Policy.permits?(allowed, {"93.184.216.35", 443})
    end

    test "a non-list policy refuses rather than raising" do
      # ⚠️ A crash here would be read as a failed connection, which looks
      # identical to a refusal from the outside -- so it would pass a denial
      # check while meaning nothing. Refusing explicitly keeps the two distinct.
      refute Policy.permits?(nil, {"93.184.216.34", 443})
    end
  end

  describe "an allowlist and a decoded destination must be comparable (T060a3)" do
    test "a destination decoded as an IP tuple matches an allowlist written as a string" do
      # ⚠️ This is the seam between two independently-written modules.
      # `OriginalDst.decode/1` yields `{93, 184, 216, 34}` because that is what
      # a `sockaddr_in` contains, while an allowlist resolved from project
      # settings is naturally written `"93.184.216.34"`. `permits?/2` matches
      # the host by *equality*, so without normalisation these never match.
      #
      # It fails closed, which is why nothing would breach -- and why it would
      # be hard to find. Every permitted destination would be silently refused
      # while the code read as working enforcement, and the "permitted
      # destination is reachable" conformance check would fail with no
      # indication that the cause was a type mismatch.
      assert Policy.permits?([{"93.184.216.34", 443}], {{93, 184, 216, 34}, 443})
    end

    test "a tuple allowlist entry matches a string destination" do
      # The same seam from the other side, so normalisation cannot be
      # one-directional and pass this group.
      assert Policy.permits?([{{93, 184, 216, 34}, 443}], {"93.184.216.34", 443})
    end

    test "normalising host forms does not make different addresses equal" do
      # ⚠️ The obvious way to close the seam -- coerce both sides to strings --
      # must not become "compare loosely". A neighbouring address stays denied.
      refute Policy.permits?([{"93.184.216.34", 443}], {{93, 184, 216, 35}, 443})
      refute Policy.permits?([{{10, 0, 0, 1}, 443}], {"10.0.0.2", 443})
    end

    test "a malformed host string is not silently treated as a match" do
      refute Policy.permits?([{"93.184.216.34", 443}], {"not-an-address", 443})
      refute Policy.permits?([{"", 443}], {{93, 184, 216, 34}, 443})
    end
  end
end
