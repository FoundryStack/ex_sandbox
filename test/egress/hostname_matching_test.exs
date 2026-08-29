defmodule ExSandbox.Egress.HostnameMatchingTest do
  @moduledoc """
  `029-FR-012`: an allowlist entry naming a hostname matches the connections
  that hostname resolves to — and matches **nothing else**.

  ## Why both halves are here

  The requirement is usually read as one obligation and it is two. Making a
  hostname entry match at all is the fix; keeping it from matching more than the
  operator wrote is what stops the fix from being a hole. `policy_test.exs`
  already records the rule for the address seam — closing a comparison must not
  become *"compare loosely"* — and every widening below was a real candidate
  implementation.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Policy

  @github {20, 205, 243, 168}
  @allowed [{"api.github.com", 443}]
  @resolved %{"api.github.com" => MapSet.new([@github])}

  describe "a hostname entry matches what this sandbox resolved it to" do
    test "the address the name resolved to is permitted" do
      assert Policy.permits?(@allowed, {@github, 443}, @resolved)
    end

    test "and is not permitted before anything resolved it" do
      # ⚠️ The control for every assertion in this file. Without it, a
      # `permits?/3` that answered `true` for any hostname entry would pass the
      # positive case and this whole group would be vacuous.
      refute Policy.permits?(@allowed, {@github, 443}, %{})
    end

    test "the port still binds" do
      refute Policy.permits?(@allowed, {@github, 80}, @resolved)
      assert Policy.permits?([{"api.github.com", :any_port}], {@github, 80}, @resolved)
    end

    test "a different address the name did not resolve to is refused" do
      refute Policy.permits?(@allowed, {{20, 205, 243, 169}, 443}, @resolved)
    end
  end

  describe "the spellings that are the same name" do
    test "case is not significant (RFC 4343)" do
      assert Policy.permits?([{"API.GitHub.COM", 443}], {@github, 443}, @resolved)
    end

    test "a trailing root dot is the same name" do
      assert Policy.permits?([{"api.github.com.", 443}], {@github, 443}, @resolved)
    end
  end

  describe "the widenings this refuses" do
    test "a suffix of an allowed name is not an allowed name" do
      # ⚠️ The classic. Suffix matching makes `github.com` admit
      # `github.com.attacker.test`, and reversed suffix matching makes
      # `api.github.com` admit any subdomain the operator never wrote.
      refute Policy.permits?([{"github.com", 443}], {@github, 443}, @resolved)

      refute Policy.permits?(
               [{"api.github.com", 443}],
               {@github, 443},
               %{"evil.api.github.com" => MapSet.new([@github])}
             )
    end

    test "a substring of an allowed name is not an allowed name" do
      refute Policy.permits?(
               [{"api.github.com", 443}],
               {@github, 443},
               %{"notapi.github.com.evil.test" => MapSet.new([@github])}
             )
    end

    test "a second name that resolved to the same address is not permitted by the first" do
      # ⚠️ This is the widening a reverse index produces, and it is the worst of
      # them: on any shared front-end address it admits most of the internet,
      # and it does so while every positive check stays green.
      refute Policy.permits?(
               [{"harmless.test", 443}],
               {@github, 443},
               %{"api.github.com" => MapSet.new([@github])}
             )
    end

    test "one sandbox's resolutions do not decide another sandbox's verdict" do
      # Expressed here as "an empty map for this sandbox refuses what a
      # populated map for another would permit". `Decision.decide/3` fetches the map
      # per source key; this pins what that buys.
      refute Policy.permits?(@allowed, {@github, 443}, %{})
      assert Policy.permits?(@allowed, {@github, 443}, @resolved)
    end
  end

  describe "address entries are unaffected" do
    test "an address entry still matches by equality, with no resolutions at all" do
      assert Policy.permits?([{"93.184.216.34", 443}], {{93, 184, 216, 34}, 443}, %{})
      refute Policy.permits?([{"93.184.216.34", 443}], {{93, 184, 216, 35}, 443}, %{})
    end

    test "an address entry is not matched through the resolution table" do
      # A malformed or address-shaped entry must not acquire a second way to
      # match; only names go through resolutions.
      refute Policy.permits?(
               [{"93.184.216.34", 443}],
               {@github, 443},
               %{"93.184.216.34" => MapSet.new([@github])}
             )
    end

    test "permits?/2 is unchanged and denies every hostname entry" do
      # ⚠️ The pre-029 arity still exists and still defaults to no resolutions,
      # so a caller that has not been taught about them denies rather than
      # permits. Default-deny survives the change.
      refute Policy.permits?(@allowed, {@github, 443})
      assert Policy.permits?([{"93.184.216.34", 443}], {{93, 184, 216, 34}, 443})
    end
  end
end
