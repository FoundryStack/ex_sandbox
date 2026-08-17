defmodule ExSandbox.Egress.VerificationTest do
  @moduledoc """
  What must be true of a running sandbox's egress for it to be *policed*
  rather than merely *isolated* (005 T060a3/T060a5).

  ## Why this module has to exist before the launch path changes

  `Hardening.Linux.sandbox_netns_separated?/1` answers "is the sandbox in a
  different netns?" — and its own comment says so, adding that this is sound
  *today* only because `--unshare-net` yields a namespace with no route, so
  isolation and policy coincide.

  ⚠️ Installing a working default route breaks that coincidence on purpose.
  From that moment the existing guard keeps returning `true` while the property
  its name suggests goes unverified — a guard that reads correctly and returns
  green on the exact path it was written to catch, which is the species this
  suite has now found seven times.

  So the check that replaces the coincidence lands with the route, not after
  it. The dangerous state is not "verification fails"; it is "verification
  passes for a sandbox with no policy".
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Verification

  @key {10, 0, 0, 0}

  describe "policed?/1" do
    test "a separated namespace with no registered policy is NOT policed" do
      # ⚠️ **The load-bearing case.** This is exactly what `--unshare-net`
      # produces, and exactly what the old `netns_separated` check calls
      # success. A sandbox here reaches nothing, so every *denial* check
      # passes and the census would report the network group demonstrated.
      assert {:error, :no_policy} =
               Verification.policed?(%{
                 netns_separated: true,
                 source_key: @key,
                 registered_allowlist: []
               })
    end

    test "a sandbox sharing the host's namespace is NOT policed" do
      # The opposite failure: no separation at all. A policy registered against
      # a sandbox that is not in its own namespace enforces nothing, because
      # its traffic never traverses the redirect.
      assert {:error, :not_separated} =
               Verification.policed?(%{
                 netns_separated: false,
                 source_key: @key,
                 registered_allowlist: [{"api.example.com", 443}]
               })
    end

    test "a separated namespace with a registered policy is policed" do
      assert :ok =
               Verification.policed?(%{
                 netns_separated: true,
                 source_key: @key,
                 registered_allowlist: [{"api.example.com", 443}]
               })
    end

    test "an unknown netns state is refused rather than assumed" do
      # T060a5's rule at the verification layer: a host that cannot answer
      # reports unavailable, never `:ok`. Treating "could not read" as
      # "separated" is how an unverifiable host starts passing.
      assert {:error, :unverifiable} =
               Verification.policed?(%{
                 netns_separated: :unknown,
                 source_key: @key,
                 registered_allowlist: [{"api.example.com", 443}]
               })
    end
  end
end
