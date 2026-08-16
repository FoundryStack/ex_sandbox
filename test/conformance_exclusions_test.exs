defmodule ExSandbox.ConformanceExclusionsTest do
  @moduledoc """
  The conformance suite offers no way to opt out of a check (012 T028, FR-011,
  quickstart Scenario 6).

  ## Why this is grep-based and blunt

  A subtler check would be a way to argue about the requirement, and the
  requirement is absolute: there is no skip flag, no exclusion tag, no mechanism
  allowlist. The moment one exists, the guarantee the suite claims to enforce
  becomes "whatever every mechanism could manage", and the first mechanism that
  cannot meet a bar lowers it for all of them.

  This test reads the suite's own source and fails on the *appearance* of an
  exclusion mechanism. False positives are the intended failure mode — a name
  that merely looks like an opt-out should be renamed rather than exempted.

  The one legitimate non-run — a host capability being absent — is checked here
  too, from the other direction: it must not be reachable from consumer
  configuration. If it were, it would be an exclusion wearing another name.
  """
  use ExUnit.Case, async: true

  @suite_files Path.wildcard("lib/ex_sandbox/conformance/*.ex") ++
                 ["lib/ex_sandbox/conformance.ex"]

  defp sources do
    Enum.map(@suite_files, fn path -> {path, File.read!(path)} end)
  end

  test "the suite files this test reads actually exist" do
    # Guards against the whole test passing vacuously if the suite moves.
    assert length(@suite_files) >= 5

    Enum.each(sources(), fn {path, body} ->
      assert byte_size(body) > 0, "#{path} is empty"
    end)
  end

  describe "no exclusion mechanism (FR-011)" do
    test "no @tag :skip or @moduletag :skip anywhere in the suite" do
      Enum.each(sources(), fn {path, body} ->
        refute body =~ ~r/@(module)?tag\s+:skip/,
               "#{path} contains a skip tag. FR-011 permits no exclusions."

        refute body =~ ~r/@(module)?tag\s+skip:/,
               "#{path} contains a skip tag. FR-011 permits no exclusions."
      end)
    end

    test "no `exclude`, `only`, or allowlist option is read from the consumer" do
      # `use ExSandbox.Conformance, mechanism: X` accepts exactly two options.
      # Anything selecting *which checks run* is an exclusion.
      forbidden = ~w(
        :exclude
        :except
        :skip
        :only_checks
        :allowlist
        :allow_list
        :supported_checks
        :opt_out
      )

      Enum.each(sources(), fn {path, body} ->
        Enum.each(forbidden, fn option ->
          refute String.contains?(body, "Keyword.get(opts, #{option}"),
                 "#{path} reads #{option} from consumer options -- that is an exclusion (FR-011)"

          refute String.contains?(body, "Keyword.fetch(opts, #{option}"),
                 "#{path} reads #{option} from consumer options -- that is an exclusion (FR-011)"
        end)
      end)
    end

    test "no mechanism allowlist: the suite never branches on which mechanism it is testing" do
      # A check that behaves differently for a named mechanism is an exclusion
      # granted in advance to that mechanism.
      Enum.each(sources(), fn {path, body} ->
        refute body =~ ~r/@mechanism\s*(==|===)\s*[A-Z]/,
               "#{path} compares @mechanism against a specific module -- a " <>
                 "per-mechanism branch is an allowlist (FR-011)"

        refute body =~ ~r/case\s+@mechanism\s+do/,
               "#{path} branches on @mechanism (FR-011)"
      end)
    end

    test "`use ExSandbox.Conformance` accepts only known non-exclusion options" do
      {_path, body} = Enum.find(sources(), fn {path, _} -> path =~ ~r/conformance\.ex$/ end)

      read_options =
        Regex.scan(~r/Keyword\.(?:get|fetch!?)\(opts,\s*(:[a-z_]+)/, body)
        |> Enum.map(fn [_, option] -> option end)
        |> Enum.uniq()
        |> Enum.sort()

      # An allowlist rather than a count, and each entry has to earn its place.
      #
      # `:credential_probe` supplies a *capability* the library cannot have --
      # `ex_sandbox` depends on Elixir and OTP alone (`012-FR-001`), so it has
      # no way to open a database connection and must be handed one. What makes
      # it not an exclusion is the next test: omitting it reports `host
      # capability unavailable`, never a pass. A consumer cannot use it to
      # silence a check they would otherwise fail, which is what `FR-011`
      # forbids.
      #
      # Anything added here needs the same two properties: it must supply
      # something the library genuinely cannot obtain, and its absence must
      # report rather than pass.
      permitted = [":credential_probe", ":mechanism", ":target_stack"]

      assert read_options -- permitted == [],
             "the suite reads #{inspect(read_options -- permitted)} from consumer " <>
               "options. Any option beyond #{inspect(permitted)} risks being an exclusion."
    end

    test "an omitted :credential_probe reports unavailable rather than passing" do
      # The assertion that keeps `:credential_probe` honest. If its absence let
      # the credentials group pass, it would be an exclusion wearing a
      # capability's clothes: a consumer with a broken credential model could
      # omit the probe and see green.
      {_path, body} =
        Enum.find(sources(), fn {path, _} -> path =~ ~r/conformance\/credentials\.ex$/ end)

      assert body =~ ~r/def probe!\(nil\) do/,
             "credentials.ex must handle a missing probe explicitly"

      [_, nil_clause] = Regex.run(~r/def probe!\(nil\) do(.*?)\n  end/s, body)

      assert nil_clause =~ "capability_unavailable",
             "a missing credential probe must report the third outcome, not pass. " <>
               "Found instead: #{nil_clause}"

      refute nil_clause =~ ~r/:ok\b/,
             "a missing credential probe must not resolve to a pass"
    end
  end

  describe "the third outcome is not consumer-requestable (T034, FR-011)" do
    test "capability_unavailable is only ever reached from a Capability check" do
      {_path, helpers} =
        Enum.find(sources(), fn {path, _} -> path =~ ~r/helpers\.ex$/ end)

      # It must derive from a runtime probe, never from an option.
      assert helpers =~ "ExSandbox.Capability.check("

      refute helpers =~ ~r/capability_unavailable\(.*opts/,
             "capability_unavailable/2 is reachable from consumer options, which " <>
               "would make it an exclusion wearing another name (FR-011)"
    end

    test "an unavailable capability is never reported as a pass" do
      {_path, group} = Enum.find(sources(), fn {path, _} -> path =~ ~r/group\.ex$/ end)

      # The tempting handler -- rescue it and carry on -- reports green. ExUnit
      # has no runtime skip, so the honest options are fail or lie.
      assert group =~ "reraise ExUnit.AssertionError",
             "the CapabilityUnavailable handler must re-raise as a failure. " <>
               "Swallowing it reports as passing, which claims a guarantee that " <>
               "was never demonstrated (FR-012b)."
    end
  end
end
