defmodule ExSandbox.ConformanceTagsTest do
  @moduledoc """
  Each conformance group is selectable by the tag quickstart documents
  (003 T047).

  ## Why this is worth a test

  `quickstart.md` tells an operator to run `mix test --only conformance:isolation`
  when they want to know whether a mechanism isolates. If no check carries that
  tag, the command does not fail — it selects nothing and ExUnit reports
  success. The operator gets a green run and concludes the mechanism isolates,
  having verified nothing at all.

  That is the failure this test exists to catch: a documented invocation that
  silently matches zero checks is worse than one that errors.
  """
  use ExUnit.Case, async: true

  # Every group quickstart offers a `--only conformance:<group>` invocation for
  # and which is implemented today. `emission` is documented but deferred with
  # FR-017, so it is deliberately absent.
  @groups [
    :lifecycle,
    :reachability,
    :reconciliation,
    :credentials,
    :isolation,
    :network,
    :resource_limits
  ]

  # Read from source rather than by compiling a suite.
  #
  # Both obvious alternatives register real ExUnit tests with the *outer* run:
  # a module-level `use ExSandbox.Conformance` and a runtime `Module.create`
  # alike. Either way this file executes the entire conformance suite against a
  # do-nothing stub as a side effect of asking what tags it carries -- 54
  # spurious failures attributed to whichever app happens to compile it.
  #
  # The tags are a static property of the group sources, so they are read
  # statically.
  @group_files Path.wildcard("lib/ex_sandbox/conformance/*.ex")

  defp group_sources do
    for path <- @group_files,
        body = File.read!(path),
        String.contains?(body, "defmacro tests do"),
        do: {path, body}
  end

  defp tags_present do
    for {_path, body} <- group_sources(),
        [_, tag] <- Regex.scan(~r/@describetag\s+conformance:\s+:(\w+)/, body),
        do: String.to_atom(tag)
  end

  test "every group is reachable by its documented tag" do
    present = tags_present()

    for group <- @groups do
      assert group in present,
             """
             No conformance check carries `@tag conformance: #{inspect(group)}`.

             `quickstart.md` documents `mix test --only conformance:#{group}`.
             With no check carrying the tag that command selects nothing and
             reports success, so an operator sees green having verified nothing.
             """
    end
  end

  test "every check carries exactly one group tag" do
    # An untagged check is unreachable by any documented invocation and would
    # only ever run in a full-suite pass -- easy to introduce and invisible
    # until someone wonders why a group looks small.
    untagged =
      for {path, body} <- group_sources(),
          not (body =~ ~r/@describetag\s+conformance:/),
          do: path

    assert untagged == [],
           "these conformance groups carry no group tag, so no documented " <>
             "`--only conformance:<group>` invocation reaches them:\n  " <>
             Enum.join(untagged, "\n  ")
  end
end
